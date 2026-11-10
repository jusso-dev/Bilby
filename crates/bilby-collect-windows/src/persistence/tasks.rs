//! Scheduled tasks through the Task Scheduler COM API. Read-only: only
//! getters are called. COM interfaces are released when they drop.

use bilby_core::cmdline::resolve;
use bilby_core::paths::KnownFolders;
use bilby_core::snapshot::{TaskAction, TaskFact};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{
    IComHandlerAction, IExecAction, ITaskFolder, ITaskService, TASK_ACTION_COM_HANDLER,
    TASK_ACTION_EXEC, TASK_ACTION_TYPE, TASK_ENUM_HIDDEN, TASK_RUNLEVEL_HIGHEST,
    TASK_RUNLEVEL_TYPE, TaskScheduler,
};
use windows::Win32::System::Variant::{VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_I4};
use windows::core::{BSTR, Interface};

/// What the task walk found.
pub struct Collected {
    /// Every task that could be read.
    pub tasks: Vec<TaskFact>,
    /// Folders that refused access (need admin).
    pub folders_denied: u32,
}

/// A `VT_I4` variant. No owned memory, so nothing to clear.
fn int_variant(i: i32) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: std::mem::ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_I4,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { lVal: i },
            }),
        },
    }
}

fn get_bstr(f: impl FnOnce(*mut BSTR) -> windows::core::Result<()>) -> Option<String> {
    let mut b = BSTR::new();
    f(&raw mut b).ok()?;
    let s = b.to_string();
    (!s.is_empty()).then_some(s)
}

/// Walks every task folder from `\`.
pub fn collect(folders: &KnownFolders) -> windows::core::Result<Collected> {
    crate::defender::init_com();
    // SAFETY: COM is initialised; TaskScheduler is an in-process class.
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }?;
    let empty = VARIANT::default();
    // SAFETY: empty variants mean local machine and current user.
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }?;
    // SAFETY: getter.
    let root = unsafe { service.GetFolder(&BSTR::from(r"\")) }?;
    let mut out = Collected {
        tasks: Vec::new(),
        folders_denied: 0,
    };
    walk(&root, folders, &mut out, 0);
    Ok(out)
}

fn walk(folder: &ITaskFolder, folders: &KnownFolders, out: &mut Collected, depth: u8) {
    if depth > 32 {
        return;
    }
    // SAFETY: getter; TASK_ENUM_HIDDEN includes hidden tasks.
    match unsafe { folder.GetTasks(TASK_ENUM_HIDDEN.0) } {
        Ok(tasks) => {
            // SAFETY: getter.
            let count = unsafe { tasks.Count() }.unwrap_or(0);
            // Collections are 1-based.
            for i in 1..=count {
                // SAFETY: index within Count().
                if let Ok(task) = unsafe { tasks.get_Item(&int_variant(i)) }
                    && let Some(fact) = read_task(&task, folders)
                {
                    out.tasks.push(fact);
                }
            }
        }
        Err(_) => out.folders_denied += 1,
    }
    // SAFETY: getter.
    let Ok(subs) = (unsafe { folder.GetFolders(0) }) else {
        out.folders_denied += 1;
        return;
    };
    // SAFETY: getter.
    let count = unsafe { subs.Count() }.unwrap_or(0);
    for i in 1..=count {
        // SAFETY: index within Count().
        if let Ok(sub) = unsafe { subs.get_Item(&int_variant(i)) } {
            walk(&sub, folders, out, depth + 1);
        }
    }
}

fn read_task(
    task: &windows::Win32::System::TaskScheduler::IRegisteredTask,
    folders: &KnownFolders,
) -> Option<TaskFact> {
    // Every unsafe block in this function is a getter on a live COM
    // interface owned by this scope, writing only into locals or
    // out-parameters we own. None changes the task.
    // SAFETY: see above.
    let path = unsafe { task.Path() }.ok()?.to_string();
    // SAFETY: see above.
    let enabled = unsafe { task.Enabled() }.is_ok_and(VARIANT_BOOL::as_bool);
    // SAFETY: see above.
    let last_run = unsafe { task.LastRunTime() }
        .ok()
        .and_then(bilby_core::cim::from_ole_date);
    // SAFETY: see above.
    let def = unsafe { task.Definition() }.ok()?;

    // SAFETY: see above.
    let author = match unsafe { def.RegistrationInfo() } {
        // SAFETY: see above.
        Ok(info) => get_bstr(|b| unsafe { info.Author(b) }),
        Err(_) => None,
    };

    let mut hidden = false;
    // SAFETY: see above.
    if let Ok(settings) = unsafe { def.Settings() } {
        let mut h = VARIANT_BOOL::default();
        // SAFETY: see above.
        hidden = unsafe { settings.Hidden(&raw mut h) }.is_ok() && h.as_bool();
    }

    let (mut user, mut elevated) = (None, false);
    // SAFETY: see above.
    if let Ok(principal) = unsafe { def.Principal() } {
        // SAFETY: see above.
        user = get_bstr(|b| unsafe { principal.UserId(b) });
        let mut level = TASK_RUNLEVEL_TYPE::default();
        // SAFETY: see above.
        elevated =
            unsafe { principal.RunLevel(&raw mut level) }.is_ok() && level == TASK_RUNLEVEL_HIGHEST;
    }

    // SAFETY: see above.
    let actions = match unsafe { def.Actions() } {
        Ok(list) => read_actions(&list, folders),
        Err(_) => Vec::new(),
    };
    Some(TaskFact {
        path,
        enabled,
        hidden,
        author,
        user,
        elevated,
        last_run,
        actions,
    })
}

fn read_actions(
    list: &windows::Win32::System::TaskScheduler::IActionCollection,
    folders: &KnownFolders,
) -> Vec<TaskAction> {
    let mut actions = Vec::new();
    let mut count = 0i32;
    // Every unsafe block in this function is a getter on a live COM
    // interface, writing only into locals we own.
    // SAFETY: see above.
    let _ = unsafe { list.Count(&raw mut count) };
    for i in 1..=count {
        // SAFETY: see above; `i` is within Count() (1-based).
        let Ok(action) = (unsafe { list.get_Item(i) }) else {
            continue;
        };
        let mut kind = TASK_ACTION_TYPE::default();
        // SAFETY: see above.
        let _ = unsafe { action.Type(&raw mut kind) };
        if kind == TASK_ACTION_EXEC {
            let Ok(exec) = action.cast::<IExecAction>() else {
                continue;
            };
            // SAFETY: see above.
            let program = get_bstr(|b| unsafe { exec.Path(b) }).unwrap_or_default();
            // SAFETY: see above.
            let args = get_bstr(|b| unsafe { exec.Arguments(b) }).unwrap_or_default();
            actions.push(exec_action(&program, &args, folders));
        } else if kind == TASK_ACTION_COM_HANDLER
            && let Ok(com) = action.cast::<IComHandlerAction>()
        {
            actions.push(TaskAction::ComHandler {
                // SAFETY: see above.
                class_id: get_bstr(|b| unsafe { com.ClassId(b) }).unwrap_or_default(),
            });
        }
    }
    actions
}

fn exec_action(program: &str, args: &str, folders: &KnownFolders) -> TaskAction {
    let quoted = if program.contains(' ') && !program.starts_with('"') {
        format!("\"{program}\"")
    } else {
        program.to_owned()
    };
    let command = format!("{quoted} {args}").trim().to_owned();
    let exists = |p: &str| !super::is_network(p, folders) && std::path::Path::new(p).is_file();
    let r = resolve(&command, folders, &exists);
    // A placeholder; persistence::fill_pending checks it in parallel.
    let target = super::pending(&r.target, folders);
    TaskAction::Exec {
        command,
        target: Some(Box::new(target)),
        host: r.via.map(|h| super::host_name(h).to_owned()),
        host_args: (!r.host_args.is_empty()).then_some(r.host_args),
    }
}
