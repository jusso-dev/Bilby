//! The app's only IPC surface. Each command renders a screen or fragment as
//! an HTML string with Askama (auto-escaping on) and the webview swaps it in.

use askama::Template;

/// The home screen with the one big button.
#[derive(Template)]
#[template(path = "home.html")]
struct Home<'a> {
    heading: &'a str,
    button: &'a str,
}

/// Renders the home screen.
#[tauri::command]
pub fn render_home() -> Result<String, String> {
    render(&Home {
        heading: "Bilby",
        button: "Check my computer",
    })
}

fn render(t: &impl Template) -> Result<String, String> {
    t.render().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_has_heading_and_button() {
        let html = render_home().expect("home renders");
        assert!(html.contains("<h1"));
        assert!(html.contains("Check my computer"));
        assert!(html.contains(r#"data-action="start-scan""#));
    }
}
