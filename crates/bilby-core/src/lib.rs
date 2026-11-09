//! Platform-neutral core of Bilby: the data model, rules, scoring and copy.
//!
//! Nothing in this crate touches the operating system. Collectors fill a
//! snapshot, and the rules here turn that snapshot into findings.

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "bilby-core");
    }
}
