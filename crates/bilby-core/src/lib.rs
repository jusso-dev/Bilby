//! Platform-neutral core of Bilby: the data model, rules, scoring and copy.
//!
//! Nothing in this crate touches the operating system. Collectors fill a
//! [`snapshot::SystemSnapshot`], the [`rules`] turn it into findings, and
//! [`score::overall`] turns findings into a traffic light.

pub mod copy;
pub mod demo;
pub mod model;
pub mod paths;
pub mod rules;
pub mod score;
pub mod snapshot;
