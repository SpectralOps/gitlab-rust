// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// TODO: Document API entities.
// #![warn(missing_docs)]
// XXX(rust-1.66)
#![allow(clippy::uninlined_format_args)]

//! A library for communicating with Gitlab instances.

#[macro_use]
mod macros;
#[cfg(feature = "client_api")]
mod gitlab;

#[cfg(not(feature = "_nohooks"))]
pub mod hooks;
#[cfg(not(feature = "_nohooks"))]
pub mod systemhooks;
#[cfg(not(feature = "_nohooks"))]
pub mod webhooks;

#[cfg(feature = "client_api")]
pub mod api;
#[cfg(feature = "client_api")]
mod auth;

#[cfg(feature = "client_api")]
pub use crate::auth::AuthError;
#[cfg(feature = "client_api")]
pub use crate::gitlab::{
    AsyncGitlab, Gitlab, GitlabBuilder, GitlabError, ImpersonationClient, RestError,
};

#[cfg(all(
    feature = "client_api",
    any(feature = "client_der", feature = "client_pem")
))]
pub use crate::gitlab::RootCertificate;

#[cfg(test)]
mod test;
