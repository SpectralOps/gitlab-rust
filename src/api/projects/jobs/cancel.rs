// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use derive_builder::Builder;

use crate::api::common::NameOrId;
use crate::api::endpoint_prelude::*;

/// Cancel a job.
#[derive(Debug, Builder)]
pub struct CancelJob<'a> {
    /// The project which owns the job.
    #[builder(setter(into))]
    project: NameOrId<'a>,
    /// The ID of the job.
    job: u64,
}

impl<'a> CancelJob<'a> {
    /// Create a builder for the endpoint.
    pub fn builder() -> CancelJobBuilder<'a> {
        CancelJobBuilder::default()
    }
}

impl<'a> Endpoint for CancelJob<'a> {
    fn method(&self) -> Method {
        Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("projects/{}/jobs/{}/cancel", self.project, self.job).into()
    }
}

#[cfg(test)]
mod tests {
    use crate::api::projects::jobs::CancelJob;

    #[test]
    fn project_and_job_are_needed() {
        let err = CancelJob::builder().build().unwrap_err();
        assert_eq!(err, "`project` must be initialized");
    }

    #[test]
    fn project_is_needed() {
        let err = CancelJob::builder().job(1).build().unwrap_err();
        assert_eq!(err, "`project` must be initialized");
    }

    #[test]
    fn job_is_needed() {
        let err = CancelJob::builder().project(1).build().unwrap_err();
        assert_eq!(err, "`job` must be initialized");
    }

    #[test]
    fn project_and_job_are_sufficient() {
        CancelJob::builder().project(1).job(1).build().unwrap();
    }
}
