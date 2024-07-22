// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use derive_builder::Builder;

use crate::api::common::NameOrId;
use crate::api::endpoint_prelude::*;

/// Get the diffs between two commits.
#[derive(Debug, Builder, Clone)]
#[builder(setter(strip_option))]
pub struct CompareCommits<'a> {
    /// The project to get a commit from.
    #[builder(setter(into))]
    project: NameOrId<'a>,
    /// The from commit sha or branch name.
    #[builder(setter(into))]
    from: Cow<'a, str>,
    /// The to commit sha or branch name.
    #[builder(setter(into))]
    to: Cow<'a, str>,
    /// The project ID to compare from.
    #[builder(default)]
    from_project_id: Option<u64>,
    /// Comparison method.
    ///
    /// When `true`, the commits are compared directly. When `false` (the default), commits are
    /// compared taking their merge base into account.
    #[builder(default)]
    straight: Option<bool>,
    /// Present diffs in the unified diff format.
    ///
    /// Default is false.
    #[builder(default)]
    unidiff: Option<bool>,
}

impl<'a> CompareCommits<'a> {
    /// Create a builder for the endpoint.
    pub fn builder() -> CompareCommitsBuilder<'a> {
        CompareCommitsBuilder::default()
    }
}

impl<'a> Endpoint for CompareCommits<'a> {
    fn method(&self) -> Method {
        Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("projects/{}/repository/compare", self.project).into()
    }

    fn parameters(&self) -> QueryParams {
        let mut params = QueryParams::default();
        params
            .push("from", self.from.as_ref())
            .push("to", self.to.as_ref())
            .push_opt("from_project_id", self.from_project_id)
            .push_opt("straight", self.straight)
            .push_opt("unidiff", self.unidiff);

        params
    }
}

#[cfg(test)]
mod tests {

    use crate::api::projects::repository::commits::{CompareCommits, CompareCommitsBuilderError};
    use crate::api::{self, Query};
    use crate::test::client::{ExpectedUrl, SingleTestClient};
    use http::Method;

    #[test]
    fn project_is_necessary() {
        let err = CompareCommits::builder()
            .from("0000000000000000000000000000000000000000")
            .to("0000000000000000000000000000000000000000")
            .build()
            .unwrap_err();
        crate::test::assert_missing_field!(err, CompareCommitsBuilderError, "project");
    }

    #[test]
    fn to_is_necessary() {
        let err = CompareCommits::builder()
            .project(1)
            .from("0000000000000000000000000000000000000000")
            .build()
            .unwrap_err();
        crate::test::assert_missing_field!(err, CompareCommitsBuilderError, "to");
    }

    #[test]
    fn from_is_necessary() {
        let err = CompareCommits::builder()
            .project(1)
            .to("0000000000000000000000000000000000000000")
            .build()
            .unwrap_err();
        crate::test::assert_missing_field!(err, CompareCommitsBuilderError, "from");
    }

    #[test]
    fn project_from_and_to_are_sufficient() {
        CompareCommits::builder()
            .project(1)
            .to("0000000000000000000000000000000000000000")
            .from("0000000000000000000000000000000000000000")
            .build()
            .unwrap();
    }

    #[test]
    fn endpoint() {
        let endpoint = ExpectedUrl::builder()
            .method(Method::GET)
            .endpoint("projects/simple%2Fproject/repository/compare")
            .add_query_params(&[
                ("from", "0000000000000000000000000000000000000000"),
                ("to", "0000000000000000000000000000000000000000"),
            ])
            .build()
            .unwrap();
        let client = SingleTestClient::new_raw(endpoint, "");
        let endpoint = CompareCommits::builder()
            .project("simple/project")
            .from("0000000000000000000000000000000000000000")
            .to("0000000000000000000000000000000000000000")
            .build()
            .unwrap();
        api::ignore(endpoint).query(&client).unwrap();
    }

    #[test]
    fn endpoint_from_project_id() {
        let endpoint = ExpectedUrl::builder()
            .method(Method::GET)
            .endpoint("projects/simple%2Fproject/repository/compare")
            .add_query_params(&[
                ("from", "0000000000000000000000000000000000000000"),
                ("to", "0000000000000000000000000000000000000000"),
                ("from_project_id", "234876"),
            ])
            .build()
            .unwrap();
        let client = SingleTestClient::new_raw(endpoint, "");
        let endpoint = CompareCommits::builder()
            .project("simple/project")
            .from("0000000000000000000000000000000000000000")
            .to("0000000000000000000000000000000000000000")
            .from_project_id(234876)
            .build()
            .unwrap();
        api::ignore(endpoint).query(&client).unwrap();
    }

    #[test]
    fn endpoint_straight() {
        let endpoint = ExpectedUrl::builder()
            .method(Method::GET)
            .endpoint("projects/simple%2Fproject/repository/compare")
            .add_query_params(&[
                ("from", "0000000000000000000000000000000000000000"),
                ("to", "0000000000000000000000000000000000000000"),
                ("straight", "true"),
            ])
            .build()
            .unwrap();
        let client = SingleTestClient::new_raw(endpoint, "");
        let endpoint = CompareCommits::builder()
            .project("simple/project")
            .from("0000000000000000000000000000000000000000")
            .to("0000000000000000000000000000000000000000")
            .straight(true)
            .build()
            .unwrap();
        api::ignore(endpoint).query(&client).unwrap();
    }

    #[test]
    fn endpoint_unidiff() {
        let endpoint = ExpectedUrl::builder()
            .method(Method::GET)
            .endpoint("projects/simple%2Fproject/repository/compare")
            .add_query_params(&[
                ("from", "0000000000000000000000000000000000000000"),
                ("to", "0000000000000000000000000000000000000000"),
                ("unidiff", "true"),
            ])
            .build()
            .unwrap();
        let client = SingleTestClient::new_raw(endpoint, "");
        let endpoint = CompareCommits::builder()
            .project("simple/project")
            .from("0000000000000000000000000000000000000000")
            .to("0000000000000000000000000000000000000000")
            .unidiff(true)
            .build()
            .unwrap();
        api::ignore(endpoint).query(&client).unwrap();
    }
}
