// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::borrow::Cow;
use std::collections::BTreeSet;

use derive_builder::Builder;

use crate::api::common::{EnableState, VisibilityLevel};
use crate::api::endpoint_prelude::*;
use crate::api::ParamValue;

/// Access levels available for most features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureAccessLevel {
    /// The feature is not available at all.
    Disabled,
    /// The features is only available to project members.
    Private,
    /// The feature is available to everyone with access to the project.
    Enabled,
}

impl FeatureAccessLevel {
    /// The variable type query parameter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FeatureAccessLevel::Disabled => "disabled",
            FeatureAccessLevel::Private => "private",
            FeatureAccessLevel::Enabled => "enabled",
        }
    }
}

impl ParamValue<'static> for FeatureAccessLevel {
    fn as_value(self) -> Cow<'static, str> {
        self.as_str().into()
    }
}

/// Access levels available for features.
///
/// Note that only the `pages` feature currently uses this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureAccessLevelPublic {
    /// The feature is not available at all.
    Disabled,
    /// The features is only available to project members.
    Private,
    /// The feature is available to everyone with access to the project.
    Enabled,
    /// The feature is publicly available regardless of project access.
    Public,
}

impl FeatureAccessLevelPublic {
    /// The variable type query parameter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FeatureAccessLevelPublic::Disabled => "disabled",
            FeatureAccessLevelPublic::Private => "private",
            FeatureAccessLevelPublic::Enabled => "enabled",
            FeatureAccessLevelPublic::Public => "public",
        }
    }
}

impl ParamValue<'static> for FeatureAccessLevelPublic {
    fn as_value(self) -> Cow<'static, str> {
        self.as_str().into()
    }
}

/// How often the container expiration policy is applied.
///
/// Note that GitLab only supports a few discrete values for this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContainerExpirationCadence {
    /// Every day.
    OneDay,
    /// Every week.
    OneWeek,
    /// Every other week.
    TwoWeeks,
    /// Every month.
    OneMonth,
    /// Quaterly.
    ThreeMonths,
}

impl ContainerExpirationCadence {
    /// The variable type query parameter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ContainerExpirationCadence::OneDay => "1d",
            ContainerExpirationCadence::OneWeek => "7d",
            ContainerExpirationCadence::TwoWeeks => "14d",
            ContainerExpirationCadence::OneMonth => "1month",
            ContainerExpirationCadence::ThreeMonths => "3month",
        }
    }
}

impl ParamValue<'static> for ContainerExpirationCadence {
    fn as_value(self) -> Cow<'static, str> {
        self.as_str().into()
    }
}

/// How many container instances to keep around.
///
/// Note that GitLab only supports a few discrete values for this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContainerExpirationKeepN {
    /// Only one.
    One,
    /// Up to five.
    Five,
    /// Up to ten.
    Ten,
    /// Up to twenty-five.
    TwentyFive,
    /// Up to fifty.
    Fifty,
    /// Up to one hunder.
    OneHundred,
}

impl ContainerExpirationKeepN {
    /// The variable type query parameter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ContainerExpirationKeepN::One => "1",
            ContainerExpirationKeepN::Five => "5",
            ContainerExpirationKeepN::Ten => "10",
            ContainerExpirationKeepN::TwentyFive => "25",
            ContainerExpirationKeepN::Fifty => "50",
            ContainerExpirationKeepN::OneHundred => "100",
        }
    }
}

impl ParamValue<'static> for ContainerExpirationKeepN {
    fn as_value(self) -> Cow<'static, str> {
        self.as_str().into()
    }
}

/// How old containers need to be before they are candidates for expiration.
///
/// Note that GitLab only supports a few discrete values for this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContainerExpirationOlderThan {
    /// One week old.
    OneWeek,
    /// Two weeks old.
    TwoWeeks,
    /// One month old.
    OneMonth,
    /// Three months old.
    ThreeMonths,
}

impl ContainerExpirationOlderThan {
    /// The variable type query parameter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ContainerExpirationOlderThan::OneWeek => "7d",
            ContainerExpirationOlderThan::TwoWeeks => "14d",
            ContainerExpirationOlderThan::OneMonth => "30d",
            ContainerExpirationOlderThan::ThreeMonths => "90d",
        }
    }
}

impl ParamValue<'static> for ContainerExpirationOlderThan {
    fn as_value(self) -> Cow<'static, str> {
        self.as_str().into()
    }
}

/// The expiration policies for container images attached to the project.
#[derive(Debug, Clone, Builder)]
#[builder(setter(strip_option))]
pub struct ContainerExpirationPolicy<'a> {
    /// How often the policy should be applied.
    #[builder(default)]
    cadence: Option<ContainerExpirationCadence>,
    /// Whether the policy is enabled or not.
    #[builder(setter(into), default)]
    enabled: Option<bool>,
    /// How many container images to keep.
    #[builder(default)]
    keep_n: Option<ContainerExpirationKeepN>,
    /// Only consider containers older than this age.
    #[builder(default)]
    older_than: Option<ContainerExpirationOlderThan>,
    /// Only apply to images with names maching a regular expression.
    ///
    /// See the [Ruby documentation](https://ruby-doc.org/core-2.7.1/Regexp.html) for supported
    /// syntax.
    #[builder(setter(into), default)]
    name_regex: Option<Cow<'a, str>>,
}

impl<'a> ContainerExpirationPolicy<'a> {
    /// Create a builder for the container expiration policy.
    pub fn builder() -> ContainerExpirationPolicyBuilder<'a> {
        ContainerExpirationPolicyBuilder::default()
    }

    pub(crate) fn add_query<'b>(&'b self, params: &mut FormParams<'b>) {
        params
            .push_opt(
                "container_expiration_policy_attributes[cadence]",
                self.cadence,
            )
            .push_opt(
                "container_expiration_policy_attributes[enabled]",
                self.enabled,
            )
            .push_opt(
                "container_expiration_policy_attributes[keep_n]",
                self.keep_n,
            )
            .push_opt(
                "container_expiration_policy_attributes[older_than]",
                self.older_than,
            )
            .push_opt(
                "container_expiration_policy_attributes[name_regex]",
                self.name_regex.as_ref(),
            );
    }
}

/// The deploy strategy used when Auto DevOps is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDevOpsDeployStrategy {
    /// Continuous deployment.
    Continuous,
    /// Manual deployment.
    Manual,
    /// Interval deployments.
    TimedIncremental,
}

impl AutoDevOpsDeployStrategy {
    /// The variable type query parameter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AutoDevOpsDeployStrategy::Continuous => "continuous",
            AutoDevOpsDeployStrategy::Manual => "manual",
            AutoDevOpsDeployStrategy::TimedIncremental => "timed_incremental",
        }
    }
}

impl ParamValue<'static> for AutoDevOpsDeployStrategy {
    fn as_value(self) -> Cow<'static, str> {
        self.as_str().into()
    }
}

/// How merge requests should be merged when using the "Merge" button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeMethod {
    /// Always create a merge commit.
    Merge,
    /// Always create a merge commit, but require that the branch be fast-forward capable.
    RebaseMerge,
    /// Only fast-forward merges are allowed.
    FastForward,
}

impl MergeMethod {
    /// The variable type query parameter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            MergeMethod::Merge => "merge",
            MergeMethod::RebaseMerge => "rebase_merge",
            MergeMethod::FastForward => "ff",
        }
    }
}

impl ParamValue<'static> for MergeMethod {
    fn as_value(self) -> Cow<'static, str> {
        self.as_str().into()
    }
}

/// The default Git strategy for CI jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildGitStrategy {
    /// Clone the reopsitory every time.
    Clone,
    /// Fetch into an existing checkout (will clone if not available).
    Fetch,
    /// Do not update the repository at all.
    None,
}

impl Default for BuildGitStrategy {
    fn default() -> Self {
        BuildGitStrategy::Fetch
    }
}

impl BuildGitStrategy {
    /// The variable type query parameter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            BuildGitStrategy::Clone => "clone",
            BuildGitStrategy::Fetch => "fetch",
            BuildGitStrategy::None => "none",
        }
    }
}

impl ParamValue<'static> for BuildGitStrategy {
    fn as_value(self) -> Cow<'static, str> {
        self.as_str().into()
    }
}

/// A structure to handle the fact that at least one of the name and path is required.
#[derive(Debug, Clone)]
enum ProjectName<'a> {
    /// The name of the new project.
    ///
    /// The `path` is based on the name.
    Name { name: Cow<'a, str> },
    /// The path of the new project.
    ///
    /// The `name` is the path.
    Path { path: Cow<'a, str> },
    /// Provide both the name and path manually.
    NameAndPath {
        name: Cow<'a, str>,
        path: Cow<'a, str>,
    },
}

impl<'a> ProjectName<'a> {
    fn with_name(self, name: Cow<'a, str>) -> Self {
        match self {
            ProjectName::Name {
                ..
            } => {
                ProjectName::Name {
                    name,
                }
            },
            ProjectName::NameAndPath {
                path, ..
            }
            | ProjectName::Path {
                path,
            } => {
                ProjectName::NameAndPath {
                    name,
                    path,
                }
            },
        }
    }

    fn with_path(self, path: Cow<'a, str>) -> Self {
        match self {
            ProjectName::Path {
                ..
            } => {
                ProjectName::Path {
                    path,
                }
            },
            ProjectName::NameAndPath {
                name, ..
            }
            | ProjectName::Name {
                name,
            } => {
                ProjectName::NameAndPath {
                    name,
                    path,
                }
            },
        }
    }
}

/// Create a new project on an instance.
#[derive(Debug, Builder)]
#[builder(setter(strip_option))]
pub struct CreateProject<'a> {
    /// The name and/or path of the project.
    #[builder(private)]
    name_and_path: ProjectName<'a>,
    /// The namespace of the new project.
    ///
    /// By default, the project is created in the API caller's namespace.
    #[builder(default)]
    namespace_id: Option<u64>,
    /// The default branch of the new project.
    ///
    /// Defaults to `master`.
    #[builder(setter(into), default)]
    default_branch: Option<Cow<'a, str>>,
    /// The description of the new project.
    #[builder(setter(into), default)]
    description: Option<Cow<'a, str>>,

    /// Set the access level for issues.
    #[builder(default)]
    issues_access_level: Option<FeatureAccessLevel>,
    /// Set the access level for repository access.
    #[builder(default)]
    repository_access_level: Option<FeatureAccessLevel>,
    /// Set the access level for merge requests.
    #[builder(default)]
    merge_requests_access_level: Option<FeatureAccessLevel>,
    /// Set the access level for making a fork of the project.
    #[builder(default)]
    forking_access_level: Option<FeatureAccessLevel>,
    /// Set the access level for CI pipeline access.
    #[builder(default)]
    builds_access_level: Option<FeatureAccessLevel>,
    /// Set the access level for access to view the wiki.
    #[builder(default)]
    wiki_access_level: Option<FeatureAccessLevel>,
    /// Set the access level for snippets.
    #[builder(default)]
    snippets_access_level: Option<FeatureAccessLevel>,
    /// Set the access level for GitLab Pages on the project.
    #[builder(default)]
    pages_access_level: Option<FeatureAccessLevelPublic>,

    /// Whether to enable email notifications or not.
    #[builder(default)]
    emails_disabled: Option<bool>,
    /// Whether outdated diff discussions are resolved when a merge request is updated or not.
    #[builder(default)]
    resolve_outdated_diff_discussions: Option<bool>,
    /// Whether the container registry is enabled or not.
    #[builder(default)]
    container_registry_enabled: Option<bool>,
    /// The expiration policy for containers.
    #[builder(default)]
    container_expiration_policy_attributes: Option<ContainerExpirationPolicy<'a>>,
    /// Whether the project can use shared runners or not.
    #[builder(default)]
    shared_runners_enabled: Option<bool>,
    /// The visibility level of the project.
    #[builder(default)]
    visibility: Option<VisibilityLevel>,
    /// A URL to import the repository from.
    #[builder(default)]
    import_url: Option<Cow<'a, str>>,
    /// Whether job results are visible to non-project members or not.
    #[builder(default)]
    public_builds: Option<bool>,
    /// Whether the CI pipeline is required to succeed before merges are allowed.
    #[builder(default)]
    only_allow_merge_if_pipeline_succeeds: Option<bool>,
    /// Whether all discussions must be resolved before merges are allowed.
    #[builder(default)]
    only_allow_merge_if_all_discussions_are_resolved: Option<bool>,
    /// The merge method to use for the project.
    #[builder(default)]
    merge_method: Option<MergeMethod>,
    /// Whether issues referenced on the default branch should be closed or not.
    #[builder(default)]
    autoclose_referenced_issues: Option<bool>,
    /// Whether to enabled the "Remove source branch" option in new merge requests by default or
    /// not.
    #[builder(default)]
    remove_source_branch_after_merge: Option<bool>,
    /// Whether `git-lfs` support should be enabled or not.
    ///
    /// See the [git-lfs](https://git-lfs.github.com/) website for more information.
    #[builder(default)]
    lfs_enabled: Option<bool>,
    /// Whether users may request access to the repository or not.
    #[builder(default)]
    request_access_enabled: Option<bool>,
    /// A list of tags to apply to the repository.
    #[builder(setter(name = "_tag_list"), default, private)]
    tag_list: BTreeSet<Cow<'a, str>>,
    // TODO: Figure out how to actually use this.
    // avatar   mixed   no  Image file for avatar of the project
    // avatar: ???,
    /// Whether to show a link to create or view a merge request when pushing a branch from the
    /// command line or not.
    #[builder(default)]
    printing_merge_request_link_enabled: Option<bool>,
    /// The default Git strategy for CI jobs of the project.
    #[builder(default)]
    build_git_strategy: Option<BuildGitStrategy>,
    /// The default timeout for jobs of the project (in seconds).
    #[builder(default)]
    build_timeout: Option<u64>,
    /// Whether to automatically cancel pipelines when branches are updated when using a previous
    /// version of th branch.
    #[builder(default)]
    auto_cancel_pending_pipelines: Option<EnableState>,
    /// The default regular expression to use for build coverage extraction.
    #[builder(setter(into), default)]
    build_coverage_regex: Option<Cow<'a, str>>,
    /// The path to the GitLab CI configuration file within the repository.
    ///
    /// Defaults to `.gitlab-ci.yml`.
    #[builder(setter(into), default)]
    ci_config_path: Option<Cow<'a, str>>,
    /// Whether Auto DevOps are enabled or not.
    #[builder(default)]
    auto_devops_enabled: Option<bool>,
    /// The Auto Deploy strategy of the project.
    #[builder(default)]
    auto_devops_deploy_strategy: Option<AutoDevOpsDeployStrategy>,
    /// The storage shard on which to store the repository.
    #[builder(setter(into), default)]
    repository_storage: Option<Cow<'a, str>>,
    /// How many approvals are required before allowing merges.
    #[builder(default)]
    approvals_before_merge: Option<u64>,
    /// The classification label of the project.
    #[builder(setter(into), default)]
    external_authorization_classification_label: Option<Cow<'a, str>>,
    /// Whether to enable pull mirroring for the project or not.
    #[builder(default)]
    mirror: Option<bool>,
    /// Whether mirror updates trigger CI builds ir not.
    #[builder(default)]
    mirror_trigger_builds: Option<bool>,
    /// Initialize the project with a readme.
    #[builder(default)]
    initialize_with_readme: Option<bool>,
    /// The name of a template project to use.
    #[builder(setter(into), default)]
    template_name: Option<Cow<'a, str>>,
    /// The ID of the template project to use.
    #[builder(default)]
    template_project_id: Option<u64>,
    /// Whether to use a custom instance or group template.
    #[builder(default)]
    use_custom_template: Option<bool>,
    /// Whether the template project should come from the group or the instance.
    #[builder(setter(name = "_group_with_project_templates_id"), default, private)]
    group_with_project_templates_id: Option<u64>,
    /// Whether the package repository is enabled or not.
    #[builder(default)]
    packages_enabled: Option<bool>,

    /// Whether to enable issues or not.
    #[deprecated(note = "use `issues_access_level` instead")]
    #[builder(default)]
    issues_enabled: Option<bool>,
    /// Whether to enable merge requests or not.
    #[deprecated(note = "use `merge_requests_access_level` instead")]
    #[builder(default)]
    merge_requests_enabled: Option<bool>,
    /// Whether to enable CI pipelines or not.
    #[deprecated(note = "use `builds_access_level` instead")]
    #[builder(default)]
    jobs_enabled: Option<bool>,
    /// Whether to enable the wiki or not.
    #[deprecated(note = "use `wiki_access_level` instead")]
    #[builder(default)]
    wiki_enabled: Option<bool>,
    /// Whether to enable snippets or not.
    #[deprecated(note = "use `snippets_access_level` instead")]
    #[builder(default)]
    snippets_enabled: Option<bool>,
}

impl<'a> CreateProject<'a> {
    /// Create a builder for the endpoint.
    pub fn builder() -> CreateProjectBuilder<'a> {
        CreateProjectBuilder::default()
    }
}

impl<'a> CreateProjectBuilder<'a> {
    /// Set the name of the project.
    ///
    /// If not set, it will default to the value of `path`.
    pub fn name<N>(&mut self, name: N) -> &mut Self
    where
        N: Into<Cow<'a, str>>,
    {
        let name = name.into();
        self.name_and_path = Some(if let Some(name_and_path) = self.name_and_path.take() {
            name_and_path.with_name(name)
        } else {
            ProjectName::Name {
                name,
            }
        });
        self
    }

    /// Set the path of the project.
    ///
    /// If not set, it will default to the value of `name` after processing to make it a valid
    /// path.
    pub fn path<P>(&mut self, path: P) -> &mut Self
    where
        P: Into<Cow<'a, str>>,
    {
        let path = path.into();
        self.name_and_path = Some(if let Some(name_and_path) = self.name_and_path.take() {
            name_and_path.with_path(path)
        } else {
            ProjectName::Path {
                path,
            }
        });
        self
    }

    /// Add a tag.
    pub fn tag<T>(&mut self, tag: T) -> &mut Self
    where
        T: Into<Cow<'a, str>>,
    {
        self.tag_list
            .get_or_insert_with(BTreeSet::new)
            .insert(tag.into());
        self
    }

    /// Add multiple tags.
    pub fn tags<I, T>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = T>,
        T: Into<Cow<'a, str>>,
    {
        self.tag_list
            .get_or_insert_with(BTreeSet::new)
            .extend(iter.map(Into::into));
        self
    }

    /// Whether the template project should come from the group or the instance.
    ///
    /// Note that setting this also sets `use_custom_template` to `true` automatically.
    pub fn group_with_project_templates_id(&mut self, id: u64) -> &mut Self {
        self.group_with_project_templates_id = Some(Some(id));
        self.use_custom_template(true);
        self
    }
}

impl<'a> Endpoint for CreateProject<'a> {
    fn method(&self) -> Method {
        Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "projects".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = FormParams::default();

        match &self.name_and_path {
            ProjectName::Name {
                name,
            } => {
                params.push("name", name);
            },
            ProjectName::Path {
                path,
            } => {
                params.push("path", path);
            },
            ProjectName::NameAndPath {
                name,
                path,
            } => {
                params.push("name", name).push("path", path);
            },
        }

        params
            .push_opt("namespace_id", self.namespace_id)
            .push_opt("default_branch", self.default_branch.as_ref())
            .push_opt("description", self.description.as_ref())
            .push_opt("issues_access_level", self.issues_access_level)
            .push_opt("repository_access_level", self.repository_access_level)
            .push_opt(
                "merge_requests_access_level",
                self.merge_requests_access_level,
            )
            .push_opt("forking_access_level", self.forking_access_level)
            .push_opt("builds_access_level", self.builds_access_level)
            .push_opt("wiki_access_level", self.wiki_access_level)
            .push_opt("snippets_access_level", self.snippets_access_level)
            .push_opt("pages_access_level", self.pages_access_level)
            .push_opt("emails_disabled", self.emails_disabled)
            .push_opt(
                "resolve_outdated_diff_discussions",
                self.resolve_outdated_diff_discussions,
            )
            .push_opt(
                "container_registry_enabled",
                self.container_registry_enabled,
            )
            .push_opt("shared_runners_enabled", self.shared_runners_enabled)
            .push_opt("visibility", self.visibility)
            .push_opt("import_url", self.import_url.as_ref())
            .push_opt("public_builds", self.public_builds)
            .push_opt(
                "only_allow_merge_if_pipeline_succeeds",
                self.only_allow_merge_if_pipeline_succeeds,
            )
            .push_opt(
                "only_allow_merge_if_all_discussions_are_resolved",
                self.only_allow_merge_if_all_discussions_are_resolved,
            )
            .push_opt("merge_method", self.merge_method)
            .push_opt(
                "autoclose_referenced_issues",
                self.autoclose_referenced_issues,
            )
            .push_opt(
                "remove_source_branch_after_merge",
                self.remove_source_branch_after_merge,
            )
            .push_opt("lfs_enabled", self.lfs_enabled)
            .push_opt("request_access_enabled", self.request_access_enabled)
            .extend(self.tag_list.iter().map(|value| ("tag_list[]", value)))
            .push_opt(
                "printing_merge_request_link_enabled",
                self.printing_merge_request_link_enabled,
            )
            .push_opt("build_git_strategy", self.build_git_strategy)
            .push_opt("build_timeout", self.build_timeout)
            .push_opt(
                "auto_cancel_pending_pipelines",
                self.auto_cancel_pending_pipelines,
            )
            .push_opt("build_coverage_regex", self.build_coverage_regex.as_ref())
            .push_opt("ci_config_path", self.ci_config_path.as_ref())
            .push_opt("auto_devops_enabled", self.auto_devops_enabled)
            .push_opt(
                "auto_devops_deploy_strategy",
                self.auto_devops_deploy_strategy,
            )
            .push_opt("repository_storage", self.repository_storage.as_ref())
            .push_opt("approvals_before_merge", self.approvals_before_merge)
            .push_opt(
                "external_authorization_classification_label",
                self.external_authorization_classification_label.as_ref(),
            )
            .push_opt("mirror", self.mirror)
            .push_opt("mirror_trigger_builds", self.mirror_trigger_builds)
            .push_opt("initialize_with_readme", self.initialize_with_readme)
            .push_opt("template_name", self.template_name.as_ref())
            .push_opt("template_project_id", self.template_project_id)
            .push_opt("use_custom_template", self.use_custom_template)
            .push_opt(
                "group_with_project_templates_id",
                self.group_with_project_templates_id,
            )
            .push_opt("packages_enabled", self.packages_enabled);

        if let Some(policy) = self.container_expiration_policy_attributes.as_ref() {
            policy.add_query(&mut params);
        }

        #[allow(deprecated)]
        {
            params
                .push_opt("issues_enabled", self.issues_enabled)
                .push_opt("merge_requests_enabled", self.merge_requests_enabled)
                .push_opt("jobs_enabled", self.jobs_enabled)
                .push_opt("wiki_enabled", self.wiki_enabled)
                .push_opt("snippets_enabled", self.snippets_enabled);
        }

        params.into_body()
    }
}

#[cfg(test)]
mod tests {
    use crate::api::projects::{
        AutoDevOpsDeployStrategy, BuildGitStrategy, ContainerExpirationCadence,
        ContainerExpirationKeepN, ContainerExpirationOlderThan, ContainerExpirationPolicy,
        CreateProject, FeatureAccessLevel, FeatureAccessLevelPublic, MergeMethod,
    };

    #[test]
    fn feature_access_level_as_str() {
        let items = &[
            (FeatureAccessLevel::Disabled, "disabled"),
            (FeatureAccessLevel::Private, "private"),
            (FeatureAccessLevel::Enabled, "enabled"),
        ];

        for (i, s) in items {
            assert_eq!(i.as_str(), *s);
        }
    }

    #[test]
    fn feature_access_level_public_as_str() {
        let items = &[
            (FeatureAccessLevelPublic::Disabled, "disabled"),
            (FeatureAccessLevelPublic::Private, "private"),
            (FeatureAccessLevelPublic::Enabled, "enabled"),
            (FeatureAccessLevelPublic::Public, "public"),
        ];

        for (i, s) in items {
            assert_eq!(i.as_str(), *s);
        }
    }

    #[test]
    fn container_expiration_cadence_as_str() {
        let items = &[
            (ContainerExpirationCadence::OneDay, "1d"),
            (ContainerExpirationCadence::OneWeek, "7d"),
            (ContainerExpirationCadence::TwoWeeks, "14d"),
            (ContainerExpirationCadence::OneMonth, "1month"),
            (ContainerExpirationCadence::ThreeMonths, "3month"),
        ];

        for (i, s) in items {
            assert_eq!(i.as_str(), *s);
        }
    }

    #[test]
    fn container_expiration_keep_n_ordering() {
        let items = &[
            ContainerExpirationKeepN::One,
            ContainerExpirationKeepN::Five,
            ContainerExpirationKeepN::Ten,
            ContainerExpirationKeepN::TwentyFive,
            ContainerExpirationKeepN::Fifty,
            ContainerExpirationKeepN::OneHundred,
        ];

        let mut last = None;
        for item in items {
            if let Some(prev) = last {
                assert!(prev < item);
            }
            last = Some(item);
        }
    }

    #[test]
    fn container_expiration_keep_n_as_str() {
        let items = &[
            (ContainerExpirationKeepN::One, "1"),
            (ContainerExpirationKeepN::Five, "5"),
            (ContainerExpirationKeepN::Ten, "10"),
            (ContainerExpirationKeepN::TwentyFive, "25"),
            (ContainerExpirationKeepN::Fifty, "50"),
            (ContainerExpirationKeepN::OneHundred, "100"),
        ];

        for (i, s) in items {
            assert_eq!(i.as_str(), *s);
        }
    }

    #[test]
    fn container_expiration_older_than_ordering() {
        let items = &[
            ContainerExpirationOlderThan::OneWeek,
            ContainerExpirationOlderThan::TwoWeeks,
            ContainerExpirationOlderThan::OneMonth,
            ContainerExpirationOlderThan::ThreeMonths,
        ];

        let mut last = None;
        for item in items {
            if let Some(prev) = last {
                assert!(prev < item);
            }
            last = Some(item);
        }
    }

    #[test]
    fn container_expiration_older_than_as_str() {
        let items = &[
            (ContainerExpirationOlderThan::OneWeek, "7d"),
            (ContainerExpirationOlderThan::TwoWeeks, "14d"),
            (ContainerExpirationOlderThan::OneMonth, "30d"),
            (ContainerExpirationOlderThan::ThreeMonths, "90d"),
        ];

        for (i, s) in items {
            assert_eq!(i.as_str(), *s);
        }
    }

    #[test]
    fn container_expiration_policy_default() {
        ContainerExpirationPolicy::builder().build().unwrap();
    }

    #[test]
    fn auto_dev_ops_deploy_strategy_as_str() {
        let items = &[
            (AutoDevOpsDeployStrategy::Continuous, "continuous"),
            (AutoDevOpsDeployStrategy::Manual, "manual"),
            (
                AutoDevOpsDeployStrategy::TimedIncremental,
                "timed_incremental",
            ),
        ];

        for (i, s) in items {
            assert_eq!(i.as_str(), *s);
        }
    }

    #[test]
    fn merge_method_as_str() {
        let items = &[
            (MergeMethod::Merge, "merge"),
            (MergeMethod::RebaseMerge, "rebase_merge"),
            (MergeMethod::FastForward, "ff"),
        ];

        for (i, s) in items {
            assert_eq!(i.as_str(), *s);
        }
    }

    #[test]
    fn build_git_strategy_default() {
        assert_eq!(BuildGitStrategy::default(), BuildGitStrategy::Fetch);
    }

    #[test]
    fn build_git_strategy_as_str() {
        let items = &[
            (BuildGitStrategy::Clone, "clone"),
            (BuildGitStrategy::Fetch, "fetch"),
            (BuildGitStrategy::None, "none"),
        ];

        for (i, s) in items {
            assert_eq!(i.as_str(), *s);
        }
    }

    #[test]
    fn name_and_path_is_needed() {
        let err = CreateProject::builder().build().unwrap_err();
        assert_eq!(err, "`name_and_path` must be initialized");
    }

    #[test]
    fn name_is_sufficient() {
        CreateProject::builder().name("name").build().unwrap();
    }

    #[test]
    fn path_is_sufficient() {
        CreateProject::builder().path("path").build().unwrap();
    }
}
