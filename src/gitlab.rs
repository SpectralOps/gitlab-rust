// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::any;
use std::convert::TryInto;
use std::fmt::{self, Debug};

use async_trait::async_trait;
use bytes::Bytes;
use graphql_client::{GraphQLQuery, QueryBody, Response};
use http::{HeaderMap, Response as HttpResponse};
use itertools::Itertools;
use log::{debug, error, info};
use reqwest::blocking::Client;
#[cfg(any(feature = "client_der", feature = "client_pem"))]
use reqwest::Certificate;
use reqwest::Client as AsyncClient;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

#[cfg(any(feature = "client_der", feature = "client_pem"))]
use reqwest::Identity as TlsIdentity;

use crate::api;
use crate::auth::{Auth, AuthError};

#[cfg(any(feature = "client_der", feature = "client_pem"))]
#[derive(Debug, Clone)]
pub enum RootCertificate {
    Der(Vec<u8>),
    Pem(Vec<u8>),
    PemBundle(Vec<u8>),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GitlabError {
    #[error("failed to parse url: {}", source)]
    UrlParse {
        #[from]
        source: url::ParseError,
    },
    #[error("error setting auth header: {}", source)]
    AuthError {
        #[from]
        source: AuthError,
    },
    #[error("communication with gitlab: {}", source)]
    Communication {
        #[from]
        source: reqwest::Error,
    },
    #[error("gitlab HTTP error: {}", status)]
    Http { status: reqwest::StatusCode },
    #[allow(clippy::upper_case_acronyms)]
    #[error("graphql error: [\"{}\"]", message.iter().format("\", \""))]
    GraphQL { message: Vec<graphql_client::Error> },
    #[error("no response from gitlab")]
    NoResponse {},
    #[error("could not parse {} data from JSON: {}", typename, source)]
    DataType {
        #[source]
        source: serde_json::Error,
        typename: &'static str,
    },
    #[error("api error: {}", source)]
    Api {
        #[from]
        source: api::ApiError<RestError>,
    },
}

impl GitlabError {
    fn http(status: reqwest::StatusCode) -> Self {
        GitlabError::Http {
            status,
        }
    }

    fn graphql(message: Vec<graphql_client::Error>) -> Self {
        GitlabError::GraphQL {
            message,
        }
    }

    fn no_response() -> Self {
        GitlabError::NoResponse {}
    }

    fn data_type<T>(source: serde_json::Error) -> Self {
        GitlabError::DataType {
            source,
            typename: any::type_name::<T>(),
        }
    }
}

type GitlabResult<T> = Result<T, GitlabError>;

// Private enum that enables the parsing of the cert bytes to be
// delayed until the client is built rather than when they're passed
// to a builder.
#[derive(Clone)]
enum ClientCert {
    None,
    #[cfg(feature = "client_der")]
    Der(Vec<u8>, String),
    #[cfg(feature = "client_pem")]
    Pem(Vec<u8>),
}

/// A representation of the Gitlab API for a single user.
///
/// Separate users should use separate instances of this.
#[derive(Clone)]
pub struct Gitlab {
    /// The client to use for API calls.
    client: Client,
    /// The base URL to use for API calls.
    rest_url: Url,
    /// The URL to use for GraphQL API calls.
    graphql_url: Url,
    /// The authentication information to use when communicating with Gitlab.
    auth: Auth,
}

impl Debug for Gitlab {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Gitlab")
            .field("rest_url", &self.rest_url)
            .field("graphql_url", &self.graphql_url)
            .finish()
    }
}

/// Should a certificate be validated in TLS connections.
/// The Insecure option is used for self-signed certificates.
#[derive(Debug, Clone)]
enum CertPolicy {
    Default,
    /// Trust all certificates (including expired certificates). This introduces significant
    /// vulnerabilities, and should only be used as a last resort.
    Insecure,
    #[cfg(any(feature = "client_der", feature = "client_pem"))]
    /// Trust certificates signed by the root certificate.
    SelfSigned(RootCertificate),
}

impl Gitlab {
    /// Create a new Gitlab API representation.
    ///
    /// The `token` should be a valid [personal access token](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html).
    /// Errors out if `token` is invalid.
    pub fn new<H, T>(host: H, token: T) -> GitlabResult<Self>
    where
        H: AsRef<str>,
        T: Into<String>,
    {
        Self::new_impl(
            "https",
            host.as_ref(),
            Auth::Token(token.into()),
            CertPolicy::Default,
            ClientCert::None,
        )
    }

    /// Create a new non-SSL Gitlab API representation.
    ///
    /// The `token` should be a valid [personal access token](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html).
    /// Errors out if `token` is invalid.
    pub fn new_insecure<H, T>(host: H, token: T) -> GitlabResult<Self>
    where
        H: AsRef<str>,
        T: Into<String>,
    {
        Self::new_impl(
            "http",
            host.as_ref(),
            Auth::Token(token.into()),
            CertPolicy::Insecure,
            ClientCert::None,
        )
    }

    #[cfg(any(feature = "client_der", feature = "client_pem"))]
    /// Create a new Gitlab API representation, with a custom root certificate.
    ///
    /// The `token` should be a valid [personal access token](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html).
    /// Errors out if `token` is invalid.
    pub fn new_self_signed<H, T>(
        host: H,
        token: T,
        root_certificate: RootCertificate,
    ) -> GitlabResult<Self>
    where
        H: AsRef<str>,
        T: Into<String>,
    {
        Self::new_impl(
            "https",
            host.as_ref(),
            Auth::Token(token.into()),
            CertPolicy::SelfSigned(root_certificate),
            ClientCert::None,
        )
    }

    /// Create a new Gitlab API representation.
    ///
    /// The `token` should be a valid [job token](https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html).
    /// Errors out if `token` is invalid.
    pub fn new_job_token<H, T>(host: H, token: T) -> GitlabResult<Self>
    where
        H: AsRef<str>,
        T: Into<String>,
    {
        Self::new_impl(
            "https",
            host.as_ref(),
            Auth::JobToken(token.into()),
            CertPolicy::Default,
            ClientCert::None,
        )
    }

    /// Create a new non-SSL Gitlab API representation.
    ///
    /// The `token` should be a valid [job token](https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html).
    /// Errors out if `token` is invalid.
    pub fn new_job_token_insecure<H, T>(host: H, token: T) -> GitlabResult<Self>
    where
        H: AsRef<str>,
        T: Into<String>,
    {
        Self::new_impl(
            "http",
            host.as_ref(),
            Auth::JobToken(token.into()),
            CertPolicy::Insecure,
            ClientCert::None,
        )
    }

    /// Create a new Gitlab API representation.
    ///
    /// The `token` should be a valid [OAuth2 token](https://docs.gitlab.com/ee/api/oauth2.html).
    /// Errors out if `token` is invalid.
    pub fn with_oauth2<H, T>(host: H, token: T) -> GitlabResult<Self>
    where
        H: AsRef<str>,
        T: Into<String>,
    {
        Self::new_impl(
            "https",
            host.as_ref(),
            Auth::OAuth2(token.into()),
            CertPolicy::Default,
            ClientCert::None,
        )
    }

    /// Create a new non-SSL Gitlab API representation.
    ///
    /// The `token` should be a valid [OAuth2 token](https://docs.gitlab.com/ee/api/oauth2.html).
    /// Errors out if `token` is invalid.
    pub fn with_oauth2_insecure<H, T>(host: H, token: T) -> GitlabResult<Self>
    where
        H: AsRef<str>,
        T: Into<String>,
    {
        Self::new_impl(
            "http",
            host.as_ref(),
            Auth::OAuth2(token.into()),
            CertPolicy::Default,
            ClientCert::None,
        )
    }

    /// Internal method to create a new Gitlab client.
    fn new_impl(
        protocol: &str,
        host: &str,
        auth: Auth,
        cert_validation: CertPolicy,
        identity: ClientCert,
    ) -> GitlabResult<Self> {
        let rest_url = Url::parse(&format!("{}://{}/api/v4/", protocol, host))?;
        let graphql_url = Url::parse(&format!("{}://{}/api/graphql", protocol, host))?;

        let client = match cert_validation {
            CertPolicy::Insecure => {
                Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()?
            },
            CertPolicy::Default => {
                match identity {
                    ClientCert::None => Client::new(),
                    #[cfg(feature = "client_der")]
                    ClientCert::Der(der, password) => {
                        let id = TlsIdentity::from_pkcs12_der(&der, &password)?;
                        Client::builder().identity(id).build()?
                    },
                    #[cfg(feature = "client_pem")]
                    ClientCert::Pem(pem) => {
                        let id = TlsIdentity::from_pem(&pem)?;
                        Client::builder().identity(id).build()?
                    },
                }
            },
            #[cfg(any(feature = "client_der", feature = "client_pem"))]
            CertPolicy::SelfSigned(cert) => {
                let mut builder = Client::builder();
                match cert {
                    RootCertificate::Der(der) => {
                        builder = builder.add_root_certificate(Certificate::from_der(&der)?);
                    },
                    RootCertificate::Pem(pem) => {
                        builder = builder.add_root_certificate(Certificate::from_pem(&pem)?);
                    },
                    RootCertificate::PemBundle(pem_bundle) => {
                        for certificate in Certificate::from_pem_bundle(&pem_bundle)? {
                            builder = builder.add_root_certificate(certificate);
                        }
                    },
                };

                builder.build()?
            },
        };

        let api = Gitlab {
            client,
            rest_url,
            graphql_url,
            auth,
        };

        // Ensure the API is working.
        api.auth.check_connection(&api)?;

        Ok(api)
    }

    /// Create a new Gitlab API client builder.
    pub fn builder<H, T>(host: H, token: T) -> GitlabBuilder
    where
        H: Into<String>,
        T: Into<String>,
    {
        GitlabBuilder::new(host, token)
    }

    /// Send a GraphQL query.
    pub fn graphql<Q>(&self, query: &QueryBody<Q::Variables>) -> GitlabResult<Q::ResponseData>
    where
        Q: GraphQLQuery,
        Q::Variables: Debug,
        for<'d> Q::ResponseData: Deserialize<'d>,
    {
        info!(
            target: "gitlab",
            "sending GraphQL query '{}' {:?}",
            query.operation_name,
            query.variables,
        );
        let req = self.client.post(self.graphql_url.clone()).json(query);
        let rsp: Response<Q::ResponseData> = self.send(req)?;

        if let Some(errs) = rsp.errors {
            return Err(GitlabError::graphql(errs));
        }
        rsp.data.ok_or_else(GitlabError::no_response)
    }

    /// Refactored code which talks to Gitlab and transforms error messages properly.
    fn send<T>(&self, req: reqwest::blocking::RequestBuilder) -> GitlabResult<T>
    where
        T: DeserializeOwned,
    {
        let auth_headers = {
            let mut headers = HeaderMap::default();
            self.auth.set_header(&mut headers)?;
            headers
        };
        let rsp = req.headers(auth_headers).send()?;
        let status = rsp.status();
        if status.is_server_error() {
            return Err(GitlabError::http(status));
        }

        serde_json::from_reader::<_, T>(rsp).map_err(GitlabError::data_type::<T>)
    }

    /// Perform a REST query with a given auth.
    fn rest_auth(
        &self,
        mut request: http::request::Builder,
        body: Vec<u8>,
        auth: &Auth,
    ) -> Result<HttpResponse<Bytes>, api::ApiError<<Self as api::RestClient>::Error>> {
        let call = || -> Result<_, RestError> {
            auth.set_header(request.headers_mut().unwrap())?;
            let http_request = request.body(body)?;
            let request = http_request.try_into()?;
            let rsp = self.client.execute(request)?;

            let mut http_rsp = HttpResponse::builder()
                .status(rsp.status())
                .version(rsp.version());
            let headers = http_rsp.headers_mut().unwrap();
            for (key, value) in rsp.headers() {
                headers.insert(key, value.clone());
            }
            Ok(http_rsp.body(rsp.bytes()?)?)
        };
        call().map_err(api::ApiError::client)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RestError {
    #[error("error setting auth header: {}", source)]
    AuthError {
        #[from]
        source: AuthError,
    },
    #[error("communication with gitlab: {}", source)]
    Communication {
        #[from]
        source: reqwest::Error,
    },
    #[error("`http` error: {}", source)]
    Http {
        #[from]
        source: http::Error,
    },
}

impl api::RestClient for Gitlab {
    type Error = RestError;

    fn rest_endpoint(&self, endpoint: &str) -> Result<Url, api::ApiError<Self::Error>> {
        debug!(target: "gitlab", "REST api call {}", endpoint);
        Ok(self.rest_url.join(endpoint)?)
    }
}

impl api::Client for Gitlab {
    fn rest(
        &self,
        request: http::request::Builder,
        body: Vec<u8>,
    ) -> Result<HttpResponse<Bytes>, api::ApiError<Self::Error>> {
        self.rest_auth(request, body, &self.auth)
    }
}

pub struct GitlabBuilder {
    protocol: &'static str,
    host: String,
    token: Auth,
    cert_validation: CertPolicy,
    identity: ClientCert,
}

impl GitlabBuilder {
    /// Create a new Gitlab API client builder.
    pub fn new<H, T>(host: H, token: T) -> Self
    where
        H: Into<String>,
        T: Into<String>,
    {
        Self {
            protocol: "https",
            host: host.into(),
            token: Auth::Token(token.into()),
            cert_validation: CertPolicy::Default,
            identity: ClientCert::None,
        }
    }

    /// Create a new unauthenticated Gitlab API client builder.
    pub fn new_unauthenticated<H>(host: H) -> Self
    where
        H: Into<String>,
    {
        Self {
            protocol: "https",
            host: host.into(),
            token: Auth::None,
            cert_validation: CertPolicy::Default,
            identity: ClientCert::None,
        }
    }

    /// Switch to an insecure protocol (http instead of https).
    pub fn insecure(&mut self) -> &mut Self {
        self.protocol = "http";
        self
    }

    pub fn cert_insecure(&mut self) -> &mut Self {
        self.cert_validation = CertPolicy::Insecure;
        self
    }

    /// Switch to using an OAuth2 token instead of a personal access token
    pub fn oauth2_token(&mut self) -> &mut Self {
        if let Auth::Token(token) = self.token.clone() {
            self.token = Auth::OAuth2(token);
        }
        self
    }

    /// [Authenticate to Gitlab](reqwest::Identity) with the provided
    /// DER-formatted PKCS#12 archive.
    #[cfg(any(doc, feature = "client_der"))]
    pub fn client_identity_from_der(&mut self, der: &[u8], password: &str) -> &mut Self {
        self.identity = ClientCert::Der(der.into(), password.into());
        self
    }

    /// [Authenticate to Gitlab](reqwest::Identity) with the provided
    /// PEM-encoded private key and certificate.
    #[cfg(any(doc, feature = "client_pem"))]
    pub fn client_identity_from_pem(&mut self, pem: &[u8]) -> &mut Self {
        self.identity = ClientCert::Pem(pem.into());
        self
    }

    pub fn build(&self) -> GitlabResult<Gitlab> {
        Gitlab::new_impl(
            self.protocol,
            &self.host,
            self.token.clone(),
            self.cert_validation.clone(),
            self.identity.clone(),
        )
    }

    pub async fn build_async(&self) -> GitlabResult<AsyncGitlab> {
        AsyncGitlab::new_impl(
            self.protocol,
            &self.host,
            self.token.clone(),
            self.cert_validation.clone(),
            self.identity.clone(),
        )
        .await
    }
}

/// A representation of the asynchronous Gitlab API for a single user.
///
/// Separate users should use separate instances of this.
#[derive(Clone)]
pub struct AsyncGitlab {
    /// The client to use for API calls.
    client: reqwest::Client,
    /// The base URL to use for API calls.
    instance_url: Url,
    /// The base URL to use for REST API calls.
    rest_url: Url,
    /// The URL to use for GraphQL API calls.
    graphql_url: Url,
    /// The authentication information to use when communicating with Gitlab.
    auth: Auth,
}

impl Debug for AsyncGitlab {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AsyncGitlab")
            .field("instance_url", &self.instance_url)
            .field("rest_url", &self.rest_url)
            .field("graphql_url", &self.graphql_url)
            .finish()
    }
}

#[async_trait]
impl api::RestClient for AsyncGitlab {
    type Error = RestError;

    fn rest_endpoint(&self, endpoint: &str) -> Result<Url, api::ApiError<Self::Error>> {
        debug!(target: "gitlab", "REST api call {}", endpoint);
        Ok(self.rest_url.join(endpoint)?)
    }

    fn instance_endpoint(&self, endpoint: &str) -> Result<Url, api::ApiError<Self::Error>> {
        debug!(target: "gitlab", "instance api call {}", endpoint);
        Ok(self.instance_url.join(endpoint)?)
    }
}

#[async_trait]
impl api::AsyncClient for AsyncGitlab {
    async fn rest_async(
        &self,
        request: http::request::Builder,
        body: Vec<u8>,
    ) -> Result<HttpResponse<Bytes>, api::ApiError<<Self as api::RestClient>::Error>> {
        self.rest_async_auth(request, body, &self.auth).await
    }
}

impl AsyncGitlab {
    /// Internal method to create a new Gitlab client.
    async fn new_impl(
        protocol: &str,
        host: &str,
        auth: Auth,
        cert_validation: CertPolicy,
        identity: ClientCert,
    ) -> GitlabResult<Self> {
        let instance_url = Url::parse(&format!("{}://{}/", protocol, host))?;
        let rest_url = Url::parse(&format!("{}://{}/api/v4/", protocol, host))?;
        let graphql_url = Url::parse(&format!("{}://{}/api/graphql", protocol, host))?;

        let client = match cert_validation {
            CertPolicy::Insecure => {
                AsyncClient::builder()
                    .danger_accept_invalid_certs(true)
                    .build()?
            },
            CertPolicy::Default => {
                match identity {
                    ClientCert::None => AsyncClient::new(),
                    #[cfg(feature = "client_der")]
                    ClientCert::Der(der, password) => {
                        let id = TlsIdentity::from_pkcs12_der(&der, &password)?;
                        AsyncClient::builder().identity(id).build()?
                    },
                    #[cfg(feature = "client_pem")]
                    ClientCert::Pem(pem) => {
                        let id = TlsIdentity::from_pem(&pem)?;
                        AsyncClient::builder().identity(id).build()?
                    },
                }
            },
            #[cfg(any(feature = "client_der", feature = "client_pem"))]
            CertPolicy::SelfSigned(cert) => {
                let mut builder = AsyncClient::builder();
                match cert {
                    RootCertificate::Der(der) => {
                        builder = builder.add_root_certificate(Certificate::from_der(&der)?);
                    },
                    RootCertificate::Pem(pem) => {
                        builder = builder.add_root_certificate(Certificate::from_pem(&pem)?);
                    },
                    RootCertificate::PemBundle(pem_bundle) => {
                        for certificate in Certificate::from_pem_bundle(&pem_bundle)? {
                            builder = builder.add_root_certificate(certificate);
                        }
                    },
                };

                builder.build()?
            },
        };

        let api = AsyncGitlab {
            client,
            instance_url,
            rest_url,
            graphql_url,
            auth,
        };

        // Ensure the API is working.
        api.auth.check_connection_async(&api).await?;

        Ok(api)
    }

    /// Send a GraphQL query.
    pub async fn graphql<Q>(&self, query: &QueryBody<Q::Variables>) -> GitlabResult<Q::ResponseData>
    where
        Q: GraphQLQuery,
        Q::Variables: Debug,
        for<'d> Q::ResponseData: Deserialize<'d>,
    {
        info!(
            target: "gitlab",
            "sending GraphQL query '{}' {:?}",
            query.operation_name,
            query.variables,
        );
        let req = self.client.post(self.graphql_url.clone()).json(query);
        let rsp: Response<Q::ResponseData> = self.send(req).await?;

        if let Some(errs) = rsp.errors {
            return Err(GitlabError::graphql(errs));
        }
        rsp.data.ok_or_else(GitlabError::no_response)
    }

    /// Refactored code which talks to Gitlab and transforms error messages properly.
    async fn send<T>(&self, req: reqwest::RequestBuilder) -> GitlabResult<T>
    where
        T: DeserializeOwned,
    {
        let auth_headers = {
            let mut headers = HeaderMap::default();
            self.auth.set_header(&mut headers)?;
            headers
        };
        let rsp = req.headers(auth_headers).send().await?;
        let status = rsp.status();
        if status.is_server_error() {
            return Err(GitlabError::http(status));
        }

        serde_json::from_slice::<T>(&rsp.bytes().await?).map_err(GitlabError::data_type::<T>)
    }

    /// Perform a REST query with a given auth.
    async fn rest_async_auth(
        &self,
        mut request: http::request::Builder,
        body: Vec<u8>,
        auth: &Auth,
    ) -> Result<HttpResponse<Bytes>, api::ApiError<<Self as api::RestClient>::Error>> {
        use futures_util::TryFutureExt;
        let call = || {
            async {
                auth.set_header(request.headers_mut().unwrap())?;
                let http_request = request.body(body)?;
                let request = http_request.try_into()?;
                let rsp = self.client.execute(request).await?;

                let mut http_rsp = HttpResponse::builder()
                    .status(rsp.status())
                    .version(rsp.version());
                let headers = http_rsp.headers_mut().unwrap();
                for (key, value) in rsp.headers() {
                    headers.insert(key, value.clone());
                }
                Ok(http_rsp.body(rsp.bytes().await?)?)
            }
        };
        call().map_err(api::ApiError::client).await
    }
}

#[derive(Clone)]
pub struct ImpersonationClient<'a, T> {
    auth: Auth,
    client: &'a T,
}

impl<'a, C> ImpersonationClient<'a, C> {
    /// Wrap an existing client using an impersonation token.
    pub fn new<T>(client: &'a C, token: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            auth: Auth::Token(token.into()),
            client,
        }
    }

    /// Switch to using an OAuth2 token instead of a personal access token
    pub fn oauth2_token(&mut self) -> &mut Self {
        if let Auth::Token(auth) = self.auth.clone() {
            self.auth = Auth::OAuth2(auth);
        }
        self
    }
}

impl<'a, C> api::RestClient for ImpersonationClient<'a, C>
where
    C: api::RestClient,
{
    type Error = C::Error;

    fn rest_endpoint(&self, endpoint: &str) -> Result<Url, api::ApiError<Self::Error>> {
        self.client.rest_endpoint(endpoint)
    }

    fn instance_endpoint(&self, endpoint: &str) -> Result<Url, api::ApiError<Self::Error>> {
        self.client.instance_endpoint(endpoint)
    }
}

impl<'a> api::Client for ImpersonationClient<'a, Gitlab> {
    fn rest(
        &self,
        request: http::request::Builder,
        body: Vec<u8>,
    ) -> Result<HttpResponse<Bytes>, api::ApiError<Self::Error>> {
        self.client.rest_auth(request, body, &self.auth)
    }
}

#[async_trait]
impl<'a> api::AsyncClient for ImpersonationClient<'a, AsyncGitlab> {
    async fn rest_async(
        &self,
        request: http::request::Builder,
        body: Vec<u8>,
    ) -> Result<HttpResponse<Bytes>, api::ApiError<<Self as api::RestClient>::Error>> {
        self.client.rest_async_auth(request, body, &self.auth).await
    }
}
