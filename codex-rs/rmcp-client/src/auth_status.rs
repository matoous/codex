use std::collections::HashMap;
use std::time::Duration;

use anyhow::Error;
use anyhow::Result;
use codex_protocol::protocol::McpAuthStatus;
use reqwest::Client;
use reqwest::StatusCode;
use reqwest::Url;
use reqwest::header::AUTHORIZATION;
use reqwest::header::HeaderMap;
use reqwest::header::WWW_AUTHENTICATE;
use serde::Deserialize;
use tracing::debug;

use crate::OAuthCredentialsStoreMode;
use crate::oauth::has_oauth_tokens;
use crate::utils::apply_default_headers;
use crate::utils::build_default_headers;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const OAUTH_DISCOVERY_HEADER: &str = "MCP-Protocol-Version";
const OAUTH_DISCOVERY_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamableHttpOAuthDiscovery {
    pub scopes_supported: Option<Vec<String>>,
}

/// Determine the authentication status for a streamable HTTP MCP server.
pub async fn determine_streamable_http_auth_status(
    server_name: &str,
    url: &str,
    bearer_token_env_var: Option<&str>,
    http_headers: Option<HashMap<String, String>>,
    env_http_headers: Option<HashMap<String, String>>,
    store_mode: OAuthCredentialsStoreMode,
) -> Result<McpAuthStatus> {
    if bearer_token_env_var.is_some() {
        return Ok(McpAuthStatus::BearerToken);
    }

    let default_headers = build_default_headers(http_headers, env_http_headers)?;
    if default_headers.contains_key(AUTHORIZATION) {
        return Ok(McpAuthStatus::BearerToken);
    }

    if has_oauth_tokens(server_name, url, store_mode)? {
        return Ok(McpAuthStatus::OAuth);
    }

    match discover_streamable_http_oauth_with_headers(url, &default_headers).await {
        Ok(Some(_)) => Ok(McpAuthStatus::NotLoggedIn),
        Ok(None) => Ok(McpAuthStatus::Unsupported),
        Err(error) => {
            debug!(
                "failed to detect OAuth support for MCP server `{server_name}` at {url}: {error:?}"
            );
            Ok(McpAuthStatus::Unsupported)
        }
    }
}

/// Attempt to determine whether a streamable HTTP MCP server advertises OAuth login.
pub async fn supports_oauth_login(url: &str) -> Result<bool> {
    Ok(discover_streamable_http_oauth(
        url, /*http_headers*/ None, /*env_http_headers*/ None,
    )
    .await?
    .is_some())
}

pub async fn discover_streamable_http_oauth(
    url: &str,
    http_headers: Option<HashMap<String, String>>,
    env_http_headers: Option<HashMap<String, String>>,
) -> Result<Option<StreamableHttpOAuthDiscovery>> {
    let default_headers = build_default_headers(http_headers, env_http_headers)?;
    discover_streamable_http_oauth_with_headers(url, &default_headers).await
}

async fn discover_streamable_http_oauth_with_headers(
    url: &str,
    default_headers: &HeaderMap,
) -> Result<Option<StreamableHttpOAuthDiscovery>> {
    let base_url = Url::parse(url)?;

    // Use no_proxy to avoid a bug in the system-configuration crate that
    // can result in a panic. See #8912.
    let builder = Client::builder().timeout(DISCOVERY_TIMEOUT).no_proxy();
    let client = apply_default_headers(builder, default_headers).build()?;

    let mut last_error: Option<Error> = None;
    match discover_via_protected_resource_metadata(&client, &base_url).await {
        Ok(Some(discovery)) => return Ok(Some(discovery)),
        Ok(None) => {}
        Err(err) => last_error = Some(err),
    }

    match discover_via_authorization_server_metadata(&client, &base_url).await {
        Ok(Some(discovery)) => return Ok(Some(discovery)),
        Ok(None) => {}
        Err(err) => last_error = Some(err),
    }

    if let Some(err) = last_error {
        debug!("OAuth discovery requests failed for {url}: {err:?}");
    }

    Ok(None)
}

async fn discover_via_protected_resource_metadata(
    client: &Client,
    base_url: &Url,
) -> Result<Option<StreamableHttpOAuthDiscovery>> {
    let challenge = fetch_bearer_challenge(client, base_url).await?;
    let challenge_scopes = challenge.scope.as_deref().and_then(normalize_scope_param);

    if let Some(resource_metadata_url) = challenge.resource_metadata
        && let Some(discovery) = fetch_protected_resource_discovery(
            client,
            resource_metadata_url,
            challenge_scopes.clone(),
        )
        .await?
    {
        return Ok(Some(discovery));
    }

    for candidate_path in protected_resource_metadata_paths(base_url.path()) {
        let mut metadata_url = base_url.clone();
        metadata_url.set_path(&candidate_path);

        if let Some(discovery) =
            fetch_protected_resource_discovery(client, metadata_url, challenge_scopes.clone())
                .await?
        {
            return Ok(Some(discovery));
        }
    }

    Ok(None)
}

async fn fetch_protected_resource_discovery(
    client: &Client,
    metadata_url: Url,
    challenge_scopes: Option<Vec<String>>,
) -> Result<Option<StreamableHttpOAuthDiscovery>> {
    let response = client
        .get(metadata_url.clone())
        .header(OAUTH_DISCOVERY_HEADER, OAUTH_DISCOVERY_VERSION)
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        return Ok(None);
    }

    let metadata = response.json::<ProtectedResourceMetadata>().await?;
    let authorization_servers = metadata
        .authorization_servers
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| Url::parse(&value).ok())
        .collect::<Vec<_>>();

    if authorization_servers.is_empty() {
        return Ok(None);
    }

    for authorization_server in authorization_servers {
        if fetch_oauth_metadata(client, &authorization_server)
            .await?
            .is_some()
        {
            return Ok(Some(StreamableHttpOAuthDiscovery {
                scopes_supported: challenge_scopes
                    .clone()
                    .or_else(|| normalize_scopes(metadata.scopes_supported.clone())),
            }));
        }
    }

    Ok(None)
}

async fn discover_via_authorization_server_metadata(
    client: &Client,
    base_url: &Url,
) -> Result<Option<StreamableHttpOAuthDiscovery>> {
    if let Some(metadata) = fetch_oauth_metadata(client, base_url).await? {
        return Ok(Some(StreamableHttpOAuthDiscovery {
            scopes_supported: normalize_scopes(metadata.scopes_supported),
        }));
    }

    Ok(None)
}

async fn fetch_oauth_metadata(
    client: &Client,
    base_url: &Url,
) -> Result<Option<OAuthDiscoveryMetadata>> {
    for candidate_path in discovery_paths(base_url.path()) {
        let mut discovery_url = base_url.clone();
        discovery_url.set_path(&candidate_path);

        let response = client
            .get(discovery_url.clone())
            .header(OAUTH_DISCOVERY_HEADER, OAUTH_DISCOVERY_VERSION)
            .send()
            .await?;

        if response.status() != StatusCode::OK {
            continue;
        }

        let metadata = response.json::<OAuthDiscoveryMetadata>().await?;

        if metadata.authorization_endpoint.is_some() && metadata.token_endpoint.is_some() {
            return Ok(Some(metadata));
        }
    }

    Ok(None)
}

#[derive(Debug, Deserialize)]
struct OAuthDiscoveryMetadata {
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    authorization_servers: Option<Vec<String>>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Default)]
struct BearerChallenge {
    resource_metadata: Option<Url>,
    scope: Option<String>,
}

fn normalize_scopes(scopes_supported: Option<Vec<String>>) -> Option<Vec<String>> {
    let scopes_supported = scopes_supported?;

    let mut normalized = Vec::new();
    for scope in scopes_supported {
        let scope = scope.trim();
        if scope.is_empty() {
            continue;
        }
        let scope = scope.to_string();
        if !normalized.contains(&scope) {
            normalized.push(scope);
        }
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_scope_param(scope: &str) -> Option<Vec<String>> {
    normalize_scopes(Some(
        scope
            .split_whitespace()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    ))
}

/// Implements RFC 8414 section 3.1 for discovering well-known oauth endpoints.
/// This is a requirement for MCP servers to support OAuth.
/// https://datatracker.ietf.org/doc/html/rfc8414#section-3.1
/// https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport/auth.rs#L182
fn discovery_paths(base_path: &str) -> Vec<String> {
    let trimmed = base_path.trim_start_matches('/').trim_end_matches('/');
    let canonical = "/.well-known/oauth-authorization-server".to_string();

    if trimmed.is_empty() {
        return vec![canonical];
    }

    let mut candidates = Vec::new();
    let mut push_unique = |candidate: String| {
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    };

    push_unique(format!("{canonical}/{trimmed}"));
    push_unique(format!("/{trimmed}/.well-known/oauth-authorization-server"));
    push_unique(canonical);

    candidates
}

fn protected_resource_metadata_paths(base_path: &str) -> Vec<String> {
    let trimmed = base_path.trim_start_matches('/').trim_end_matches('/');
    let canonical = "/.well-known/oauth-protected-resource".to_string();

    if trimmed.is_empty() {
        return vec![canonical];
    }

    let mut candidates = Vec::new();
    let mut push_unique = |candidate: String| {
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    };

    push_unique(format!("{canonical}/{trimmed}"));
    push_unique(format!("/{trimmed}/.well-known/oauth-protected-resource"));
    push_unique(canonical);

    candidates
}

async fn fetch_bearer_challenge(client: &Client, base_url: &Url) -> Result<BearerChallenge> {
    let response = client
        .get(base_url.clone())
        .header(OAUTH_DISCOVERY_HEADER, OAUTH_DISCOVERY_VERSION)
        .send()
        .await?;

    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(BearerChallenge::default());
    }

    Ok(parse_bearer_challenge(response.headers()))
}

fn parse_bearer_challenge(headers: &HeaderMap) -> BearerChallenge {
    for value in headers.get_all(WWW_AUTHENTICATE) {
        let Ok(header) = value.to_str() else {
            continue;
        };

        let Some(params) = parse_bearer_challenge_params(header) else {
            continue;
        };

        return BearerChallenge {
            resource_metadata: params
                .get("resource_metadata")
                .and_then(|value| Url::parse(value).ok()),
            scope: params.get("scope").cloned(),
        };
    }

    BearerChallenge::default()
}

fn parse_bearer_challenge_params(header: &str) -> Option<HashMap<String, String>> {
    let (scheme, rest) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let mut params = HashMap::new();
    let mut chars = rest.trim().chars().peekable();

    while chars.peek().is_some() {
        while matches!(chars.peek(), Some(' ' | ',')) {
            chars.next();
        }

        if chars.peek().is_none() {
            break;
        }

        let mut key = String::new();
        while let Some(ch) = chars.peek() {
            if *ch == '=' {
                break;
            }
            key.push(*ch);
            chars.next();
        }

        if !matches!(chars.next(), Some('=')) {
            return None;
        }

        let value = if matches!(chars.peek(), Some('"')) {
            chars.next();
            let mut quoted = String::new();
            while let Some(ch) = chars.next() {
                match ch {
                    '\\' => {
                        if let Some(escaped) = chars.next() {
                            quoted.push(escaped);
                        }
                    }
                    '"' => break,
                    _ => quoted.push(ch),
                }
            }
            quoted
        } else {
            let mut bare = String::new();
            while let Some(ch) = chars.peek() {
                if *ch == ',' {
                    break;
                }
                bare.push(*ch);
                chars.next();
            }
            bare.trim().to_string()
        };

        params.insert(key.trim().to_string(), value);
    }

    Some(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::Router;
    use axum::response::Response;
    use axum::routing::get;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use tokio::task::JoinHandle;

    struct TestServer {
        url: String,
        handle: JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_oauth_discovery_server(metadata: serde_json::Value) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        let app = Router::new().route(
            "/.well-known/oauth-authorization-server/mcp",
            get({
                let metadata = metadata.clone();
                move || {
                    let metadata = metadata.clone();
                    async move { Json(metadata) }
                }
            }),
        );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should run");
        });

        TestServer {
            url: format!("http://{address}/mcp"),
            handle,
        }
    }

    async fn spawn_protected_resource_server(
        challenge_scope: Option<&str>,
        metadata: serde_json::Value,
    ) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        let metadata = metadata.clone();
        let challenge_header = challenge_scope.map(|scope| {
            let resource_metadata_url =
                format!("http://{address}/.well-known/oauth-protected-resource/mcp");
            format!("Bearer resource_metadata=\"{resource_metadata_url}\", scope=\"{scope}\"")
        });
        let app = Router::new()
            .route(
                "/mcp",
                get({
                    move || {
                        let challenge_header = challenge_header.clone();
                        async move {
                            let mut response = Response::builder().status(StatusCode::UNAUTHORIZED);
                            if let Some(challenge_header) = challenge_header {
                                response = response.header(WWW_AUTHENTICATE, challenge_header);
                            }
                            response.body(String::new()).expect("response should build")
                        }
                    }
                }),
            )
            .route(
                "/.well-known/oauth-protected-resource",
                get({
                    let metadata = metadata.clone();
                    move || {
                        let metadata = metadata.clone();
                        async move { Json(metadata) }
                    }
                }),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get({
                    move || {
                        let metadata = metadata.clone();
                        async move { Json(metadata) }
                    }
                }),
            );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should run");
        });

        TestServer {
            url: format!("http://{address}/mcp"),
            handle,
        }
    }

    async fn spawn_external_authorization_server() -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        let app = Router::new().route(
            "/.well-known/oauth-authorization-server",
            get(|| async {
                Json(serde_json::json!({
                    "authorization_endpoint": "https://example.com/authorize",
                    "token_endpoint": "https://example.com/token",
                    "scopes_supported": ["ignored"],
                }))
            }),
        );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should run");
        });

        TestServer {
            url: format!("http://{address}"),
            handle,
        }
    }

    struct EnvVarGuard {
        key: String,
        original: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &str, value: &str) -> Self {
            let original = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe {
                    std::env::set_var(&self.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(&self.key);
                }
            }
        }
    }

    #[tokio::test]
    async fn determine_auth_status_uses_bearer_token_when_authorization_header_present() {
        let status = determine_streamable_http_auth_status(
            "server",
            "not-a-url",
            None,
            Some(HashMap::from([(
                "Authorization".to_string(),
                "Bearer token".to_string(),
            )])),
            None,
            OAuthCredentialsStoreMode::Keyring,
        )
        .await
        .expect("status should compute");

        assert_eq!(status, McpAuthStatus::BearerToken);
    }

    #[tokio::test]
    #[serial(auth_status_env)]
    async fn determine_auth_status_uses_bearer_token_when_env_authorization_header_present() {
        let _guard = EnvVarGuard::set("CODEX_RMCP_CLIENT_AUTH_STATUS_TEST_TOKEN", "Bearer token");
        let status = determine_streamable_http_auth_status(
            "server",
            "not-a-url",
            None,
            None,
            Some(HashMap::from([(
                "Authorization".to_string(),
                "CODEX_RMCP_CLIENT_AUTH_STATUS_TEST_TOKEN".to_string(),
            )])),
            OAuthCredentialsStoreMode::Keyring,
        )
        .await
        .expect("status should compute");

        assert_eq!(status, McpAuthStatus::BearerToken);
    }

    #[tokio::test]
    async fn discover_streamable_http_oauth_returns_normalized_scopes() {
        let server = spawn_oauth_discovery_server(serde_json::json!({
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "scopes_supported": ["profile", " email ", "profile", "", "   "],
        }))
        .await;

        let discovery = discover_streamable_http_oauth(&server.url, None, None)
            .await
            .expect("discovery should succeed")
            .expect("oauth support should be detected");

        assert_eq!(
            discovery.scopes_supported,
            Some(vec!["profile".to_string(), "email".to_string()])
        );
    }

    #[tokio::test]
    async fn discover_streamable_http_oauth_ignores_empty_scopes() {
        let server = spawn_oauth_discovery_server(serde_json::json!({
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "scopes_supported": ["", "   "],
        }))
        .await;

        let discovery = discover_streamable_http_oauth(&server.url, None, None)
            .await
            .expect("discovery should succeed")
            .expect("oauth support should be detected");

        assert_eq!(discovery.scopes_supported, None);
    }

    #[tokio::test]
    async fn discover_streamable_http_oauth_uses_protected_resource_metadata_scopes() {
        let auth_server = spawn_external_authorization_server().await;
        let server = spawn_protected_resource_server(
            None,
            serde_json::json!({
                "authorization_servers": [auth_server.url],
                "scopes_supported": ["offline_access", " email ", "offline_access"],
            }),
        )
        .await;

        let discovery = discover_streamable_http_oauth(&server.url, None, None)
            .await
            .expect("discovery should succeed")
            .expect("oauth support should be detected");

        assert_eq!(
            discovery,
            StreamableHttpOAuthDiscovery {
                scopes_supported: Some(vec!["offline_access".to_string(), "email".to_string(),]),
            }
        );
    }

    #[tokio::test]
    async fn discover_streamable_http_oauth_prefers_scope_from_resource_metadata_challenge() {
        let auth_server = spawn_external_authorization_server().await;
        let server = spawn_protected_resource_server(
            Some("profile email"),
            serde_json::json!({
                "authorization_servers": [auth_server.url],
                "scopes_supported": ["offline_access"],
            }),
        )
        .await;

        let discovery = discover_streamable_http_oauth(&server.url, None, None)
            .await
            .expect("discovery should succeed")
            .expect("oauth support should be detected");

        assert_eq!(
            discovery,
            StreamableHttpOAuthDiscovery {
                scopes_supported: Some(vec!["profile".to_string(), "email".to_string()]),
            }
        );
    }

    #[tokio::test]
    async fn supports_oauth_login_does_not_require_scopes_supported() {
        let server = spawn_oauth_discovery_server(serde_json::json!({
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
        }))
        .await;

        let supported = supports_oauth_login(&server.url)
            .await
            .expect("support check should succeed");

        assert!(supported);
    }

    #[tokio::test]
    async fn supports_oauth_login_uses_external_authorization_server_from_protected_resource_metadata()
     {
        let auth_server = spawn_external_authorization_server().await;
        let server = spawn_protected_resource_server(
            None,
            serde_json::json!({
                "authorization_servers": [auth_server.url],
            }),
        )
        .await;

        let supported = supports_oauth_login(&server.url)
            .await
            .expect("support check should succeed");

        assert!(supported);
    }
}
