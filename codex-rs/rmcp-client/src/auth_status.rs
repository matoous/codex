use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use codex_protocol::protocol::McpAuthStatus;
use reqwest::header::AUTHORIZATION;
use reqwest::header::HeaderMap;
use rmcp::transport::auth::AuthError;
use rmcp::transport::auth::AuthorizationManager;
use tracing::debug;

use crate::OAuthCredentialsStoreMode;
use crate::http_client::build_http_client;
use crate::oauth::has_oauth_tokens;
use crate::utils::build_default_headers;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

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
    let http_client = build_http_client(
        Some(default_headers),
        /*no_proxy*/ true,
        Some(DISCOVERY_TIMEOUT),
    )?;
    let mut auth_manager = AuthorizationManager::new(url).await?;
    auth_manager.with_client(http_client)?;

    match auth_manager.discover_metadata().await {
        Ok(_) => Ok(Some(StreamableHttpOAuthDiscovery {
            scopes_supported: normalize_scopes(auth_manager.select_scopes(None, &[])),
        })),
        Err(AuthError::NoAuthorizationSupport) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn normalize_scopes(scopes_supported: Vec<String>) -> Option<Vec<String>> {
    let mut normalized = Vec::new();
    for scope in scopes_supported {
        let scope = scope.trim();
        if scope.is_empty() {
            continue;
        }
        if !normalized.iter().any(|existing| existing == scope) {
            normalized.push(scope.to_string());
        }
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::OsString;

    use axum::Router;
    use axum::extract::State;
    use axum::http::HeaderValue;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use serial_test::serial;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::DISCOVERY_TIMEOUT;
    use super::StreamableHttpOAuthDiscovery;
    use super::determine_streamable_http_auth_status;
    use super::discover_streamable_http_oauth;
    use super::supports_oauth_login;
    use crate::McpAuthStatus;
    use crate::OAuthCredentialsStoreMode;

    #[derive(Clone)]
    struct TestAppState {
        authorize_url: String,
        token_url: String,
        protected_resource_scopes: Option<Vec<String>>,
        challenge_scope: Option<String>,
    }

    struct TestServer {
        url: String,
        _handle: JoinHandle<()>,
    }

    async fn spawn_oauth_discovery_server(
        protected_resource_scopes: Option<Vec<String>>,
        challenge_scope: Option<&str>,
    ) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        let base_url = format!("http://{address}");
        let state = TestAppState {
            authorize_url: format!("{base_url}/authorize"),
            token_url: format!("{base_url}/token"),
            protected_resource_scopes,
            challenge_scope: challenge_scope.map(str::to_string),
        };

        let app = Router::new()
            .route("/mcp", get(mcp_route))
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource_metadata_route),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(authorization_server_metadata_route),
            )
            .with_state(state);

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should run");
        });

        TestServer {
            url: format!("{base_url}/mcp"),
            _handle: handle,
        }
    }

    async fn mcp_route(State(state): State<TestAppState>) -> impl IntoResponse {
        let resource_metadata = "/.well-known/oauth-protected-resource";
        let mut challenge = format!("Bearer resource_metadata=\"{resource_metadata}\"");
        if let Some(scope) = &state.challenge_scope {
            challenge.push_str(&format!(", scope=\"{scope}\""));
        }

        (
            StatusCode::UNAUTHORIZED,
            [(
                "WWW-Authenticate",
                HeaderValue::from_str(&challenge).expect("valid header"),
            )],
        )
    }

    async fn protected_resource_metadata_route(
        State(state): State<TestAppState>,
    ) -> impl IntoResponse {
        let mut metadata = json!({
            "authorization_servers": ["./"],
        });
        if let Some(scopes_supported) = &state.protected_resource_scopes {
            metadata["scopes_supported"] = json!(scopes_supported);
        }
        serde_json::to_string(&metadata).expect("metadata should serialize")
    }

    async fn authorization_server_metadata_route(
        State(state): State<TestAppState>,
    ) -> impl IntoResponse {
        serde_json::to_string(&json!({
            "authorization_endpoint": state.authorize_url,
            "token_endpoint": state.token_url,
            "scopes_supported": ["offline_access", "email", "profile"],
        }))
        .expect("metadata should serialize")
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
            /*bearer_token_env_var*/ None,
            Some(HashMap::from([(
                "Authorization".to_string(),
                "Bearer token".to_string(),
            )])),
            /*env_http_headers*/ None,
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
            /*bearer_token_env_var*/ None,
            /*http_headers*/ None,
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
    async fn discover_streamable_http_oauth_uses_protected_resource_metadata_scopes() {
        let server = spawn_oauth_discovery_server(
            Some(vec![
                "profile".to_string(),
                " email ".to_string(),
                "profile".to_string(),
                "".to_string(),
                "   ".to_string(),
            ]),
            None,
        )
        .await;

        let discovery = discover_streamable_http_oauth(
            &server.url,
            /*http_headers*/ None,
            /*env_http_headers*/ None,
        )
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
    async fn discover_streamable_http_oauth_prefers_scope_from_www_authenticate() {
        let server = spawn_oauth_discovery_server(
            Some(vec!["profile".to_string()]),
            Some("offline_access email"),
        )
        .await;

        let discovery = discover_streamable_http_oauth(
            &server.url,
            /*http_headers*/ None,
            /*env_http_headers*/ None,
        )
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
    async fn supports_oauth_login_does_not_require_scopes_supported() {
        let server = spawn_oauth_discovery_server(None, None).await;

        let supported =
            tokio::time::timeout(DISCOVERY_TIMEOUT * 2, supports_oauth_login(&server.url))
                .await
                .expect("support check should not time out")
                .expect("support check should succeed");

        assert!(supported);
    }
}
