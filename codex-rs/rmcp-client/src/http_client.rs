use std::env;
use std::fs;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use reqwest::Client;
use reqwest::ClientBuilder;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderName;
use reqwest::header::HeaderValue;

const CODEX_CA_CERTIFICATE_ENV: &str = "CODEX_CA_CERTIFICATE";
const SSL_CERT_FILE_ENV: &str = "SSL_CERT_FILE";

pub(crate) fn build_http_client(
    default_headers: Option<&HeaderMap>,
    no_proxy: bool,
    timeout: Option<Duration>,
) -> Result<Client> {
    let mut builder = Client::builder();
    if no_proxy {
        builder = builder.no_proxy();
    }
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    if let Some(default_headers) = default_headers.filter(|headers| !headers.is_empty()) {
        builder = builder.default_headers(default_headers.clone());
    }
    apply_custom_ca_bundle(builder)
}

pub(crate) fn custom_headers_from(
    default_headers: &HeaderMap,
) -> std::collections::HashMap<HeaderName, HeaderValue> {
    default_headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn apply_custom_ca_bundle(builder: ClientBuilder) -> Result<Client> {
    let Some(ca_bundle_path) = configured_ca_bundle_path() else {
        return builder
            .build()
            .context("failed to build HTTP client with system root certificates");
    };

    let pem_bundle = fs::read(&ca_bundle_path)
        .with_context(|| format!("failed to read CA certificate bundle `{ca_bundle_path}`"))?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem_bundle)
        .with_context(|| format!("failed to parse PEM certificates from `{ca_bundle_path}`"))?;

    let builder = certificates
        .into_iter()
        .fold(builder, |builder, certificate| {
            builder.add_root_certificate(certificate)
        });

    builder.build().with_context(|| {
        format!("failed to build HTTP client with custom CA bundle `{ca_bundle_path}`")
    })
}

fn configured_ca_bundle_path() -> Option<String> {
    [CODEX_CA_CERTIFICATE_ENV, SSL_CERT_FILE_ENV]
        .into_iter()
        .find_map(|env_var| {
            env::var(env_var)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}
