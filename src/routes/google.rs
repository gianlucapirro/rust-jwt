// src/routes/google.rs
use crate::services::auth::{login_or_create_social_user, set_auth_cookie};
use crate::settings::config::SETTINGS;
use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
};
use openidconnect::PkceCodeVerifier;
use openidconnect::{
    AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType},
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// In-memory store for state, nonce, pkce_verifier
type SessionStore = Arc<RwLock<HashMap<String, AuthState>>>;

#[derive(Clone)]
struct AuthState {
    nonce: String,
    pkce_verifier: String,
}

// ———————— /api/auth/google ————————
pub async fn google_login(State(store): State<SessionStore>) -> impl IntoResponse {
    // 1. Build HTTP client
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client");

    // 2. Discover provider
    let provider_metadata = match CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
        &http_client,
    )
    .await
    {
        Ok(meta) => meta,
        Err(_) => return Err(Redirect::to("/login?error=discovery")),
    };

    // 3. Build client
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(SETTINGS.google_client_id.clone()),
        Some(ClientSecret::new(SETTINGS.google_client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(SETTINGS.google_redirect_uri.clone()).unwrap());

    // 4. Generate PKCE, CSRF, Nonce
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let csrf_token = CsrfToken::new_random();
    let nonce = Nonce::new_random();

    // 5. Build auth URL
    let (auth_url, _csrf, _nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // 6. Store state
    let state_key = csrf_token.secret().clone();
    store.write().unwrap().insert(
        state_key.clone(),
        AuthState {
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
        },
    );

    // 7. Redirect to Google
    Ok(Redirect::temporary(auth_url.as_str()))
}

// ———————— /api/auth/google/callback ————————
#[derive(Deserialize)]
pub struct CallbackQuery {
    code: String,
    state: String,
}

pub async fn google_callback(
    Query(query): Query<CallbackQuery>,
    State(store): State<SessionStore>,
) -> impl IntoResponse {
    // 1. Validate state
    let auth_state = {
        let store = store.read().unwrap();
        store.get(&query.state).cloned()
    }
    .ok_or(Redirect::to("/login?error=invalid_state"))?;

    // 2. Rebuild client — http_client is used here
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client");

    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
        &http_client,
    )
    .await
    .map_err(|_| Redirect::to("/login?error=discovery"))?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(SETTINGS.google_client_id.clone()),
        Some(ClientSecret::new(SETTINGS.google_client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(SETTINGS.google_redirect_uri.clone()).unwrap());

    // 3. Exchange code — FIXED
    let token_request = client
        .exchange_code(AuthorizationCode::new(query.code))
        .map_err(|_| Redirect::to("/login?error=invalid_code"))?;

    let token_response = token_request
        .set_pkce_verifier(PkceCodeVerifier::new(auth_state.pkce_verifier))
        .request_async(&http_client) // ← Use your http_client
        .await
        .map_err(|_| Redirect::to("/login?error=token_exchange"))?;

    // 4. Get and verify ID token
    let id_token = token_response
        .id_token()
        .ok_or(Redirect::to("/login?error=no_id_token"))?;

    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(auth_state.nonce))
        .map_err(|_| Redirect::to("/login?error=invalid_token"))?;

    // 5. Optional: Verify access token hash
    if let Some(expected) = claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token.signing_alg().unwrap(),
            id_token.signing_key(&client.id_token_verifier()).unwrap(),
        )
        .map_err(|_| Redirect::to("/login?error=hash_calc"))?;
        if actual != *expected {
            return Err(Redirect::to("/login?error=invalid_access_token"));
        }
    }

    // 6. Extract user info
    let email = claims
        .email()
        .and_then(|e| e.get(None))
        .map(|s| s.to_string())
        .ok_or(Redirect::to("/login?error=no_email"))?;

    let name = claims
        .full_name()
        .and_then(|n| n.get(None))
        .map(|s| s.to_string());

    // 7. Login or create user
    let user = login_or_create_social_user(&email, name.as_deref(), "google")
        .await
        .map_err(|_| Redirect::to("/login?error=auth_failed"))?;

    // 8. Set cookie
    let mut response = Redirect::to("/").into_response();
    set_auth_cookie(&mut redirect, &user_model, &app.jwt)
        .map_err(|_| Redirect::to("/login?error=cookie"))?;

    // 9. Clean up
    store.write().unwrap().remove(&query.state);

    Ok(response)
}

// ———————— Router ————————
pub fn google_routes() -> Router {
    let store: SessionStore = Arc::new(RwLock::new(HashMap::new()));
    Router::new()
        .route("/api/auth/google", get(google_login))
        .route("/api/auth/google/callback", get(google_callback))
        .with_state(store)
}
