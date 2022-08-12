use serde::Serialize;

use super::{Entry, TokenOrRequest, TokenProvider};
use crate::{error, token::RequestReason, Error, Token};

const IAM_CREDENTIALS_ENDPOINT: &'static str = "https://iamcredentials.googleapis.com";

// The impersonation response is in a different format from the other GCP responses. Why, Google, why?
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    /// The actual token
    #[serde(rename = "accessToken")]
    access_token: String,
    /// The time until the token expires and a new one needs to be requested.
    /// In RFC3339 format.
    #[serde(rename = "expireTime")]
    expires_time: String,
}

impl From<TokenResponse> for Token {
    fn from(response: TokenResponse) -> Token {
        let expires = time::OffsetDateTime::parse(
            &response.expires_time,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let expires_in = (expires - time::OffsetDateTime::now_utc()).whole_seconds();
        Token {
            access_token: response.access_token,
            refresh_token: String::new(),
            token_type: String::new(), // FIXME?
            expires_in_timestamp: Some(expires.into()),
            expires_in: Some(expires_in.max(0)),
        }
    }
}

fn uri(email: &str) -> String {
    format!(
        "{}/v1/projects/-/serviceAccounts/{}:generateAccessToken",
        IAM_CREDENTIALS_ENDPOINT, email
    )
}

pub struct ImpersonatedAccountInfo {
    /// A token for the end user that will be impersonating the service account.
    pub user_token: Token,
    /// The email address of the service account to impersonate.
    ///
    /// For example, my-test-account@my-test-project.iam.gserviceaccount.com
    pub service_account_email: String,
}

pub struct ImpersonatedAccountProvider {
    info: ImpersonatedAccountInfo,
    cache: std::sync::Mutex<Vec<Entry>>,
}

impl ImpersonatedAccountProvider {
    pub fn new(info: ImpersonatedAccountInfo) -> Self {
        ImpersonatedAccountProvider {
            info,
            cache: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Hashes a set of scopes to a numeric key we can use to have an in-memory
    /// cache of scopes -> token
    // FIXME: copy-paste from service_account
    fn serialize_scopes<'a, I, S>(scopes: I) -> (u64, Vec<String>)
    where
        S: AsRef<str> + 'a,
        I: Iterator<Item = &'a S>,
    {
        use std::hash::Hasher;

        let scopes = scopes.map(|s| s.as_ref().to_owned()).collect::<Vec<_>>();
        let hash = {
            let mut hasher = twox_hash::XxHash::default();
            for s in &scopes {
                hasher.write(s.as_bytes());
            }
            hasher.finish()
        };

        (hash, scopes)
    }
}

#[derive(Serialize)]
struct Request {
    scope: Vec<String>,
    lifetime: String,
    // TODO: delegates? what are they for?
}

impl TokenProvider for ImpersonatedAccountProvider {
    fn get_token_with_subject<'a, S, I, T>(
        &self,
        // FIXME: what to do with this?
        _subject: Option<T>,
        scopes: I,
    ) -> Result<TokenOrRequest, Error>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
        T: Into<String>,
    {
        let (hash, scopes) = Self::serialize_scopes(scopes.into_iter());
        let reason = {
            let cache = self.cache.lock().map_err(|_e| Error::Poisoned)?;
            match cache.binary_search_by(|i| i.hash.cmp(&hash)) {
                Ok(i) => {
                    let token = &cache[i].token;

                    if !token.has_expired() {
                        return Ok(TokenOrRequest::Token(token.clone()));
                    }

                    RequestReason::Expired
                }
                Err(_) => RequestReason::ScopesChanged,
            }
        };

        let uri = uri(&self.info.service_account_email);

        let body = Request {
            scope: scopes,
            lifetime: "3600s".to_owned(), // FIXME
        };
        let body = serde_json::to_vec(&body)?;
        let request = http::Request::builder()
            .method("POST")
            .uri(&uri)
            .header(
                http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", self.info.user_token.access_token),
            )
            .body(body)?;

        Ok(TokenOrRequest::Request {
            reason,
            request,
            scope_hash: hash,
        })
    }

    fn parse_token_response<S>(
        &self,
        hash: u64,
        response: http::Response<S>,
    ) -> Result<Token, Error>
    where
        S: AsRef<[u8]>,
    {
        let (parts, body) = response.into_parts();

        if !parts.status.is_success() {
            let body_bytes = body.as_ref();

            if parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|ct| ct.to_str().ok())
                == Some("application/json; charset=utf-8")
            {
                if let Ok(auth_error) = serde_json::from_slice::<error::AuthError>(body_bytes) {
                    return Err(Error::Auth(auth_error));
                }
            }

            return Err(Error::HttpStatus(parts.status));
        }

        let token_res: TokenResponse = serde_json::from_slice(body.as_ref())?;
        let token: Token = token_res.into();

        // Last token wins, which...should?...be fine
        {
            let mut cache = self.cache.lock().map_err(|_e| Error::Poisoned)?;
            match cache.binary_search_by(|i| i.hash.cmp(&hash)) {
                Ok(i) => cache[i].token = token.clone(),
                Err(i) => {
                    cache.insert(
                        i,
                        Entry {
                            hash,
                            token: token.clone(),
                        },
                    );
                }
            };
        }

        Ok(token)
    }
}
