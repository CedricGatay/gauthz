//! An interface for fetching Google API tokens targeting
//! [Server to Server](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)
//! applications
//!
//! # examples
//!
//! ```no_run
//! // gauthz interfaces
//! extern crate futures;
//! extern crate gauthz;
//! use futures::Future;
//!
//! use gauthz::{Credentials, Result, Scope, Tokens};
//!
//! async fn run() -> Result<String> {
//!     let tokens = Tokens::new(
//!         Credentials::default().unwrap(),
//!         vec![Scope::CloudPlatform],
//!     );
//!     let access_token = tokens.get().await;
//!     access_token.map(|t| t.value().to_owned())
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     match run().await {
//!         Ok(ok) => println!("{}", ok),
//!         Err(err) => println!("{}", err),
//!     }
//! }
//! ```
//!
//! # Cargo features
//!
//! This crate has one Cargo feature, `tls`, which adds HTTPS support via the `Tokens::new`
//! constructor. This feature is enabled by default.
#![warn(missing_docs)]
#![feature(async_closure)]

#[macro_use]
extern crate serde_derive;
extern crate medallion;
extern crate serde_json;
extern crate time;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate hyper;
#[cfg(feature = "tls")]
extern crate hyper_tls;
extern crate tokio;

use std::env;
use std::fs::File;
use std::io::Read;
use std::time::{Duration, Instant};

use futures::{Future as StdFuture, Stream as StdStream, future, stream};
use hyper::{Client as HyperClient, Method, Request, Body};
use hyper::client::connect::Connect;
use hyper::client::{HttpConnector};

#[cfg(feature = "tls")]
use hyper_tls::HttpsConnector;
use medallion::{Algorithm, Header, Payload, Token};

pub mod error;

use error::*;
pub use error::{Error, Result};

mod scope;

pub use scope::*;
use std::pin::Pin;


/// A `Stream` with an error type pinned to `gauthz::Error`
pub type Stream<T> = Box<StdStream<Item=T>>;

const TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v4/token";

/// Authentication credential information generated from google api console
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Credentials {
    /// a pem encoded rsa key
    private_key: String,
    /// account email
    client_email: String,
}

impl Credentials {
    /// Attempts to resolve credentials from location
    /// defined by common Google API env var
    /// `GOOGLE_APPLICATION_CREDENTIALS`
    pub fn default() -> Result<Credentials> {
        let file = File::open(
            env::var("GOOGLE_APPLICATION_CREDENTIALS").map_err(|_| {
                ErrorKind::Msg("missing GOOGLE_APPLICATION_CREDENTIALS".into())
            })?,
        )?;
        Self::from_reader(file)
    }
    /// Convenience method for parsing credentials from json str
    pub fn from_str(s: &str) -> Result<Credentials> {
        serde_json::from_str(s).map_err(Error::from)
    }
    /// Convenience method for parsing credentials from a reader
    /// ( i.e. a `std::fs:File` )
    pub fn from_reader<R>(r: R) -> Result<Credentials>
        where
            R: Read,
    {
        serde_json::from_reader(r).map_err(Error::from)
    }
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
}

/// An access token can be used to authenticate
/// google api requests
///
/// Instances of these can be onbtained from one of the methods provided by
/// `gauthz.Tokens`
#[derive(Default, Deserialize, PartialEq, Debug, Clone)]
pub struct AccessToken {
    access_token: String,
    expires_in: u64,
    #[serde(default, skip)]
    instant: Option<Instant>,
    #[serde(default, skip)]
    duration: Option<Duration>,
}

impl AccessToken {
    /// Returns string value of access token
    ///
    /// This is typically the value you use for HTTP Authorization: Bearer
    /// header values
    pub fn value(&self) -> &str {
        &self.access_token
    }
    /// Returns true if this access token has has expired
    ///
    /// This is typically one hour in practice
    pub fn expired(&self) -> bool {
        match (self.instant, self.duration) {
            (Some(inst), Some(dur)) => inst.elapsed() >= dur,
            _ => false,
        }
    }

    fn start(mut self) -> Self {
        self.instant = Some(Instant::now());
        self.duration = Some(Duration::from_secs(self.expires_in));
        self
    }
}

/// An interface for generating access tokens to authenticate
/// google api requests
///
/// A scope is required to limit access to target apis
/// some scopes, like https://www.googleapis.com/auth/cloud-platform,
/// provide access to multiple apis
#[derive(Clone)]
pub struct Tokens<C>
    where
        C: Connect + Clone + Send + Sync,
{
    http: HyperClient<C>,
    credentials: Credentials,
    scopes: String,
}

#[cfg(feature = "tls")]
impl Tokens<HttpsConnector<HttpConnector>> {
    /// Creates a new instance of `Tokens` using a `hyper::Client`
    /// preconfigured for tls.
    ///
    /// For client customization use `Tokens::custom` instead
    pub fn new<Iter>(
credentials: Credentials,
scopes: Iter,
    ) -> Self
        where
            Iter: ::std::iter::IntoIterator<Item=Scope>,
    {
        let connector = HttpsConnector::new();
        let hyper = HyperClient::builder()
            .keep_alive(true)
            .build(connector);
        Tokens::custom(hyper, credentials, scopes)
    }
}

impl<C: 'static + Connect + Clone + Send + Sync> Tokens<C> {
    /// Creates a new instance of `Tokens` with a custom `hyper::Client`
    /// with a customly configured `hyper::Client`
    pub fn custom<Iter>(
        http: HyperClient<C>,
        credentials: Credentials,
        scopes: Iter,
    ) -> Self
        where
            Iter: ::std::iter::IntoIterator<Item=Scope>,
    {
        Self {
            http,
            credentials,
            scopes: scopes
                .into_iter()
                .map(|s| s.url())
                .collect::<Vec<_>>()
                .join(","),
        }
    }
    /*
        /// Returns a `Stream` of `AccessTokens`. The same `AccessToken` will be
        /// yielded multiple times until it is expired. After which, a new token
        /// will be fetched
        pub fn stream(&self) -> Stream<AccessToken> {
            let instance = self.clone();
            let tokens =
                stream::unfold(None, async move |state: Option<AccessToken>| -> Option<(AccessToken, Option<AccessToken>)>{
                    let instance = instance.clone();
                    match state {
                        Some(ref token) if !token.expired() => {
                            Some((token.clone(), state.clone()))
                        },
                        _ => {
                            let token = instance.get().await.ok()?;
                            let next = Some(token.clone());
                            Some((token.clone(), next))

                            //future::ok((None, state.clone())).await.ok()
                        }
                    }
                });
            /*
                stream::unfold::<
                    _,
                    _,
                    Future<(AccessToken, Option<AccessToken>)>,
                    _,
                >(None, move |state| {
                    match state {
                        Some(ref token) if !token.expired() => {
                            Box::new(future::ok((token.clone(), state.clone())))
                        }
                        _ => {
                            Box::new(async {instance.get().await.map(|token| {
                                let next = Some(token.clone());
                                (token, next)
                            }).unwrap()})
                        }
                    }
                });*/
            Box::new(tokens)
        }
    */
    fn new_request(&self) -> Request<Body> {
        let header: Header<()> = Header {
            alg: Algorithm::RS256,
            ..Default::default()
        };
        let iat = time::now_utc().to_timespec().sec;
        let exp = iat + 3600;
        let payload = Payload {
            claims: Some(Claims {
                iss: self.credentials.clone().client_email,
                scope: self.scopes.clone(),
                aud: TOKEN_URL.into(),
                exp: exp,
                iat: iat,
            }),
            ..Default::default()
        };
        let signed = Token::new(header, payload)
            .sign(&self.credentials.clone().private_key.into_bytes())
            .unwrap();
        let body = Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}",
            assertion = signed.as_str()
        ));
        let req = Request::builder().uri(TOKEN_URL).method(Method::POST)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body).unwrap();
        req
    }

    /// Returns a `Future` yielding a new `AccessToken`
    pub async fn get(&self) -> Result<AccessToken> {
        let response = self.http
            .request(self.new_request()).await
            .map_err(|e| Error::from(e.to_string()))?;
        let status = response.status();
        let bytes = hyper::body::to_bytes(response).await?;
        serde_json::from_slice::<AccessToken>(&bytes)
            .map_err(|err| ErrorKind::Codec(err).into())
            .map(AccessToken::start)
        /*let body = response.body();//concat2().map_err(Error::from);
        body.and_then(move |body| if status.is_success() {
            serde_json::from_str::<AccessToken>(&body)
                .map_err(|err| ErrorKind::Codec(err).into())
                .map(AccessToken::start)
        } else {
            Err(match serde_json::from_str::<ApiError>(&body) {
                Err(err) => ErrorKind::Codec(err).into(),
                Ok(err) => {
                    ErrorKind::Api(err.error, err.error_description)
                        .into()
                }
            })
        })*/
    }
}

#[cfg(test)]
mod tests {
    use super::AccessToken;
    use std::time::Duration;


    #[test]
    fn tokens_value() {
        let token = AccessToken {
            access_token: "test".into(),
            expires_in: 1,
            ..Default::default()
        };
        assert_eq!(token.value(), token.access_token)
    }

    #[test]
    fn tokens_expire() {
        let token = AccessToken {
            access_token: "test".into(),
            expires_in: 1,
            ..Default::default()
        }.start();
        assert!(!token.expired());
        let duration = Duration::from_secs(1);
        assert_eq!(token.duration, Some(duration));
        ::std::thread::sleep(duration);
        assert!(token.expired())
    }
}
