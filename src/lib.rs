//! # actix-web-middleware-slack
//! actix-web middleware for [Verifying requests from Slack](https://api.slack.com/authentication/verifying-requests-from-slack)
//!
//! ## Quick Start
//! ```
//! use actix_web::{App, HttpServer, web};
//! use actix_web_middleware_slack::Slack;
//!
//! #[tokio::main]
//! async fn main() {
//!     // https://api.slack.com/authentication/verifying-requests-from-slack#verifying-requests-from-slack-using-signing-secrets__app-management-updates
//!     let signing_secret = "Signing Secret";
//!     let app = App::new().wrap(Slack::new(signing_secret));
//! }
//! ```

use std::future::{ready, Ready};

use std::rc::Rc;
use std::time::UNIX_EPOCH;

use actix_http::h1::Payload;
use actix_web::dev::forward_ready;
use actix_web::http::header::HeaderMap;
use actix_web::web::BytesMut;
use actix_web::{
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Clone)]
pub struct Slack {
    slack_signing_secret: String,
}

impl Slack {
    pub fn new(slack_signing_secret: impl Into<String>) -> Self {
        Self {
            slack_signing_secret: slack_signing_secret.into(),
        }
    }
}

const HEADER_TIMESTAMP: &str = "X-Slack-Request-Timestamp";
const HEADER_SIGNATURE: &str = "X-Slack-Signature";

impl<S: 'static, B> Transform<S, ServiceRequest> for Slack
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = SlackMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SlackMiddleware {
            service: Rc::new(service),
            slack_signing_secret: self.slack_signing_secret.to_string(),
        }))
    }
}

type HmacSha256 = Hmac<Sha256>;

pub struct SlackMiddleware<S> {
    service: Rc<S>,
    slack_signing_secret: String,
}

impl<S, B> Service<ServiceRequest> for SlackMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let headers = req.headers();
        let ts = match get_timestamp(headers) {
            Some(ts) => ts,
            None => {
                return Box::pin(async { Ok(bad_request(req, format!("header '{}' is required", HEADER_TIMESTAMP))) })
            }
        };
        let signature = match get_signature(headers) {
            Some(signature) => signature,
            None => {
                return Box::pin(async { Ok(bad_request(req, format!("header '{}' is required", HEADER_SIGNATURE))) })
            }
        };

        let service = self.service.clone();
        let slack_signing_secret = self.slack_signing_secret.to_string();
        Box::pin(async move {
            let mut payload = req.take_payload();
            let mut body = BytesMut::new();
            while let Some(item) = payload.next().await {
                body.extend_from_slice(&item?);
            }
            let calculated_signature =
                sign(ts, String::from_utf8(body.to_vec()).unwrap(), slack_signing_secret.as_bytes());
            if calculated_signature == signature {
                let (_, mut payload) = Payload::create(true);
                payload.unread_data(body.into());
                req.set_payload(payload.into());
                let res = service.call(req);
                res.await.map(ServiceResponse::map_into_left_body)
            } else {
                Ok(bad_request(req, "invalid signature".to_string()))
            }
        })
    }
}

fn sign(ts: u64, body: String, secret: &[u8]) -> String {
    let sig_basestring = format!("v0:{}:{}", ts, body);
    let mut hmac = HmacSha256::new_from_slice(secret).unwrap();
    hmac.update(sig_basestring.as_bytes());
    format!("v0={}", hex::encode(hmac.finalize().into_bytes()))
}

fn get_timestamp(header: &HeaderMap) -> Option<u64> {
    let ts = header.get(HEADER_TIMESTAMP)?;
    let ts = ts.to_str().ok()?.parse::<u64>().ok()?;
    let now = std::time::SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if now - ts > 60 * 5 {
        None
    } else {
        Some(ts)
    }
}

fn get_signature(header: &HeaderMap) -> Option<String> {
    let signature = header.get(HEADER_SIGNATURE)?;
    Some(signature.to_str().ok()?.to_string())
}

fn bad_request<B>(req: ServiceRequest, body: String) -> ServiceResponse<EitherBody<B>> {
    let (req, _pl) = req.into_parts();
    let response = HttpResponse::BadRequest().body(body).map_into_right_body();
    ServiceResponse::new(req, response)
}

#[cfg(test)]
mod tests {
    use actix_web::dev::{Service, Transform};
    use actix_web::http::StatusCode;
    use actix_web::test;
    use actix_web::test::TestRequest;

    use crate::{sign, Slack, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use actix_http::body::to_bytes;
    use actix_http::h1::Payload;
    use actix_web::web::Bytes;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";
    const TEST_BODY : &str = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";

    trait BodyTest {
        fn as_str(&self) -> &str;
    }

    impl BodyTest for Bytes {
        fn as_str(&self) -> &str {
            std::str::from_utf8(self).unwrap()
        }
    }

    #[test]
    fn test_sign() {
        assert_eq!(
            "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
            sign(1531420618, TEST_BODY.to_string(), TEST_SECRET.as_bytes())
        );
    }

    #[tokio::test]
    async fn no_timestamp_header() {
        let mw = Slack::new("test").new_transform(test::ok_service()).await.unwrap();
        let req = TestRequest::default().to_srv_request();
        let res = mw.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body()).await.unwrap();
        assert_eq!(body.as_str(), format!("header '{}' is required", HEADER_TIMESTAMP));
    }

    #[tokio::test]
    async fn old_timestamp() {
        let mut now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        now -= 60 * 5 + 1;
        let mut req = TestRequest::default().to_srv_request();
        req.headers_mut()
            .insert(HEADER_TIMESTAMP.try_into().unwrap(), now.into());
        let mw = Slack::new("test").new_transform(test::ok_service()).await.unwrap();
        let res = mw.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body()).await.unwrap();
        assert_eq!(body.as_str(), format!("header '{}' is required", HEADER_TIMESTAMP));
    }

    #[tokio::test]
    async fn no_signature_header() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut req = TestRequest::default().to_srv_request();
        req.headers_mut()
            .insert(HEADER_TIMESTAMP.try_into().unwrap(), now.into());
        let mw = Slack::new("test").new_transform(test::ok_service()).await.unwrap();
        let res = mw.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body()).await.unwrap();
        assert_eq!(body.as_str(), format!("header '{}' is required", HEADER_SIGNATURE));
    }

    #[tokio::test]
    async fn invalid_sign() {
        let mw = Slack::new(TEST_SECRET).new_transform(test::ok_service()).await.unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut req = TestRequest::default().to_srv_request();
        let _headers = req.headers_mut();
        req.headers_mut()
            .insert(HEADER_TIMESTAMP.try_into().unwrap(), now.into());
        req.headers_mut()
            .insert(HEADER_SIGNATURE.try_into().unwrap(), "aaa".try_into().unwrap());
        let res = mw.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body()).await.unwrap();
        assert_eq!(body.as_str(), "invalid signature");
    }

    #[tokio::test]
    async fn success() {
        let mw = Slack::new(TEST_SECRET).new_transform(test::ok_service()).await.unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let signature = sign(now, TEST_BODY.to_string(), TEST_SECRET.as_bytes());

        // request body
        let mut req = TestRequest::default().to_srv_request();
        let (_, mut payload) = Payload::create(true);
        payload.unread_data(TEST_BODY.into());
        req.set_payload(payload.into());

        // headers
        let _headers = req.headers_mut();
        req.headers_mut()
            .insert(HEADER_TIMESTAMP.try_into().unwrap(), now.into());
        req.headers_mut()
            .insert(HEADER_SIGNATURE.try_into().unwrap(), signature.try_into().unwrap());

        let res = mw.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
