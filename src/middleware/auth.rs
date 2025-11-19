use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures::future::LocalBoxFuture;
use std::future::{ready, Ready};

use crate::utils::verify_token;

pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService { service }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
}

fn add_cors_headers(mut response: HttpResponse) -> HttpResponse {
    let headers = response.headers_mut();
    headers.insert(
        actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        actix_web::http::header::HeaderValue::from_static("http://localhost:5173"),
    );
    headers.insert(
        actix_web::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        actix_web::http::header::HeaderValue::from_static("true"),
    );
    response
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Skip auth for OPTIONS requests (CORS preflight)
        if req.method() == actix_web::http::Method::OPTIONS {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }

        let auth_header = req.headers().get("Authorization");

        if let Some(auth_value) = auth_header {
            if let Ok(auth_str) = auth_value.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    match verify_token(token) {
                        Ok(claims) => {
                            let user_id = claims.sub.clone();
                            req.extensions_mut().insert(claims);
                            // Also insert user_id as String for handlers that use web::ReqData<String>
                            req.extensions_mut().insert(user_id);
                            let fut = self.service.call(req);
                            return Box::pin(async move {
                                let res = fut.await?;
                                Ok(res)
                            });
                        }
                        Err(_) => {
                            return Box::pin(async move {
                                let response = HttpResponse::Unauthorized()
                                    .body("Invalid token");
                                let response = add_cors_headers(response);
                                Err(actix_web::error::InternalError::from_response(
                                    "Invalid token",
                                    response,
                                ).into())
                            });
                        }
                    }
                }
            }
        }

        Box::pin(async move {
            let response = HttpResponse::Unauthorized()
                .body("Missing or invalid authorization header");
            let response = add_cors_headers(response);
            Err(actix_web::error::InternalError::from_response(
                "Missing or invalid authorization header",
                response,
            ).into())
        })
    }
}
