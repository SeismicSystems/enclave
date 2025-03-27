use tower::Service;
use std::{
    task::{Context, Poll},
    future::Future,
    pin::Pin,
};
use bytes::Bytes;
use jsonrpsee_core::http_helpers::read_body;
use super::{HttpRequest, HttpResponse, HttpBody};
use crate::auth::auth_future::ResponseFuture;

#[derive(Clone)]
pub struct JsonRpcPreprocessor<S> {
    pub inner: S,
}

#[derive(Debug)]
pub struct JsonRpcMetadata {
    pub method: String,
    pub body: Bytes,
}

impl<S> Service<HttpRequest> for JsonRpcPreprocessor<S>
where
    S: Service<HttpRequest, Response = HttpResponse>,
    S::Future: Send + 'static,
{
    type Response = HttpResponse;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    // type Future = Pin<Box<dyn Future<Output = ResponseFuture<S::Future>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: HttpRequest) -> Self::Future {
        let mut inner = self.inner;

        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = read_body(&parts.headers, body, 5).await.unwrap();
            // let parsed: Request<'_> = match serde_json::from_slice(&body) {
            //     Ok(req) => req,
            //     Err(_) => {
            //         return Ok(HttpResponse::builder()
            //             .status(400)
            //             .body(hyper::Body::from("Invalid JSON-RPC request"))
            //             .unwrap());
            //     }
            // };

            // // Insert method + raw body into request extensions
            // req.extensions_mut().insert(JsonRpcMetadata {
            //     method: parsed.method.to_string(),
            //     body,
            // });

            // // Reconstruct the request with a fresh body
            // *req.body_mut() = hyper::Body::from(body.clone());

            inner.call(req).await
            // ResponseFuture::future(self.inner.call(req)).await
        })
    }
}
