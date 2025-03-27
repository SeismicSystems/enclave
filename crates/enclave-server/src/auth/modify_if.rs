
use jsonrpsee::core::client::ClientT;
use jsonrpsee::server::Server;
use jsonrpsee::server::middleware::rpc::{RpcServiceBuilder, RpcServiceT};
use jsonrpsee::types::Request;
use std::borrow::Cow as StdCow;

use tower::Service;
use std::task::Context;
use std::task::Poll;

// use jsonrpsee::types::{Response, Request};

use super::HttpResponse;

// use super::{HttpRequest, HttpResponse};

#[derive(Clone)]
pub struct ModifyRequestIf<S> {
	pub inner: S,
}

impl<'a, S> RpcServiceT<'a> for ModifyRequestIf<S>
where
	S: Send + Sync + RpcServiceT<'a>,
{
	type Future = S::Future;

	fn call(&self, mut req: Request<'a>) -> Self::Future {
		// Example how to modify the params in the call.
		if req.method == "say_hello" {
			// It's a bit awkward to create new params in the request
			// but this shows how to do it.
			let raw_value = serde_json::value::to_raw_value("myparams").unwrap();
			req.params = Some(StdCow::Owned(raw_value));
		}
		// Re-direct all calls that isn't `say_hello` to `say_goodbye`
		else if req.method != "say_hello" {
			req.method = "say_goodbye".into();
		}

		self.inner.call(req)
	}
}

impl<S> Service<Request<'static>> for ModifyRequestIf<S>
where
    S: Service<Request<'static>, Response = HttpResponse>,
    S::Future: Send + 'static,
{
    type Error = S::Error;
    type Future = S::Future;
	type Response = HttpResponse;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<'static>) -> Self::Future {
        if req.method == "say_hello" {
            let raw_value = serde_json::value::to_raw_value("myparams").unwrap();
            req.params = Some(StdCow::Owned(raw_value));
        } else if req.method != "say_hello" {
            req.method = "say_goodbye".into();
        }

        self.inner.call(req)
    }
}