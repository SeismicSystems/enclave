use super::HttpResponse;
use std::future::Future;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::Poll;
use std::task::Context;

/// A future representing the response of an RPC request
#[pin_project]
#[allow(missing_debug_implementations)]
pub struct ResponseFuture<F> {
    /// The kind of response future, error or pending
    #[pin]
    kind: Kind<F>,
}

impl<F> ResponseFuture<F> {
    pub const fn future(future: F) -> Self {
        Self { kind: Kind::Future { future } }
    }

    pub const fn invalid_auth(err_res: HttpResponse) -> Self {
        Self { kind: Kind::Error { response: Some(err_res) } }
    }
}

#[pin_project(project = KindProj)]
enum Kind<F> {
    Future {
        #[pin]
        future: F,
    },
    Error {
        response: Option<HttpResponse>,
    },
}

impl<F, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<HttpResponse, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().kind.project() {
            KindProj::Future { future } => future.poll(cx),
            KindProj::Error { response } => {
                let response = response.take().unwrap();
                Poll::Ready(Ok(response))
            }
        }
    }
}