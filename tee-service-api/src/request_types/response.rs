use http_body_util::Full;
use bytes::Bytes;

pub type BytesBody = Full<Bytes>;

pub fn string_body(body: String) -> BytesBody {
    Full::new(Bytes::from(body))
}