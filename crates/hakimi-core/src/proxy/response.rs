use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};

use super::upstream;
use super::{BoxError, ProxyBody};

pub(crate) fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub(crate) fn full_body(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub(super) fn empty_response(status: StatusCode) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .expect("static response")
}

pub(crate) fn text_response(
    status: StatusCode,
    content_type: &str,
    body: impl Into<String>,
) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(full_body(body.into()))
        .expect("text response")
}

pub(crate) fn json_response(value: serde_json::Value) -> Response<ProxyBody> {
    text_response(
        StatusCode::OK,
        "application/json; charset=utf-8",
        value.to_string(),
    )
}

pub(crate) fn error_response(status: StatusCode, title: &str, detail: &str) -> Response<ProxyBody> {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title>{style}</head>\
         <body><main><h1>{title}</h1><p class=\"code\">{status}</p><pre>{detail}</pre></main></body></html>",
        title = escape_html(title),
        status = status.as_u16(),
        detail = escape_html(detail),
        style = upstream::ERROR_STYLE,
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full_body(body))
        .expect("error response")
}

pub(crate) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
