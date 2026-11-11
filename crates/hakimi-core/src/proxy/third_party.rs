use http::header::{self, HeaderMap, HeaderName};

const SET_COOKIE2: HeaderName = HeaderName::from_static("set-cookie2");

pub(crate) fn strip_request_credentials(headers: &mut HeaderMap) {
    headers.remove(header::COOKIE);
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::PROXY_AUTHORIZATION);
}

pub(crate) fn strip_response_cookies(headers: &mut HeaderMap) {
    headers.remove(header::SET_COOKIE);
    headers.remove(&SET_COOKIE2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn request_credentials_are_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("session=secret"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        headers.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic secret"),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("image/*"));

        strip_request_credentials(&mut headers);

        assert!(!headers.contains_key(header::COOKIE));
        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert!(!headers.contains_key(header::PROXY_AUTHORIZATION));
        assert_eq!(headers[header::ACCEPT], "image/*");
    }

    #[test]
    fn response_cookies_are_stripped() {
        let mut headers = HeaderMap::new();
        headers.append(header::SET_COOKIE, HeaderValue::from_static("session=mirror"));
        headers.append(header::SET_COOKIE, HeaderValue::from_static("pref=relay"));
        headers.insert(SET_COOKIE2, HeaderValue::from_static("legacy=third-party"));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));

        strip_response_cookies(&mut headers);

        assert!(!headers.contains_key(header::SET_COOKIE));
        assert!(!headers.contains_key(SET_COOKIE2));
        assert_eq!(headers[header::CONTENT_TYPE], "image/jpeg");
    }
}
