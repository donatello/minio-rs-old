use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT,
};
use std::collections::{HashMap, HashSet};
use time::Tm;

use crate::minio;

fn aws_format_time(t: &Tm) -> String {
    t.strftime("%Y%m%dT%H%M%SZ").unwrap().to_string()
}

fn mk_scope(t: &Tm, r: &minio::Region) -> String {
    let scope_time = t.strftime("%Y%m%d").unwrap().to_string();
    format!("{}/{}/s3/aws4_request", scope_time, r)
}

// Returns list of SORTED headers that will be signed. TODO: verify
// that input headermap contains only ASCII valued headers
fn get_headers_to_sign(h: &HeaderMap) -> Vec<(String, String)> {
    let mut ignored_hdrs: HashSet<HeaderName> = HashSet::new();
    ignored_hdrs.insert(AUTHORIZATION);
    ignored_hdrs.insert(CONTENT_LENGTH);
    ignored_hdrs.insert(CONTENT_TYPE);
    ignored_hdrs.insert(USER_AGENT);
    let mut res: Vec<(String, String)> = h
        .iter()
        .map(|(x, y)| (x.clone(), y.clone()))
        .filter(|(x, y)| !ignored_hdrs.contains(x))
        .map(|(x, y)| {
            (
                x.as_str().to_string(),
                y.to_str()
                    .expect("Unexpected non-ASCII header value!")
                    .to_string(),
            )
        })
        .collect();
    res.sort();
    res
}

fn uri_encode(c: char, encode_slash: bool) -> String {
    if c == '/' {
        if encode_slash {
            "%2F".to_string()
        } else {
            "/".to_string()
        }
    } else if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '~' {
        c.to_string()
    } else {
        let mut b = [0; 8];
        let cs = c.encode_utf8(&mut b).as_bytes();
        cs.iter().map(|x| format!("%{:X}", x)).collect()
    }
}

fn uri_encode_str(s: &str, encode_slash: bool) -> String {
    s.chars().map(|x| uri_encode(x, encode_slash)).collect()
}

fn get_canonical_querystr(q: &HashMap<String, Option<String>>) -> String {
    let mut hs: Vec<(String, Option<String>)> = q.clone().drain().collect();
    hs.sort();
    let vs: Vec<String> = hs
        .drain(..)
        .map(|(x, y)| match y {
            Some(s) => uri_encode_str(&x, true) + "=" + &uri_encode_str(&s, true),
            None => uri_encode_str(&x, true),
        })
        .collect();
    vs[..].join("&")
}

fn mk_path(r: &minio::S3Req) -> String {
    let mut res: String = String::from("");
    if let Some(s) = &r.bucket {
        res.push_str(&s);
        if let Some(o) = &r.object {
            let s1 = format!("/{}", o);
            res.push_str(&s1);
        }
    };
    res
}

fn get_canonical_request(r: &mut minio::S3Req) -> String {
    let v = aws_format_time(&r.ts);
    r.headers
        .insert("x-amz-date", HeaderValue::from_str(&v[..]).unwrap());

    let hs = get_headers_to_sign(&r.headers);
    let path_str = mk_path(r);
    let canonical_qstr = get_canonical_querystr(&r.query);
    let canonical_hdrs: String = hs.iter().map(|(x, y)| format!("{}:{}\n", x, y)).collect();
    let signed_hdrs = hs
        .iter()
        .map(|(x, _)| x.clone())
        .collect::<Vec<String>>()
        .join(";");
    // FIXME: using only unsigned payload for now - need to add
    // hashing of payload.
    let payload_hash_str = String::from("UNSIGNED-PAYLOAD");
    let res = vec![
        r.method.to_string(),
        uri_encode_str(&path_str, false),
        canonical_qstr,
        canonical_hdrs,
        signed_hdrs,
        payload_hash_str,
    ];
    res.join("\n")
}
