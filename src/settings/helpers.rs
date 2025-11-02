use anyhow::{Result, bail};
use cookie::SameSite;
use std::env;

pub fn must(k: &str) -> Result<String> {
    match env::var(k) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => bail!("Missing required env var: {k}"),
    }
}
pub fn get(k: &str) -> Option<String> {
    // Help to get var
    env::var(k).ok()
}
pub fn parse_bool(v: &Option<String>, default_: bool) -> bool {
    match v.as_deref() {
        Some("1") | Some("true") | Some("TRUE") | Some("True") => true,
        Some("0") | Some("false") | Some("FALSE") | Some("False") => false,
        _ => default_,
    }
}
pub fn parse_i64(v: &Option<String>, default_: i64) -> Result<i64> {
    match v {
        Some(s) if !s.is_empty() => Ok(s.parse()?),
        _ => Ok(default_),
    }
}

pub fn parse_samesite(s: &str) -> Result<SameSite> {
    Ok(match s {
        "Lax" | "lax" => SameSite::Lax,
        "Strict" | "strict" => SameSite::Strict,
        "None" | "none" => SameSite::None,
        other => anyhow::bail!("AUTH_COOKIE_SAMESITE must be Lax|Strict|None, got {other}"),
    })
}
