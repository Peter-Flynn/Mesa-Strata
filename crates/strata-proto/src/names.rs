//! Client and source names: `[a-z0-9][a-z0-9_-]*`. A name never starts with an underscore,
//! so no client can collide with the server's own `<pool>/strata/_server` dataset.

pub const MAX_NAME: usize = 64;

pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_NAME
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

pub fn check_name(what: &str, name: &str) -> Result<(), String> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(format!("invalid {what} name {name:?}: must match [a-z0-9][a-z0-9_-]* (max {MAX_NAME})"))
    }
}

/// Snapshot names the server creates: `strata-<UTC yyyymmddThhmmssZ>-g<gen>`.
pub fn server_snapshot_name(unix_secs: i64, generation: u64) -> String {
    format!("strata-{}-g{generation}", utc_compact(unix_secs))
}

pub fn parse_server_snapshot_name(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("strata-")?;
    let (stamp, generation) = rest.split_once("-g")?;
    if stamp.len() != 16 || !stamp.ends_with('Z') || stamp.as_bytes()[8] != b'T' {
        return None;
    }
    if !stamp.bytes().enumerate().all(|(i, c)| i == 8 || i == 15 || c.is_ascii_digit()) {
        return None;
    }
    if generation.is_empty() || !generation.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    generation.parse().ok()
}

pub fn utc_compact(unix_secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix_secs);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

pub fn utc_readable(unix_secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix_secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}Z")
}

// Howard Hinnant's days-to-civil algorithm (proleptic Gregorian, UTC).
fn civil(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let sod = unix_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, (sod / 3600) as u32, ((sod % 3600) / 60) as u32, (sod % 60) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("nas2"));
        assert!(valid_name("0vm_disk-1"));
        assert!(!valid_name("_server"));
        assert!(!valid_name("-x"));
        assert!(!valid_name("Home"));
        assert!(!valid_name("a/b"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"a".repeat(65)));
    }

    #[test]
    fn snapshot_names() {
        // 2026-11-17 12:34:56 UTC
        let t = 1_794_918_896;
        assert_eq!(utc_compact(t), "20261117T123456Z");
        let n = server_snapshot_name(t, 42);
        assert_eq!(n, "strata-20261117T123456Z-g42");
        assert_eq!(parse_server_snapshot_name(&n), Some(42));
        assert_eq!(parse_server_snapshot_name("strata-20261117T123456Z-g"), None);
        assert_eq!(parse_server_snapshot_name("autosnap_2026"), None);
        assert_eq!(utc_compact(0), "19700101T000000Z");
        assert_eq!(utc_compact(951_782_400), "20000229T000000Z");
    }
}
