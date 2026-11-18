//! The backup interval a source reports to the server for staleness checks, worked out
//! from its systemd `OnCalendar` expression with `systemd-analyze calendar`.

use std::process::Command;

/// Seconds from a `(in UTC): Tue 2026-11-17 14:15:00 UTC` line.
fn parse_in_utc(line: &str) -> Option<i64> {
    let rest = line.trim().strip_prefix("(in UTC):")?.trim();
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let (date, time) = match parts.as_slice() {
        [_, d, t, "UTC"] => (*d, *t),
        _ => return None,
    };
    let d: Vec<i64> = date.split('-').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let t: Vec<i64> = time.split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    if d.len() != 3 || t.len() != 3 {
        return None;
    }
    let (y, m, day) = (d[0] - i64::from(d[1] <= 2), d[1], d[2]);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + t[0] * 3600 + t[1] * 60 + t[2])
}

pub fn parse_calendar_output(out: &str) -> Option<u64> {
    let times: Vec<i64> = out.lines().filter_map(parse_in_utc).collect();
    match times.as_slice() {
        [a, b, ..] if b > a => Some((b - a) as u64),
        _ => None,
    }
}

pub fn interval_secs(spec: &str) -> Option<u64> {
    let out = Command::new("systemd-analyze").args(["calendar", "--iterations=2", spec]).output().ok()?;
    out.status.success().then(|| parse_calendar_output(&String::from_utf8_lossy(&out.stdout)))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemd_analyze() {
        let out = "  Original form: *:0/15\nNormalized form: *-*-* *:00/15:00\n    Next elapse: Tue 2026-11-17 14:15:00 UTC\n       (in UTC): Tue 2026-11-17 14:15:00 UTC\n       From now: 4min left\n       Iter. #2: Tue 2026-11-17 14:30:00 UTC\n       (in UTC): Tue 2026-11-17 14:30:00 UTC\n";
        assert_eq!(parse_calendar_output(out), Some(900));
        assert_eq!(parse_in_utc("(in UTC): Thu 1970-01-01 00:00:10 UTC"), Some(10));
        assert_eq!(parse_in_utc("(in UTC): Tue 2026-11-17 12:34:56 UTC"), Some(1_794_918_896));
    }
}
