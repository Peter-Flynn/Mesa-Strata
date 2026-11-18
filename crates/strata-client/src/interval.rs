//! The backup interval a source reports to the server for staleness checks, worked out
//! from its systemd `OnCalendar` expression with `systemd-analyze calendar`.

use std::process::Command;

/// Seconds from a line such as `Next elapse: Tue 2026-11-17 14:15:00 UTC`.
/// systemd-analyze prints each elapse in the local zone (`Next elapse:`, `Iteration #2:`)
/// and repeats it on an `(in UTC):` line only when the local zone isn't UTC, so exactly one
/// line per elapse ends in `UTC` either way.
fn parse_utc_line(line: &str) -> Option<i64> {
    let (_, rest) = line.split_once(": ")?;
    let (date, time) = match rest.split_whitespace().collect::<Vec<_>>().as_slice() {
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
    let times: Vec<i64> = out.lines().filter_map(parse_utc_line).collect();
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
        // Output of systemd 255 `systemd-analyze calendar --iterations=2 '*:0/15'` with the
        // local zone set to UTC, then to Europe/Berlin.
        let utc = "  Original form: *:0/15
Normalized form: *-*-* *:00/15:00
    Next elapse: Wed 2026-11-18 22:15:00 UTC
       From now: 9min left
   Iteration #2: Wed 2026-11-18 22:30:00 UTC
       From now: 24min left
";
        let berlin = "  Original form: *:0/15
Normalized form: *-*-* *:00/15:00
    Next elapse: Wed 2026-11-18 23:15:00 CET
       (in UTC): Wed 2026-11-18 22:15:00 UTC
       From now: 9min left
   Iteration #2: Wed 2026-11-18 23:30:00 CET
       (in UTC): Wed 2026-11-18 22:30:00 UTC
       From now: 24min left
";
        assert_eq!(parse_calendar_output(utc), Some(900));
        assert_eq!(parse_calendar_output(berlin), Some(900));
        assert_eq!(parse_utc_line("(in UTC): Thu 1970-01-01 00:00:10 UTC"), Some(10));
        assert_eq!(parse_utc_line("Next elapse: Tue 2026-11-17 12:34:56 UTC"), Some(1_794_918_896));
    }
}
