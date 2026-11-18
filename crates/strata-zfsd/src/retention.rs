//! Which snapshots of a source survive: the `keep` newest, plus the newest snapshot of each
//! of the last `dailies` UTC days counting today. Times are the server's own `creation`
//! property, so a client can't backdate anything. The newest snapshot always survives.

use crate::config::Retention;

const DAY: i64 = 86_400;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub creation: i64,
    pub createtxg: u64,
}

/// Returns the names to destroy, oldest first.
pub fn plan(snaps: &[Candidate], policy: Retention, now: i64) -> Vec<String> {
    let mut v: Vec<&Candidate> = snaps.iter().collect();
    v.sort_by_key(|c| c.createtxg);
    let n = v.len();
    let keep = (policy.keep.max(1) as usize).min(n);
    let mut kept = vec![false; n];
    for k in kept.iter_mut().skip(n - keep) {
        *k = true;
    }
    let today = now.div_euclid(DAY);
    let first_day = today - policy.dailies as i64 + 1;
    let mut seen_day = None;
    for i in (0..n).rev() {
        let day = v[i].creation.div_euclid(DAY);
        if policy.dailies > 0 && day >= first_day && day <= today && seen_day.is_none_or(|d| day < d) {
            kept[i] = true;
            seen_day = Some(day);
        }
    }
    v.iter().zip(kept).filter(|(_, k)| !k).map(|(c, _)| c.name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snaps(times: &[i64]) -> Vec<Candidate> {
        times
            .iter()
            .enumerate()
            .map(|(i, &t)| Candidate { name: format!("s{i}"), creation: t, createtxg: i as u64 + 1 })
            .collect()
    }

    #[test]
    fn keeps_newest_n() {
        let s = snaps(&[1, 2, 3, 4, 5]);
        assert_eq!(plan(&s, Retention { keep: 3, dailies: 0 }, 10), vec!["s0", "s1"]);
        assert!(plan(&s, Retention { keep: 30, dailies: 0 }, 10).is_empty());
        assert_eq!(plan(&s, Retention { keep: 0, dailies: 0 }, 10).len(), 4, "keep is at least 1");
    }

    #[test]
    fn flood_cannot_roll_over_daily_anchors() {
        let now = 100 * DAY + 3600;
        let mut times: Vec<i64> = (0..20).map(|d| (80 + d) * DAY + 7200).collect();
        times.extend((0..30).map(|i| now - 3000 + i));
        let s = snaps(&times);
        let doomed = plan(&s, Retention { keep: 30, dailies: 14 }, now);
        let survivors: Vec<&Candidate> = s.iter().filter(|c| !doomed.contains(&c.name)).collect();
        assert_eq!(survivors.len(), 30 + 13);
        for d in 87..100 {
            assert!(survivors.iter().any(|c| c.creation.div_euclid(DAY) == d), "anchor for day {d}");
        }
        assert!(survivors.iter().all(|c| c.creation.div_euclid(DAY) >= 87));
    }

    #[test]
    fn newest_of_each_day() {
        let s = snaps(&[DAY + 10, DAY + 20, 2 * DAY + 5, 2 * DAY + 6, 3 * DAY]);
        let doomed = plan(&s, Retention { keep: 1, dailies: 3 }, 3 * DAY + 100);
        assert_eq!(doomed, vec!["s0", "s2"]);
    }
}
