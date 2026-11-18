//! Ángelma — the server's Message of the Day.
//!
//! The template uses `HDAP{[tag]}` placeholders. Tags are resolved at request
//! time from the node's live state; unknown tags are left verbatim so an
//! operator immediately sees a typo. `HDAP{{` renders a literal `HDAP{`.
//!
//! Available tags:
//! `uptime`, `uptime_secs`, `users`, `files`, `sessions`, `node`, `version`,
//! `protocol`, `started_utc`, `now_utc`, `date_utc`, `peers`, `tls`,
//! `rate_limit`. Aliases: `user_count`, `uptime_s`, `server`, `codename`.

use hdap_core::time::unix_secs_utc;

/// Live facts needed to render an Ángelma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MotdContext {
    pub server_id: String,
    pub version: &'static str,
    pub protocol_version: u64,
    pub protocol_codename: &'static str,
    pub started_at: u64,
    pub now: u64,
    pub users: usize,
    pub files: usize,
    pub sessions: usize,
    pub peers: usize,
    pub tls: bool,
    pub rate_limit_per_sec: u32,
}

impl Default for MotdContext {
    fn default() -> Self {
        let now = unix_secs_utc();
        Self {
            server_id: String::new(),
            version: env!("CARGO_PKG_VERSION"),
            protocol_version: hdap_core::PROTOCOL_VERSION,
            protocol_codename: hdap_core::PROTOCOL_CODENAME,
            started_at: now,
            now,
            users: 0,
            files: 0,
            sessions: 0,
            peers: 0,
            tls: false,
            rate_limit_per_sec: 0,
        }
    }
}

impl MotdContext {
    /// Resolve one tag. Returns `None` for unknown tags.
    pub fn tag(&self, tag: &str) -> Option<String> {
        Some(match tag {
            "uptime_secs" | "uptime_s" => self.now.saturating_sub(self.started_at).to_string(),
            "uptime" => human_duration(self.now.saturating_sub(self.started_at)),
            "users" | "user_count" => self.users.to_string(),
            "files" => self.files.to_string(),
            "sessions" => self.sessions.to_string(),
            "node" | "server" => self.server_id.clone(),
            "version" => self.version.to_string(),
            "protocol" => format!("v{} ({})", self.protocol_version, self.protocol_codename),
            "codename" => self.protocol_codename.to_string(),
            "started_utc" => self.started_at.to_string(),
            "now_utc" => self.now.to_string(),
            "date_utc" => format_unix_utc(self.now),
            "peers" => self.peers.to_string(),
            "tls" => if self.tls { "on" } else { "off" }.to_string(),
            "rate_limit" => self.rate_limit_per_sec.to_string(),
            _ => return None,
        })
    }
}

/// Render `template` against `ctx`.
pub fn render(template: &str, ctx: &MotdContext) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if template[i..].starts_with("HDAP{{") {
            out.push_str("HDAP{");
            i += 6;
            continue;
        }
        if template[i..].starts_with("HDAP{") {
            if let Some(end) = template[i + 5..].find('}') {
                let inner = &template[i + 5..i + 5 + end];
                // Canonical form is `HDAP{[tag]}`; also accept bare `HDAP{tag}`.
                let tag = inner
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .unwrap_or(inner);
                match ctx.tag(tag) {
                    Some(value) => out.push_str(&value),
                    None => {
                        // Keep the original so the operator can spot the typo.
                        out.push_str(&template[i..i + 6 + end]);
                    }
                }
                i += 6 + end;
                continue;
            }
        }
        let ch = template[i..].chars().next().expect("non-empty slice");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Compact human-readable duration, e.g. `2d 03h 07m`.
pub fn human_duration(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours:02}h {mins:02}m")
    } else if hours > 0 {
        format!("{hours}h {mins:02}m")
    } else {
        format!("{mins}m")
    }
}

/// `YYYY-MM-DD HH:MM:SS UTC` from Unix seconds, with no local-timezone
/// dependency. Algorithm by Howard Hinnant, adapted for unsigned days.
pub fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_live_tags() {
        let ctx = MotdContext {
            server_id: "pyle1".into(),
            started_at: 1_700_000_000,
            now: 1_700_000_124,
            users: 42,
            files: 7,
            ..Default::default()
        };
        let out = render(
            "HDAP{node} · up HDAP{[uptime]} · HDAP{[users]} users · HDAP{[files]} files · HDAP{[now_utc]}",
            &ctx,
        );
        assert!(out.contains("pyle1"));
        assert!(out.contains("2m"));
        assert!(out.contains("42 users"));
        assert!(out.contains("7 files"));
        assert!(out.contains('1'));
    }

    #[test]
    fn unknown_tags_and_escapes() {
        let ctx = MotdContext::default();
        assert_eq!(render("HDAP{[nope]}", &ctx), "HDAP{[nope]}");
        assert_eq!(render("HDAP{{ rest", &ctx), "HDAP{ rest");
    }

    #[test]
    fn utc_formatting_is_stable() {
        assert_eq!(format_unix_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_unix_utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(human_duration(0), "0m");
        assert_eq!(human_duration(90), "1m");
        assert_eq!(human_duration(7_265), "2h 01m");
    }
}
