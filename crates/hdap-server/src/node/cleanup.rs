//! Periodic housekeeping for the node (v2/Teleios).
//!
//! Expired factor-1 challenges and sessions are purged from memory and, when
//! a database is attached, flushed to disk. Without this worker both maps
//! grew forever and any anonymous caller could inflate them (AME-24).

use std::sync::Arc;
use std::time::Duration;

use crate::node::auth::prune_expired;
use crate::node::Node;

/// Background loop. Intended to be spawned once from `main`.
pub fn run_forever(node: Arc<Node>) {
    let interval = node.cfg.cleanup_interval_secs;
    if interval == 0 {
        return;
    }
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        let now = node.now();
        let removed = {
            let mut st = node.lock_state();
            prune_expired(&mut st, now)
        };
        if removed > 0 {
            if let Err(e) = node.persist() {
                crate::hlog!(warn, "cleanup", "persist after prune failed: {e}");
            }
            crate::hlog!(info, "cleanup", "removed {removed} expired records");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::{ProklesisRecord, Session};

    #[test]
    fn expired_records_are_removed_with_a_fixed_clock() {
        let (node, _now) = Node::with_clock_and_now(Config::default(), 100);
        {
            let mut st = node.lock_state();
            st.proklesis.insert(
                "c".into(),
                ProklesisRecord {
                    user_id: "u".into(),
                    ts: 1,
                    expires_at: 50,
                },
            );
            st.sessions.insert(
                hdap_core::session_storage_key("t"),
                Session {
                    user_id: "u".into(),
                    exp: 90,
                },
            );
        }
        let removed = {
            let mut st = node.lock_state();
            prune_expired(&mut st, node.now())
        };
        assert_eq!(removed, 2);
        assert!(node.lock_state().proklesis.is_empty());
        assert!(node.lock_state().sessions.is_empty());
    }
}
