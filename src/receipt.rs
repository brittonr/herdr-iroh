//! Idempotent `agent.prompt` and `pane.send_text` deliveries.
//!
//! A client that times out cannot tell whether herdr typed the text. The same
//! `message_id` within the TTL returns the first receipt and does not type again.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

const MAX_ENTRIES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub delivery: &'static str,
    pub agent_status: Option<String>,
    pub herdr: Value,
    pub payload_hash: String,
}

enum Slot {
    Pending,
    Done { at: Instant, receipt: Receipt },
}

pub struct ReceiptStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, Slot>>,
    wait: Condvar,
}

impl ReceiptStore {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
            wait: Condvar::new(),
        }
    }

    /// `Ok(None)` means this caller should perform the herdr call.
    /// `Ok(Some)` is a duplicate receipt. `Err` is an invalid id.
    pub fn begin(&self, key: &str, payload_hash: &str) -> Result<Option<Receipt>, &'static str> {
        let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        self.evict(&mut guard);
        match guard.get(key) {
            Some(Slot::Done { at, receipt }) if at.elapsed() <= self.ttl => {
                let mut copy = receipt.clone();
                copy.delivery = "duplicate";
                if copy.payload_hash != payload_hash {
                    copy.herdr = serde_json::json!({
                        "note": "message_id was already used for a different payload"
                    });
                }
                return Ok(Some(copy));
            }
            Some(Slot::Pending) => {}
            _ => {
                guard.insert(key.to_string(), Slot::Pending);
                return Ok(None);
            }
        }
        drop(guard);
        let wait_for = Duration::from_secs(30);
        let started = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        loop {
            match guard.get(key) {
                Some(Slot::Done { receipt, .. }) => {
                    let mut copy = receipt.clone();
                    copy.delivery = "duplicate";
                    return Ok(Some(copy));
                }
                Some(Slot::Pending) if started.elapsed() < wait_for => {
                    let (next, timeout) = self
                        .wait
                        .wait_timeout(guard, wait_for.saturating_sub(started.elapsed()))
                        .unwrap_or_else(|err| err.into_inner());
                    guard = next;
                    if timeout.timed_out() && started.elapsed() >= wait_for {
                        return Ok(Some(Receipt {
                            delivery: "duplicate",
                            agent_status: None,
                            herdr: serde_json::json!({"note": "the first delivery is still in flight"}),
                            payload_hash: payload_hash.to_string(),
                        }));
                    }
                }
                _ => return Ok(None),
            }
        }
    }

    pub fn finish(&self, key: &str, receipt: Receipt) {
        let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        guard.insert(
            key.to_string(),
            Slot::Done {
                at: Instant::now(),
                receipt,
            },
        );
        self.evict(&mut guard);
        self.wait.notify_all();
    }

    fn evict(&self, guard: &mut HashMap<String, Slot>) {
        guard.retain(|_, slot| match slot {
            Slot::Pending => true,
            Slot::Done { at, .. } => at.elapsed() <= self.ttl,
        });
        while guard.len() > MAX_ENTRIES {
            let Some(oldest) = guard
                .iter()
                .filter_map(|(key, slot)| match slot {
                    Slot::Done { at, .. } => Some((key.clone(), *at)),
                    Slot::Pending => None,
                })
                .min_by_key(|(_, at)| *at)
                .map(|(key, _)| key)
            else {
                break;
            };
            guard.remove(&oldest);
        }
    }
}

#[must_use]
pub fn payload_hash(text: &str) -> String {
    format!("{:016x}", simple_hash(text.as_bytes()))
}

fn simple_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

pub fn message_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'))
}

pub fn receipt_json(id: &str, message_id: &str, receipt: &Receipt, payload_match: bool) -> Value {
    serde_json::json!({
        "id": id,
        "result": {
            "type": "delivery_receipt",
            "message_id": message_id,
            "delivery": receipt.delivery,
            "agent_status": receipt.agent_status,
            "payload_match": payload_match,
            "herdr": receipt.herdr,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_does_not_require_a_second_send() {
        let store = ReceiptStore::new(Duration::from_secs(60));
        assert!(store.begin("k", "h1").unwrap().is_none());
        store.finish(
            "k",
            Receipt {
                delivery: "delivered",
                agent_status: Some("working".into()),
                herdr: serde_json::json!({"result": {"type": "ok"}}),
                payload_hash: "h1".into(),
            },
        );
        let again = store.begin("k", "h1").unwrap().unwrap();
        assert_eq!(again.delivery, "duplicate");
        assert_eq!(again.agent_status.as_deref(), Some("working"));
        let mismatch = store.begin("k", "other").unwrap().unwrap();
        assert_eq!(mismatch.delivery, "duplicate");
        assert!(mismatch.herdr.get("note").is_some());
    }

    #[test]
    fn message_ids_are_bounded_tokens() {
        assert!(message_id_ok("prompt-1"));
        assert!(message_id_ok("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!message_id_ok(""));
        assert!(!message_id_ok("has space"));
        assert!(!message_id_ok(&"x".repeat(81)));
    }
}
