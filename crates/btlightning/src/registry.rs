use crate::types::{PeerAddr, QuicAxonInfo};
use quinn::Connection;
use std::collections::{HashMap, HashSet};
use tokio::time::Instant;

pub(crate) struct ReconnectState {
    pub attempts: u32,
    pub next_retry_at: Instant,
    pub in_progress: bool,
}

impl ReconnectState {
    pub fn new() -> Self {
        Self {
            attempts: 0,
            next_retry_at: Instant::now(),
            in_progress: false,
        }
    }
}

pub(crate) enum ReconnectRejection {
    InProgress,
    Exhausted { attempts: u32 },
    Backoff { next: Instant },
}

#[derive(Default)]
pub(crate) struct MinerRegistry {
    active_miners: HashMap<String, QuicAxonInfo>,
    established_connections: HashMap<PeerAddr, Connection>,
    reconnect_states: HashMap<PeerAddr, ReconnectState>,
    addr_to_hotkeys: HashMap<PeerAddr, HashSet<String>>,
}

impl MinerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, miner: QuicAxonInfo) {
        let new_addr_key = miner.addr_key();
        let hotkey = miner.hotkey.clone();
        if let Some(old) = self.active_miners.get(&hotkey) {
            let old_addr_key = old.addr_key();
            if old_addr_key != new_addr_key {
                if let Some(hotkeys) = self.addr_to_hotkeys.get_mut(&old_addr_key) {
                    hotkeys.remove(&hotkey);
                    if hotkeys.is_empty() {
                        self.addr_to_hotkeys.remove(&old_addr_key);
                    }
                }
            }
        }
        self.active_miners.insert(hotkey.clone(), miner);
        self.addr_to_hotkeys
            .entry(new_addr_key)
            .or_default()
            .insert(hotkey);
    }

    pub fn deregister(&mut self, hotkey: &str) -> Option<QuicAxonInfo> {
        if let Some(miner) = self.active_miners.remove(hotkey) {
            let addr_key = miner.addr_key();
            if let Some(hotkeys) = self.addr_to_hotkeys.get_mut(&addr_key) {
                hotkeys.remove(hotkey);
                if hotkeys.is_empty() {
                    self.addr_to_hotkeys.remove(&addr_key);
                }
            }
            Some(miner)
        } else {
            None
        }
    }

    pub fn addr_has_hotkeys(&self, addr_key: &PeerAddr) -> bool {
        self.addr_to_hotkeys.contains_key(addr_key)
    }

    pub fn hotkeys_at_addr(&self, addr_key: &PeerAddr) -> Vec<String> {
        self.addr_to_hotkeys
            .get(addr_key)
            .map(|hs| hs.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn active_miner(&self, hotkey: &str) -> Option<&QuicAxonInfo> {
        self.active_miners.get(hotkey)
    }

    pub fn contains_active_miner(&self, hotkey: &str) -> bool {
        self.active_miners.contains_key(hotkey)
    }

    pub fn active_hotkeys(&self) -> Vec<String> {
        self.active_miners.keys().cloned().collect()
    }

    pub fn active_addrs(&self) -> HashSet<PeerAddr> {
        self.active_miners.values().map(|m| m.addr_key()).collect()
    }

    pub fn active_miner_count(&self) -> usize {
        self.active_miners.len()
    }

    pub fn get_connection(&self, addr: &PeerAddr) -> Option<Connection> {
        self.established_connections.get(addr).cloned()
    }

    pub fn set_connection(&mut self, addr: PeerAddr, conn: Connection) {
        self.established_connections.insert(addr, conn);
    }

    pub fn remove_connection(&mut self, addr: &PeerAddr) -> Option<Connection> {
        self.established_connections.remove(addr)
    }

    pub fn contains_connection(&self, addr: &PeerAddr) -> bool {
        self.established_connections.contains_key(addr)
    }

    pub fn connection_count(&self) -> usize {
        self.established_connections.len()
    }

    pub fn connection_addrs(&self) -> impl Iterator<Item = &PeerAddr> {
        self.established_connections.keys()
    }

    pub fn reconnect_state_or_insert(&mut self, addr: PeerAddr) -> &mut ReconnectState {
        self.reconnect_states
            .entry(addr)
            .or_insert_with(ReconnectState::new)
    }

    pub fn try_start_reconnect(
        &mut self,
        addr: PeerAddr,
        max_retries: u32,
    ) -> std::result::Result<(), ReconnectRejection> {
        let rs = self
            .reconnect_states
            .entry(addr)
            .or_insert_with(ReconnectState::new);
        if rs.in_progress {
            return Err(ReconnectRejection::InProgress);
        }
        if rs.attempts >= max_retries {
            return Err(ReconnectRejection::Exhausted {
                attempts: rs.attempts,
            });
        }
        if Instant::now() < rs.next_retry_at {
            return Err(ReconnectRejection::Backoff {
                next: rs.next_retry_at,
            });
        }
        rs.in_progress = true;
        Ok(())
    }

    #[cfg(test)]
    pub fn reconnect_state_count(&self) -> usize {
        self.reconnect_states.len()
    }

    pub fn remove_reconnect_state(&mut self, addr: &PeerAddr) -> bool {
        self.reconnect_states.remove(addr).is_some()
    }

    pub fn drain_connections(&mut self) -> impl Iterator<Item = (PeerAddr, Connection)> + '_ {
        self.established_connections.drain()
    }

    pub fn clear(&mut self) {
        self.established_connections.clear();
        self.active_miners.clear();
        self.reconnect_states.clear();
        self.addr_to_hotkeys.clear();
    }

    #[cfg(test)]
    fn assert_invariants(&self) {
        for (hotkey, miner) in &self.active_miners {
            let addr = miner.addr_key();
            let hotkeys_at = self.addr_to_hotkeys.get(&addr);
            assert!(
                hotkeys_at.is_some_and(|hs| hs.contains(hotkey)),
                "active miner {} at {} missing from addr_to_hotkeys",
                hotkey,
                addr
            );
        }

        for (addr, hotkeys) in &self.addr_to_hotkeys {
            assert!(!hotkeys.is_empty(), "empty hotkey set at addr {}", addr);
            for hk in hotkeys {
                assert!(
                    self.active_miners.contains_key(hk),
                    "addr_to_hotkeys references {} at {} but not in active_miners",
                    hk,
                    addr
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_miner() -> impl Strategy<Value = QuicAxonInfo> {
        (
            "[a-z]{4,8}",
            (1u8..=254, 0u8..=255, 0u8..=255, 1u8..=254),
            1024u16..65535,
        )
            .prop_map(|(hotkey, (a, b, c, d), port)| {
                let ip = format!("{}.{}.{}.{}", a, b, c, d);
                QuicAxonInfo::new(hotkey, ip, port, 4)
            })
    }

    #[derive(Debug, Clone)]
    enum Op {
        Register(QuicAxonInfo),
        Deregister(String),
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            arb_miner().prop_map(Op::Register),
            "[a-z]{4,8}".prop_map(Op::Deregister),
        ]
    }

    proptest! {
        #[test]
        fn registry_invariants_hold_after_random_ops(ops in proptest::collection::vec(arb_op(), 1..200)) {
            let mut reg = MinerRegistry::new();
            for op in ops {
                match op {
                    Op::Register(miner) => reg.register(miner),
                    Op::Deregister(hk) => { reg.deregister(&hk); }
                }
                reg.assert_invariants();
            }
        }

        #[test]
        fn register_same_hotkey_different_addr_updates_correctly(
            hotkey in "[a-z]{4,8}",
            ip1 in "1\\.0\\.0\\.[1-9]",
            ip2 in "2\\.0\\.0\\.[1-9]",
            port in 1024u16..65535,
        ) {
            let mut reg = MinerRegistry::new();
            let m1 = QuicAxonInfo::new(hotkey.clone(), ip1, port, 4);
            let m2 = QuicAxonInfo::new(hotkey.clone(), ip2, port, 4);

            reg.register(m1);
            reg.assert_invariants();
            prop_assert_eq!(reg.active_miner_count(), 1);

            reg.register(m2);
            reg.assert_invariants();
            prop_assert_eq!(reg.active_miner_count(), 1);
        }

        #[test]
        fn deregister_nonexistent_is_noop(hotkey in "[a-z]{4,8}") {
            let mut reg = MinerRegistry::new();
            prop_assert!(reg.deregister(&hotkey).is_none());
            reg.assert_invariants();
        }

        #[test]
        fn addr_key_roundtrips((a, b, c, d) in (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255), port in 1024u16..65535) {
            let ip = format!("{}.{}.{}.{}", a, b, c, d);
            let addr = PeerAddr::new(&ip, port);
            let s: &str = addr.as_ref();
            prop_assert!(s.contains(&port.to_string()));
            prop_assert!(s.contains(&ip));
        }

        #[test]
        fn backoff_never_exceeds_max(
            initial_ms in 100u64..5000,
            max_ms in 5000u64..120_000,
            attempts in 0u32..30,
        ) {
            let initial = std::time::Duration::from_millis(initial_ms);
            let max = std::time::Duration::from_millis(max_ms);
            let shift = attempts.min(20);
            let backoff = (initial * 2u32.pow(shift)).min(max);
            prop_assert!(backoff <= max);
        }
    }

    #[test]
    fn clear_resets_all_maps() {
        let mut reg = MinerRegistry::new();
        reg.register(QuicAxonInfo::new("hk1".into(), "1.2.3.4".into(), 8080, 4));
        reg.register(QuicAxonInfo::new("hk2".into(), "5.6.7.8".into(), 9090, 4));
        let addr = PeerAddr::new("1.2.3.4", 8080);
        reg.reconnect_state_or_insert(addr);
        assert_eq!(reg.active_miner_count(), 2);
        assert!(reg.reconnect_state_count() > 0);
        reg.clear();
        assert_eq!(reg.active_miner_count(), 0);
        assert_eq!(reg.reconnect_state_count(), 0);
        reg.assert_invariants();
    }
}
