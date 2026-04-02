use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;

use crate::proxy::handshake::{AuthProbeState, AuthProbeSaturationState};
use crate::proxy::middle_relay::{DesyncDedupRotationState, RelayIdleCandidateRegistry};

pub(crate) struct HandshakeSharedState {
    pub(crate) auth_probe: DashMap<IpAddr, AuthProbeState>,
    pub(crate) auth_probe_saturation: Mutex<Option<AuthProbeSaturationState>>,
    pub(crate) auth_probe_eviction_hasher: RandomState,
    pub(crate) invalid_secret_warned: Mutex<HashSet<(String, String)>>,
    pub(crate) unknown_sni_warn_next_allowed: Mutex<Option<Instant>>,
}

pub(crate) struct MiddleRelaySharedState {
    pub(crate) desync_dedup: DashMap<u64, Instant>,
    pub(crate) desync_dedup_previous: DashMap<u64, Instant>,
    pub(crate) desync_hasher: RandomState,
    pub(crate) desync_full_cache_last_emit_at: Mutex<Option<Instant>>,
    pub(crate) desync_dedup_rotation_state: Mutex<DesyncDedupRotationState>,
    pub(crate) relay_idle_registry: Mutex<RelayIdleCandidateRegistry>,
    pub(crate) relay_idle_mark_seq: AtomicU64,
}

pub(crate) struct ProxySharedState {
    pub(crate) handshake: HandshakeSharedState,
    pub(crate) middle_relay: MiddleRelaySharedState,
}

impl ProxySharedState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            handshake: HandshakeSharedState {
                auth_probe: DashMap::new(),
                auth_probe_saturation: Mutex::new(None),
                auth_probe_eviction_hasher: RandomState::new(),
                invalid_secret_warned: Mutex::new(HashSet::new()),
                unknown_sni_warn_next_allowed: Mutex::new(None),
            },
            middle_relay: MiddleRelaySharedState {
                desync_dedup: DashMap::new(),
                desync_dedup_previous: DashMap::new(),
                desync_hasher: RandomState::new(),
                desync_full_cache_last_emit_at: Mutex::new(None),
                desync_dedup_rotation_state: Mutex::new(DesyncDedupRotationState::default()),
                relay_idle_registry: Mutex::new(RelayIdleCandidateRegistry::default()),
                relay_idle_mark_seq: AtomicU64::new(0),
            },
        })
    }
}
