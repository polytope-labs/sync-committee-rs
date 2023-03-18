use ssz_rs::Node;
use codec::{Encode, Decode};
use ethereum_consensus::bellatrix;
use ethereum_consensus::primitives::Root;
use crate::types;

/// Minimum state required by the light client to validate new sync committee attestations
#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct LightClientState {
    /// The latest recorded finalized header
    pub finalized_header: BeaconBlockHeader,
    /// Latest finalized epoch
    pub latest_finalized_epoch: u64,
    // Sync committees corresponding to the finalized header
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct SyncCommittee {
    pub public_keys: Vec<Vec<u8>>,
    pub aggregate_public_key: Vec<u8>,
}


impl<const SYNC_COMMITTEE_SIZE: usize> From<types::LightClientState<SYNC_COMMITTEE_SIZE>> for LightClientState {
    fn from(state: types::LightClientState<SYNC_COMMITTEE_SIZE>) -> Self {
        LightClientState {
            finalized_header: state.finalized_header.into(),
            latest_finalized_epoch: state.latest_finalized_epoch,
            current_sync_committee: state.current_sync_committee.into(),
            next_sync_committee: state.next_sync_committee.into(),
        }
    }
}

impl From<bellatrix::BeaconBlockHeader> for BeaconBlockHeader {
    fn from(beacon_block_header: bellatrix::BeaconBlockHeader) -> Self {
        BeaconBlockHeader {
            slot: beacon_block_header.slot,
            proposer_index: beacon_block_header.proposer_index as u64,
            parent_root: beacon_block_header.parent_root.as_bytes().try_into().unwrap(),
            state_root: beacon_block_header.state_root.as_bytes().try_into().unwrap(),
            body_root: beacon_block_header.body_root.as_bytes().try_into().unwrap()
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<bellatrix::SyncCommittee<SYNC_COMMITTEE_SIZE>> for SyncCommittee {
    fn from(sync_committee: bellatrix::SyncCommittee<SYNC_COMMITTEE_SIZE>) -> Self {
        SyncCommittee {
            public_keys: sync_committee.public_keys.iter().map(|public_key| public_key.to_vec()).collect(),
            aggregate_public_key: sync_committee.aggregate_public_key.to_vec()
        }
    }
}

