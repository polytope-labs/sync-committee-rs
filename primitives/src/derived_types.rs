use crate::types;
use codec::{Decode, Encode};
use ethereum_consensus::{bellatrix, primitives::Root};
use ssz_rs::Node;

#[derive(Debug)]
pub enum Error {
	EmptyAggregate,
	EncodingError { provided: usize, expected: usize },
}

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

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<types::LightClientState<SYNC_COMMITTEE_SIZE>>
	for LightClientState
{
	type Error = Error;
	fn try_from(state: types::LightClientState<SYNC_COMMITTEE_SIZE>) -> Result<Self, Self::Error> {
		Ok(LightClientState {
			finalized_header: state.finalized_header.try_into()?,
			latest_finalized_epoch: state.latest_finalized_epoch,
			current_sync_committee: state.current_sync_committee.try_into()?,
			next_sync_committee: state.next_sync_committee.try_into()?,
		})
	}
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct BeaconBlockHeader {
	pub slot: u64,
	pub proposer_index: u64,
	pub parent_root: [u8; 32],
	pub state_root: [u8; 32],
	pub body_root: [u8; 32],
}

impl TryFrom<bellatrix::BeaconBlockHeader> for BeaconBlockHeader {
	type Error = Error;

	fn try_from(beacon_block_header: bellatrix::BeaconBlockHeader) -> Result<Self, Self::Error> {
		Ok(BeaconBlockHeader {
			slot: beacon_block_header.slot,
			proposer_index: beacon_block_header.proposer_index as u64,
			parent_root: beacon_block_header
				.parent_root
				.as_bytes()
				.try_into()
				.expect("Invalid Node bytes"),
			state_root: beacon_block_header
				.state_root
				.as_bytes()
				.try_into()
				.expect("Invalid Node bytes"),
			body_root: beacon_block_header
				.body_root
				.as_bytes()
				.try_into()
				.expect("Invalid Node bytes"),
		})
	}
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct SyncCommittee {
	pub public_keys: Vec<Vec<u8>>,
	pub aggregate_public_key: Vec<u8>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<bellatrix::SyncCommittee<SYNC_COMMITTEE_SIZE>>
	for SyncCommittee
{
	type Error = Error;

	fn try_from(
		sync_committee: bellatrix::SyncCommittee<SYNC_COMMITTEE_SIZE>,
	) -> Result<Self, Self::Error> {
		Ok(SyncCommittee {
			public_keys: sync_committee
				.public_keys
				.iter()
				.map(|public_key| public_key.to_vec())
				.collect(),
			aggregate_public_key: sync_committee.aggregate_public_key.to_vec(),
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
pub struct LightClientUpdate {
	/// the header that the sync committee signed
	pub attested_header: BeaconBlockHeader,
	/// the sync committee has potentially changed, here's an ssz proof for that.
	pub sync_committee_update: Option<SyncCommitteeUpdate>,
	/// the actual header which was finalized by the ethereum attestation protocol.
	pub finalized_header: BeaconBlockHeader,
	/// execution payload of the finalized header
	pub execution_payload: ExecutionPayloadProof,
	/// Finalized header proof
	pub finality_proof: FinalityProof,
	/// signature & participation bits
	pub sync_aggregate: SyncAggregate,
	/// slot at which signature was produced
	pub signature_slot: u64,
	/// ancestors of the finalized block to be verified, may be empty.
	pub ancestor_blocks: Vec<AncestorBlock>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<types::LightClientUpdate<SYNC_COMMITTEE_SIZE>>
	for LightClientUpdate
{
	type Error = Error;
	fn try_from(
		update: types::LightClientUpdate<SYNC_COMMITTEE_SIZE>,
	) -> Result<Self, Self::Error> {
		let sync_committee_update_option: Option<SyncCommitteeUpdate>;

		match update.sync_committee_update {
			Some(sync_committee_update) =>
				sync_committee_update_option = Some(sync_committee_update.try_into()?),

			None => sync_committee_update_option = None,
		}
		Ok(LightClientUpdate {
			attested_header: update.attested_header.try_into()?,
			sync_committee_update: sync_committee_update_option,
			finalized_header: update.finalized_header.try_into()?,
			execution_payload: update.execution_payload.try_into()?,
			finality_proof: update.finality_proof.try_into()?,
			sync_aggregate: update.sync_aggregate.try_into()?,
			signature_slot: update.signature_slot,
			ancestor_blocks: update
				.ancestor_blocks
				.iter()
				.map(|ancestor_block| {
					ancestor_block.clone().try_into().expect("Error converting ancestor block")
				})
				.collect(),
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
pub struct SyncCommitteeUpdate {
	// actual sync committee
	pub next_sync_committee: SyncCommittee,
	// sync committee, ssz merkle proof.
	pub next_sync_committee_branch: Vec<Vec<u8>>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<types::SyncCommitteeUpdate<SYNC_COMMITTEE_SIZE>>
	for SyncCommitteeUpdate
{
	type Error = Error;

	fn try_from(
		sync_committee_update: types::SyncCommitteeUpdate<SYNC_COMMITTEE_SIZE>,
	) -> Result<Self, Self::Error> {
		Ok(SyncCommitteeUpdate {
			next_sync_committee: sync_committee_update.next_sync_committee.try_into()?,
			next_sync_committee_branch: sync_committee_update
				.next_sync_committee_branch
				.iter()
				.map(|hash| hash.to_vec())
				.collect(),
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
pub struct ExecutionPayloadProof {
	/// The state root in the `ExecutionPayload` which represents the commitment to
	/// the ethereum world state in the yellow paper.
	pub state_root: Vec<u8>,
	/// the block number of the execution header.
	pub block_number: u64,
	/// merkle mutli proof for the state_root & block_number in the [`ExecutionPayload`].
	pub multi_proof: Vec<Vec<u8>>,
	/// merkle proof for the `ExecutionPayload` in the [`BeaconBlockBody`].
	pub execution_payload_branch: Vec<Vec<u8>>,
	/// timestamp
	pub timestamp: u64,
}

impl TryFrom<types::ExecutionPayloadProof> for ExecutionPayloadProof {
	type Error = Error;
	fn try_from(
		execution_payload_proof: types::ExecutionPayloadProof,
	) -> Result<Self, Self::Error> {
		Ok(ExecutionPayloadProof {
			state_root: execution_payload_proof.state_root.to_vec(),
			block_number: execution_payload_proof.block_number,
			multi_proof: execution_payload_proof
				.multi_proof
				.iter()
				.map(|proof| proof.to_vec())
				.collect(),
			execution_payload_branch: execution_payload_proof
				.execution_payload_branch
				.iter()
				.map(|branch| branch.to_vec())
				.collect(),
			timestamp: execution_payload_proof.timestamp,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
pub struct FinalityProof {
	/// The latest  finalized epoch
	pub epoch: u64,
	/// Finalized header proof
	pub finality_branch: Vec<Vec<u8>>,
}

impl TryFrom<types::FinalityProof> for FinalityProof {
	type Error = Error;
	fn try_from(finality_proof: types::FinalityProof) -> Result<Self, Self::Error> {
		Ok(FinalityProof {
			epoch: finality_proof.epoch,
			finality_branch: finality_proof
				.finality_branch
				.iter()
				.map(|branch| branch.to_vec())
				.collect(),
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
pub struct SyncAggregate {
	pub sync_committee_bits: Vec<u8>,
	pub sync_committee_signature: Vec<u8>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<bellatrix::SyncAggregate<SYNC_COMMITTEE_SIZE>>
	for SyncAggregate
{
	type Error = Error;
	fn try_from(
		sync_aggregate: bellatrix::SyncAggregate<SYNC_COMMITTEE_SIZE>,
	) -> Result<Self, Self::Error> {
		Ok(SyncAggregate {
			sync_committee_bits: sync_aggregate.sync_committee_bits.clone().to_bitvec().into_vec(),
			sync_committee_signature: sync_aggregate.sync_committee_signature.clone().to_vec(),
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AncestorBlock {
	/// The actual beacon chain header
	pub header: BeaconBlockHeader,
	/// Associated execution header proofs
	pub execution_payload: ExecutionPayloadProof,
	/// Ancestry proofs of the beacon chain header.
	pub ancestry_proof: AncestryProof,
}

impl TryFrom<types::AncestorBlock> for AncestorBlock {
	type Error = Error;
	fn try_from(ancestor_block: types::AncestorBlock) -> Result<Self, Self::Error> {
		Ok(AncestorBlock {
			header: ancestor_block.header.try_into()?,
			execution_payload: ancestor_block.execution_payload.try_into()?,
			ancestry_proof: ancestor_block.ancestry_proof.try_into()?,
		})
	}
}

/// Holds the neccessary proofs required to verify a header in the `block_roots` field
/// either in [`BeaconState`] or [`HistoricalBatch`].
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockRootsProof {
	/// Generalized index of the header in the `block_roots` list.
	pub block_header_index: u64,
	/// The proof for the header, needed to reconstruct `hash_tree_root(state.block_roots)`
	pub block_header_branch: Vec<Vec<u8>>,
}

impl TryFrom<types::BlockRootsProof> for BlockRootsProof {
	type Error = Error;
	fn try_from(beacon_block_header: types::BlockRootsProof) -> Result<Self, Self::Error> {
		Ok(BlockRootsProof {
			block_header_index: beacon_block_header.block_header_index,
			block_header_branch: beacon_block_header
				.block_header_branch
				.iter()
				.map(|hash| hash.to_vec())
				.collect(),
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum AncestryProof {
	/// This variant defines the proof data for a beacon chain header in the `state.block_roots`
	BlockRoots {
		/// Proof for the header in `state.block_roots`
		block_roots_proof: BlockRootsProof,
		/// The proof for the reconstructed `hash_tree_root(state.block_roots)` in [`BeaconState`]
		block_roots_branch: Vec<Vec<u8>>,
	},
	/// This variant defines the neccessary proofs for a beacon chain header in the
	/// `state.historical_roots`.
	HistoricalRoots {
		/// Proof for the header in `historical_batch.block_roots`
		block_roots_proof: BlockRootsProof,
		/// The proof for the `historical_batch.block_roots`, needed to reconstruct
		/// `hash_tree_root(historical_batch)`
		historical_batch_proof: Vec<Vec<u8>>,
		/// The proof for the `hash_tree_root(historical_batch)` in `state.historical_roots`
		historical_roots_proof: Vec<Vec<u8>>,
		/// The generalized index for the historical_batch in `state.historical_roots`.
		historical_roots_index: u64,
		/// The proof for the reconstructed `hash_tree_root(state.historical_roots)` in
		/// [`BeaconState`]
		historical_roots_branch: Vec<Vec<u8>>,
	},
}

impl TryFrom<types::AncestryProof> for AncestryProof {
	type Error = Error;
	fn try_from(ancestry_proof: types::AncestryProof) -> Result<Self, Self::Error> {
		Ok(match ancestry_proof {
			types::AncestryProof::BlockRoots { block_roots_proof, block_roots_branch } =>
				AncestryProof::BlockRoots {
					block_roots_proof: block_roots_proof.try_into()?,
					block_roots_branch: block_roots_branch
						.iter()
						.map(|hash| hash.to_vec())
						.collect(),
				},
			types::AncestryProof::HistoricalRoots {
				block_roots_proof,
				historical_batch_proof,
				historical_roots_proof,
				historical_roots_index,
				historical_roots_branch,
			} => AncestryProof::HistoricalRoots {
				block_roots_proof: block_roots_proof.try_into()?,
				historical_batch_proof: historical_batch_proof
					.iter()
					.map(|hash| hash.to_vec())
					.collect(),
				historical_roots_proof: historical_roots_proof
					.iter()
					.map(|hash| hash.to_vec())
					.collect(),
				historical_roots_index,
				historical_roots_branch: historical_roots_branch
					.iter()
					.map(|hash| hash.to_vec())
					.collect(),
			},
		})
	}
}
