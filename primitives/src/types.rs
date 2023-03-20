use crate::derived_types;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use ethereum_consensus::{
	bellatrix::{BeaconBlockHeader, SyncAggregate, SyncCommittee},
	crypto::PublicKey,
	domains::DomainType,
	primitives::{BlsSignature, Hash32, Slot},
	ssz::ByteVector,
};
use ssz_rs::{Bitvector, Deserialize, Node, Vector};

#[derive(Debug)]
pub enum Error {
	InvalidRoot,
	InvalidPublicKey,
	InvalidProof,
	InvalidBitVec,
	ErrorConvertingAncestorBlock,
}

impl Display for Error {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		match self {
			Error::InvalidRoot => write!(f, "Invalid root",),
			Error::InvalidPublicKey => write!(f, "Invalid public key",),
			Error::InvalidProof => write!(f, "Invalid proof",),
			Error::InvalidBitVec => write!(f, "Invalid bit vec",),
			Error::ErrorConvertingAncestorBlock => write!(f, "Error deriving ancestor block",),
		}
	}
}

pub const DOMAIN_SYNC_COMMITTEE: DomainType = DomainType::SyncCommittee;
pub const FINALIZED_ROOT_INDEX: u64 = 52;
pub const EXECUTION_PAYLOAD_STATE_ROOT_INDEX: u64 = 18;
pub const EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX: u64 = 22;
pub const EXECUTION_PAYLOAD_INDEX: u64 = 56;
pub const NEXT_SYNC_COMMITTEE_INDEX: u64 = 55;
pub const BLOCK_ROOTS_INDEX: u64 = 37;
pub const HISTORICAL_ROOTS_INDEX: u64 = 39;
pub const HISTORICAL_BATCH_BLOCK_ROOTS_INDEX: u64 = 2;
pub const EXECUTION_PAYLOAD_TIMESTAMP_INDEX: u64 = 25;
#[cfg(not(feature = "testing"))]
pub const GENESIS_VALIDATORS_ROOT: [u8; 32] =
	hex_literal::hex!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
#[cfg(feature = "testing")]
pub const GENESIS_VALIDATORS_ROOT: [u8; 32] =
	hex_literal::hex!("6034f557b4560fc549ac0e2c63269deb07bfac7bf2bbd0b8b7d4d321240bffd9");

/// This holds the relevant data required to prove the state root in the execution payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionPayloadProof {
	/// The state root in the `ExecutionPayload` which represents the commitment to
	/// the ethereum world state in the yellow paper.
	pub state_root: Hash32,
	/// the block number of the execution header.
	pub block_number: u64,
	/// merkle mutli proof for the state_root & block_number in the [`ExecutionPayload`].
	pub multi_proof: Vec<Hash32>,
	/// merkle proof for the `ExecutionPayload` in the [`BeaconBlockBody`].
	pub execution_payload_branch: Vec<Hash32>,
	/// timestamp
	pub timestamp: u64,
}

impl TryFrom<derived_types::ExecutionPayloadProof> for ExecutionPayloadProof {
	type Error = Error;
	fn try_from(
		derived_execution_payload_proof: derived_types::ExecutionPayloadProof,
	) -> Result<Self, Self::Error> {
		let multi_proof = derived_execution_payload_proof
			.multi_proof
			.iter()
			.map(|proof| Hash32::try_from(proof.as_ref()).map_err(|_| Error::InvalidProof).unwrap())
			.collect();

		let execution_payload_branch = derived_execution_payload_proof
			.execution_payload_branch
			.iter()
			.map(|proof| Hash32::try_from(proof.as_ref()).map_err(|_| Error::InvalidProof).unwrap())
			.collect();

		Ok(ExecutionPayloadProof {
			state_root: Hash32::try_from(derived_execution_payload_proof.state_root.as_slice())
				.map_err(|_| Error::InvalidRoot)?,
			block_number: derived_execution_payload_proof.block_number,
			multi_proof,
			execution_payload_branch,
			timestamp: derived_execution_payload_proof.timestamp,
		})
	}
}

/// Holds the neccessary proofs required to verify a header in the `block_roots` field
/// either in [`BeaconState`] or [`HistoricalBatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRootsProof {
	/// Generalized index of the header in the `block_roots` list.
	pub block_header_index: u64,
	/// The proof for the header, needed to reconstruct `hash_tree_root(state.block_roots)`
	pub block_header_branch: Vec<Hash32>,
}

impl TryFrom<derived_types::BlockRootsProof> for BlockRootsProof {
	type Error = Error;
	fn try_from(
		derived_beacon_block_header: derived_types::BlockRootsProof,
	) -> Result<Self, Self::Error> {
		let branch = derived_beacon_block_header
			.block_header_branch
			.iter()
			.map(|proof| Hash32::try_from(proof.as_ref()).map_err(|_| Error::InvalidProof).unwrap())
			.collect();

		Ok(BlockRootsProof {
			block_header_index: derived_beacon_block_header.block_header_index,
			block_header_branch: branch,
		})
	}
}

/// The block header ancestry proof, this is an enum because the header may either exist in
/// `state.block_roots` or `state.historical_roots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AncestryProof {
	/// This variant defines the proof data for a beacon chain header in the `state.block_roots`
	BlockRoots {
		/// Proof for the header in `state.block_roots`
		block_roots_proof: BlockRootsProof,
		/// The proof for the reconstructed `hash_tree_root(state.block_roots)` in [`BeaconState`]
		block_roots_branch: Vec<Hash32>,
	},
	/// This variant defines the neccessary proofs for a beacon chain header in the
	/// `state.historical_roots`.
	HistoricalRoots {
		/// Proof for the header in `historical_batch.block_roots`
		block_roots_proof: BlockRootsProof,
		/// The proof for the `historical_batch.block_roots`, needed to reconstruct
		/// `hash_tree_root(historical_batch)`
		historical_batch_proof: Vec<Hash32>,
		/// The proof for the `hash_tree_root(historical_batch)` in `state.historical_roots`
		historical_roots_proof: Vec<Hash32>,
		/// The generalized index for the historical_batch in `state.historical_roots`.
		historical_roots_index: u64,
		/// The proof for the reconstructed `hash_tree_root(state.historical_roots)` in
		/// [`BeaconState`]
		historical_roots_branch: Vec<Hash32>,
	},
}

impl TryFrom<derived_types::AncestryProof> for AncestryProof {
	type Error = Error;
	fn try_from(ancestry_proof: derived_types::AncestryProof) -> Result<Self, Self::Error> {
		Ok(match ancestry_proof {
			derived_types::AncestryProof::BlockRoots { block_roots_proof, block_roots_branch } =>
				AncestryProof::BlockRoots {
					block_roots_proof: block_roots_proof.try_into()?,
					block_roots_branch: block_roots_branch
						.iter()
						.map(|proof| {
							Hash32::try_from(proof.as_ref())
								.map_err(|_| Error::InvalidProof)
								.unwrap()
						})
						.collect(),
				},
			derived_types::AncestryProof::HistoricalRoots {
				block_roots_proof,
				historical_batch_proof,
				historical_roots_proof,
				historical_roots_index,
				historical_roots_branch,
			} => AncestryProof::HistoricalRoots {
				block_roots_proof: block_roots_proof.try_into()?,
				historical_batch_proof: historical_batch_proof
					.iter()
					.map(|proof| {
						Hash32::try_from(proof.as_ref()).map_err(|_| Error::InvalidProof).unwrap()
					})
					.collect(),
				historical_roots_proof: historical_roots_proof
					.iter()
					.map(|proof| {
						Hash32::try_from(proof.as_ref()).map_err(|_| Error::InvalidProof).unwrap()
					})
					.collect(),
				historical_roots_index,
				historical_roots_branch: historical_roots_branch
					.iter()
					.map(|proof| {
						Hash32::try_from(proof.as_ref()).map_err(|_| Error::InvalidProof).unwrap()
					})
					.collect(),
			},
		})
	}
}

/// This defines the neccesary data needed to prove ancestor blocks, relative to the finalized
/// header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorBlock {
	/// The actual beacon chain header
	pub header: BeaconBlockHeader,
	/// Associated execution header proofs
	pub execution_payload: ExecutionPayloadProof,
	/// Ancestry proofs of the beacon chain header.
	pub ancestry_proof: AncestryProof,
}

impl TryFrom<derived_types::AncestorBlock> for AncestorBlock {
	type Error = Error;
	fn try_from(derived_ancestor_block: derived_types::AncestorBlock) -> Result<Self, Self::Error> {
		let beacon_block_header = construct_beacon_header(derived_ancestor_block.header)?;
		Ok(AncestorBlock {
			header: beacon_block_header,
			execution_payload: derived_ancestor_block.execution_payload.try_into()?,
			ancestry_proof: derived_ancestor_block.ancestry_proof.try_into()?,
		})
	}
}

/// Holds the latest sync committee as well as an ssz proof for it's existence
/// in a finalized header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncCommitteeUpdate<const SYNC_COMMITTEE_SIZE: usize> {
	// actual sync committee
	pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
	// sync committee, ssz merkle proof.
	pub next_sync_committee_branch: Vec<Hash32>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<derived_types::SyncCommitteeUpdate>
	for SyncCommitteeUpdate<SYNC_COMMITTEE_SIZE>
{
	type Error = Error;

	fn try_from(
		sync_committee_update: derived_types::SyncCommitteeUpdate,
	) -> Result<Self, Self::Error> {
		let next_sync_committee =
			construct_sync_committee(sync_committee_update.next_sync_committee)?;
		Ok(SyncCommitteeUpdate {
			next_sync_committee,
			next_sync_committee_branch: sync_committee_update
				.next_sync_committee_branch
				.iter()
				.map(|proof| {
					Hash32::try_from(proof.as_ref()).map_err(|_| Error::InvalidProof).unwrap()
				})
				.collect(),
		})
	}
}

/// Minimum state required by the light client to validate new sync committee attestations
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LightClientState<const SYNC_COMMITTEE_SIZE: usize> {
	/// The latest recorded finalized header
	pub finalized_header: BeaconBlockHeader,
	/// Latest finalized epoch
	pub latest_finalized_epoch: u64,
	// Sync committees corresponding to the finalized header
	pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
	pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<derived_types::LightClientState>
	for LightClientState<SYNC_COMMITTEE_SIZE>
{
	type Error = Error;
	fn try_from(state: derived_types::LightClientState) -> Result<Self, Self::Error> {
		construct_light_client_state(state)
	}
}

/// Finalized header proof
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FinalityProof {
	/// The latest  finalized epoch
	pub epoch: u64,
	/// Finalized header proof
	pub finality_branch: Vec<Hash32>,
}

impl TryFrom<derived_types::FinalityProof> for FinalityProof {
	type Error = Error;
	fn try_from(derived_finality_proof: derived_types::FinalityProof) -> Result<Self, Self::Error> {
		Ok(FinalityProof {
			epoch: derived_finality_proof.epoch,
			finality_branch: derived_finality_proof
				.finality_branch
				.iter()
				.map(|proof| {
					Hash32::try_from(proof.as_ref()).map_err(|_| Error::InvalidProof).unwrap()
				})
				.collect(),
		})
	}
}

/// Data required to advance the state of the light client.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LightClientUpdate<const SYNC_COMMITTEE_SIZE: usize> {
	/// the header that the sync committee signed
	pub attested_header: BeaconBlockHeader,
	/// the sync committee has potentially changed, here's an ssz proof for that.
	pub sync_committee_update: Option<SyncCommitteeUpdate<SYNC_COMMITTEE_SIZE>>,
	/// the actual header which was finalized by the ethereum attestation protocol.
	pub finalized_header: BeaconBlockHeader,
	/// execution payload of the finalized header
	pub execution_payload: ExecutionPayloadProof,
	/// Finalized header proof
	pub finality_proof: FinalityProof,
	/// signature & participation bits
	pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
	/// slot at which signature was produced
	pub signature_slot: Slot,
	/// ancestors of the finalized block to be verified, may be empty.
	pub ancestor_blocks: Vec<AncestorBlock>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<derived_types::LightClientUpdate>
	for LightClientUpdate<SYNC_COMMITTEE_SIZE>
{
	type Error = Error;
	fn try_from(derived_update: derived_types::LightClientUpdate) -> Result<Self, Self::Error> {
		construct_light_client_update(derived_update)
	}
}

fn construct_beacon_header(
	derived_header: derived_types::BeaconBlockHeader,
) -> Result<BeaconBlockHeader, Error> {
	let finalized_header = BeaconBlockHeader {
		slot: derived_header.slot,
		proposer_index: derived_header.proposer_index as usize,
		parent_root: Node::from_bytes(
			derived_header.parent_root.as_ref().try_into().map_err(|_| Error::InvalidRoot)?,
		),
		state_root: Node::from_bytes(
			derived_header.state_root.as_ref().try_into().map_err(|_| Error::InvalidRoot)?,
		),
		body_root: Node::from_bytes(
			derived_header.body_root.as_ref().try_into().map_err(|_| Error::InvalidRoot)?,
		),
	};

	Ok(finalized_header)
}

fn construct_sync_committee<const SYNC_COMMITTEE_SIZE: usize>(
	derived_sync_committee: derived_types::SyncCommittee,
) -> Result<SyncCommittee<SYNC_COMMITTEE_SIZE>, Error> {
	let public_keys_vector: Vec<PublicKey> = derived_sync_committee
		.public_keys
		.iter()
		.map(|public_key| {
			PublicKey::try_from(public_key.as_slice())
				.map_err(|_| Error::InvalidPublicKey)
				.unwrap()
		})
		.collect();
	let sync_committee = SyncCommittee {
		public_keys: Vector::try_from(public_keys_vector).unwrap(),
		aggregate_public_key: PublicKey::try_from(
			derived_sync_committee.aggregate_public_key.as_slice(),
		)
		.map_err(|_| Error::InvalidPublicKey)?,
	};

	Ok(sync_committee)
}

fn construct_sync_aggregate<const SYNC_COMMITTEE_SIZE: usize>(
	derived_sync_aggregate: derived_types::SyncAggregate,
) -> Result<SyncAggregate<SYNC_COMMITTEE_SIZE>, Error> {
	let derived_sync_committee_bits = derived_sync_aggregate.sync_committee_bits;
	let bit_vector = Bitvector::<SYNC_COMMITTEE_SIZE>::deserialize(&derived_sync_committee_bits)
		.map_err(|_| Error::InvalidBitVec)?;

	let sync_aggregate = SyncAggregate {
		sync_committee_bits: bit_vector,
		sync_committee_signature: BlsSignature::try_from(
			derived_sync_aggregate.sync_committee_signature.as_ref(),
		)
		.map_err(|_| Error::InvalidPublicKey)?,
	};

	Ok(sync_aggregate)
}

fn construct_light_client_state<const SYNC_COMMITTEE_SIZE: usize>(
	state: derived_types::LightClientState,
) -> Result<LightClientState<SYNC_COMMITTEE_SIZE>, Error> {
	let finalized_header = construct_beacon_header(state.finalized_header)?;

	let current_sync_committee = construct_sync_committee(state.current_sync_committee.clone())?;
	let next_sync_committee = construct_sync_committee(state.next_sync_committee)?;

	Ok(LightClientState {
		finalized_header,
		latest_finalized_epoch: state.latest_finalized_epoch,
		current_sync_committee,
		next_sync_committee,
	})
}

fn construct_light_client_update<const SYNC_COMMITTEE_SIZE: usize>(
	derived_update: derived_types::LightClientUpdate,
) -> Result<LightClientUpdate<SYNC_COMMITTEE_SIZE>, Error> {
	let sync_committee_update_option: Option<SyncCommitteeUpdate<SYNC_COMMITTEE_SIZE>>;

	match derived_update.sync_committee_update {
		Some(sync_committee_update) =>
			sync_committee_update_option = Some(sync_committee_update.try_into()?),
		None => sync_committee_update_option = None,
	}
	Ok(LightClientUpdate {
		attested_header: construct_beacon_header(derived_update.attested_header)?,
		sync_committee_update: sync_committee_update_option,
		finalized_header: construct_beacon_header(derived_update.finalized_header)?,
		execution_payload: derived_update.execution_payload.try_into()?,
		finality_proof: derived_update.finality_proof.try_into()?,
		sync_aggregate: construct_sync_aggregate(derived_update.sync_aggregate)?,
		signature_slot: derived_update.signature_slot,
		ancestor_blocks: derived_update
			.ancestor_blocks
			.iter()
			.map(|ancestor_block| {
				ancestor_block
					.clone()
					.try_into()
					.map_err(|_| Error::ErrorConvertingAncestorBlock)
					.unwrap()
			})
			.collect(),
	})
}
