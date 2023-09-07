#[warn(unused_imports)]
#[warn(unused_variables)]
mod responses;
mod routes;
#[cfg(test)]
mod test;

use anyhow::anyhow;
use bls_on_arkworks::{point_to_pubkey, types::G1ProjectivePoint};
use reqwest::Client;
use sync_committee_primitives::consensus_types::{
	BeaconBlock, BeaconBlockHeader, BeaconState, SyncCommittee, Validator,
};

use crate::{
	responses::{
		finality_checkpoint_response::FinalityCheckpoint,
		sync_committee_response::NodeSyncCommittee,
	},
	routes::*,
};
use primitive_types::H256;
use ssz_rs::{List, Merkleized, Node, Vector};
use sync_committee_primitives::{
	constants::{
		BlsPublicKey, ValidatorIndex, BLOCK_ROOTS_INDEX, BYTES_PER_LOGS_BLOOM,
		EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR, ETH1_DATA_VOTES_BOUND,
		EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX, EXECUTION_PAYLOAD_INDEX,
		EXECUTION_PAYLOAD_STATE_ROOT_INDEX, EXECUTION_PAYLOAD_TIMESTAMP_INDEX,
		FINALIZED_ROOT_INDEX, HISTORICAL_ROOTS_LIMIT, MAX_ATTESTATIONS, MAX_ATTESTER_SLASHINGS,
		MAX_BYTES_PER_TRANSACTION, MAX_DEPOSITS, MAX_EXTRA_DATA_BYTES, MAX_PROPOSER_SLASHINGS,
		MAX_TRANSACTIONS_PER_PAYLOAD, MAX_VALIDATORS_PER_COMMITTEE, MAX_VOLUNTARY_EXITS,
		NEXT_SYNC_COMMITTEE_INDEX, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE,
		VALIDATOR_REGISTRY_LIMIT,
	},
	types::{AncestryProof, BlockRootsProof, ExecutionPayloadProof},
	util::compute_epoch_at_slot,
};
use sync_committee_verifier::signature_verification::pubkey_to_projective;

pub type BeaconStateType = BeaconState<
	SLOTS_PER_HISTORICAL_ROOT,
	HISTORICAL_ROOTS_LIMIT,
	ETH1_DATA_VOTES_BOUND,
	VALIDATOR_REGISTRY_LIMIT,
	EPOCHS_PER_HISTORICAL_VECTOR,
	EPOCHS_PER_SLASHINGS_VECTOR,
	MAX_VALIDATORS_PER_COMMITTEE,
	SYNC_COMMITTEE_SIZE,
	BYTES_PER_LOGS_BLOOM,
	MAX_EXTRA_DATA_BYTES,
	MAX_BYTES_PER_TRANSACTION,
	MAX_TRANSACTIONS_PER_PAYLOAD,
>;

#[derive(Clone)]
pub struct SyncCommitteeProver {
	pub node_url: String,
	pub client: Client,
}

impl SyncCommitteeProver {
	pub fn new(node_url: String) -> Self {
		let client = Client::new();

		SyncCommitteeProver { node_url, client }
	}

	pub async fn fetch_finalized_checkpoint(&self) -> Result<FinalityCheckpoint, anyhow::Error> {
		let full_url = self.generate_route(&finality_checkpoints("head"));
		let response = self.client.get(full_url).send().await?;

		let response_data =
			response.json::<responses::finality_checkpoint_response::Response>().await?;
		Ok(response_data.data)
	}

	pub async fn fetch_header(&self, block_id: &str) -> Result<BeaconBlockHeader, anyhow::Error> {
		let path = header_route(block_id);
		let full_url = self.generate_route(&path);
		let response = self.client.get(full_url).send().await?;

		let response_data =
			response.json::<responses::beacon_block_header_response::Response>().await?;

		let beacon_block_header = response_data.data.header.message;

		Ok(beacon_block_header)
	}

	pub async fn fetch_block(
		&self,
		block_id: &str,
	) -> Result<
		BeaconBlock<
			MAX_PROPOSER_SLASHINGS,
			MAX_VALIDATORS_PER_COMMITTEE,
			MAX_ATTESTER_SLASHINGS,
			MAX_ATTESTATIONS,
			MAX_DEPOSITS,
			MAX_VOLUNTARY_EXITS,
			SYNC_COMMITTEE_SIZE,
			BYTES_PER_LOGS_BLOOM,
			MAX_EXTRA_DATA_BYTES,
			MAX_BYTES_PER_TRANSACTION,
			MAX_TRANSACTIONS_PER_PAYLOAD,
		>,
		anyhow::Error,
	> {
		let path = block_route(block_id);
		let full_url = self.generate_route(&path);

		let response = self.client.get(full_url).send().await?;

		let response_data = response.json::<responses::beacon_block_response::Response>().await?;

		let beacon_block = response_data.data.message;

		Ok(beacon_block)
	}

	pub async fn fetch_sync_committee(
		&self,
		state_id: &str,
	) -> Result<NodeSyncCommittee, anyhow::Error> {
		let path = sync_committee_route(state_id);
		let full_url = self.generate_route(&path);

		let response = self.client.get(full_url).send().await?;

		let response_data = response.json::<responses::sync_committee_response::Response>().await?;

		let sync_committee = response_data.data;

		Ok(sync_committee)
	}

	pub async fn fetch_validator(
		&self,
		state_id: &str,
		validator_index: &str,
	) -> Result<Validator, anyhow::Error> {
		let path = validator_route(state_id, validator_index);
		let full_url = self.generate_route(&path);

		let response = self.client.get(full_url).send().await?;

		let response_data = response.json::<responses::validator_response::Response>().await?;

		let validator = response_data.data.validator;

		Ok(validator)
	}

	pub async fn fetch_beacon_state(
		&self,
		state_id: &str,
	) -> Result<BeaconStateType, anyhow::Error> {
		let path = beacon_state_route(state_id);
		let full_url = self.generate_route(&path);

		let response = self.client.get(full_url).send().await?;

		let response_data = response.json::<responses::beacon_state_response::Response>().await?;

		let beacon_state = response_data.data;

		Ok(beacon_state)
	}

	pub async fn fetch_processed_sync_committee(
		&self,
		state_id: &str,
	) -> Result<SyncCommittee<SYNC_COMMITTEE_SIZE>, anyhow::Error> {
		// fetches sync committee from Node
		let node_sync_committee = self.fetch_sync_committee(state_id).await?;

		let mut validators: List<Validator, VALIDATOR_REGISTRY_LIMIT> = Default::default();
		for validator_index in node_sync_committee.validators.iter() {
			// fetches validator based on validator index
			let validator = self.fetch_validator(state_id, validator_index).await?;
			validators.push(validator);
		}

		let public_keys_vector = node_sync_committee
			.validators
			.into_iter()
			.map(|i| {
				let validator_index: ValidatorIndex = i.parse()?;
				Ok(validators[validator_index].public_key.clone())
			})
			.collect::<Result<Vec<_>, anyhow::Error>>()?;

		let aggregate_public_key = eth_aggregate_public_keys(&public_keys_vector)?;

		let sync_committee = SyncCommittee::<SYNC_COMMITTEE_SIZE> {
			public_keys: Vector::<BlsPublicKey, SYNC_COMMITTEE_SIZE>::try_from(public_keys_vector)
				.map_err(|e| anyhow!("{:?}", e))?,
			aggregate_public_key,
		};

		Ok(sync_committee)
	}

	fn generate_route(&self, path: &str) -> String {
		format!("{}{}", self.node_url.clone(), path)
	}
}

pub fn get_attested_epoch(finalized_epoch: u64) -> u64 {
	finalized_epoch + 2
}

pub fn prove_execution_payload(
	beacon_state: &mut BeaconStateType,
) -> anyhow::Result<ExecutionPayloadProof> {
	let indices = [
		EXECUTION_PAYLOAD_STATE_ROOT_INDEX as usize,
		EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX as usize,
		EXECUTION_PAYLOAD_TIMESTAMP_INDEX as usize,
	];
	// generate multi proofs
	let multi_proof = ssz_rs::generate_proof(
		&mut beacon_state.latest_execution_payload_header,
		indices.as_slice(),
	)?;

	Ok(ExecutionPayloadProof {
		state_root: H256::from_slice(
			beacon_state.latest_execution_payload_header.state_root.as_slice(),
		),
		block_number: beacon_state.latest_execution_payload_header.block_number,
		timestamp: beacon_state.latest_execution_payload_header.timestamp,
		multi_proof,
		execution_payload_branch: ssz_rs::generate_proof(
			beacon_state,
			&[EXECUTION_PAYLOAD_INDEX as usize],
		)?,
	})
}

pub fn prove_sync_committee_update(state: &mut BeaconStateType) -> anyhow::Result<Vec<Node>> {
	let proof = ssz_rs::generate_proof(state, &[NEXT_SYNC_COMMITTEE_INDEX as usize])?;
	Ok(proof)
}

pub fn prove_finalized_header(state: &mut BeaconStateType) -> anyhow::Result<Vec<Node>> {
	let indices = [FINALIZED_ROOT_INDEX as usize];
	let proof = ssz_rs::generate_proof(state, indices.as_slice())?;

	Ok(proof)
}

pub fn prove_block_roots_proof(
	state: &mut BeaconStateType,
	mut header: BeaconBlockHeader,
) -> anyhow::Result<AncestryProof> {
	// Check if block root should still be part of the block roots vector on the beacon state
	let epoch_for_header = compute_epoch_at_slot(header.slot) as usize;
	let epoch_for_state = compute_epoch_at_slot(state.slot) as usize;

	if epoch_for_state.saturating_sub(epoch_for_header) >=
		SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH as usize
	{
		// todo:  Historical root proofs
		unimplemented!()
	} else {
		// Get index of block root in the block roots
		let block_root = header.hash_tree_root().expect("hash tree root should be valid");
		let block_index = state
			.block_roots
			.as_ref()
			.into_iter()
			.position(|root| root == &block_root)
			.expect("Block root should exist in block_roots");

		let proof = ssz_rs::generate_proof(&mut state.block_roots, &[block_index])?;

		let block_roots_proof =
			BlockRootsProof { block_header_index: block_index as u64, block_header_branch: proof };

		let block_roots_branch = ssz_rs::generate_proof(state, &[BLOCK_ROOTS_INDEX as usize])?;
		Ok(AncestryProof::BlockRoots { block_roots_proof, block_roots_branch })
	}
}

pub fn eth_aggregate_public_keys(points: &[BlsPublicKey]) -> anyhow::Result<BlsPublicKey> {
	let points = points
		.iter()
		.map(|point| pubkey_to_projective(point))
		.collect::<Result<Vec<_>, _>>()?;
	let aggregate = points
		.into_iter()
		.fold(G1ProjectivePoint::default(), |acc, g1_point| acc + g1_point);
	let public_key = point_to_pubkey(aggregate.into());

	let bls_public_key =
		BlsPublicKey::try_from(public_key.as_slice()).map_err(|e| anyhow!("{:?}", e))?;

	Ok(bls_public_key)
}
