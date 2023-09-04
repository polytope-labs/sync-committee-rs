#![cfg_attr(not(feature = "std"), no_std)]
#[warn(unused_imports)]
#[warn(unused_variables)]
extern crate alloc;
extern crate core;

pub mod error;
mod signature_verification;

use crate::{
	error::Error,
	signature_verification::{verify_aggregate_signature, BLS_COMPRESSED_KEY_SIZE},
};
use alloc::vec::Vec;
use ethereum_consensus::{
	bellatrix::{compute_domain, mainnet::SYNC_COMMITTEE_SIZE, Checkpoint},
	primitives::Root,
	signing::compute_signing_root,
	state_transition::Context,
};
use ssz_rs::{
	calculate_merkle_root, calculate_multi_merkle_root, prelude::is_valid_merkle_branch,
	GeneralizedIndex, Merkleized, Node,
};
use sync_committee_primitives::{
	types::{
		AncestryProof, BLOCK_ROOTS_INDEX, BLOCK_ROOTS_INDEX_LOG2, DOMAIN_SYNC_COMMITTEE,
		EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX, EXECUTION_PAYLOAD_INDEX,
		EXECUTION_PAYLOAD_INDEX_LOG2, EXECUTION_PAYLOAD_STATE_ROOT_INDEX,
		EXECUTION_PAYLOAD_TIMESTAMP_INDEX, FINALIZED_ROOT_INDEX, FINALIZED_ROOT_INDEX_LOG2,
		GENESIS_VALIDATORS_ROOT, HISTORICAL_BATCH_BLOCK_ROOTS_INDEX, HISTORICAL_ROOTS_INDEX,
		HISTORICAL_ROOTS_INDEX_LOG2, NEXT_SYNC_COMMITTEE_INDEX, NEXT_SYNC_COMMITTEE_INDEX_LOG2,
	},
	util::{compute_epoch_at_slot, compute_fork_version, compute_sync_committee_period_at_slot},
};

pub type LightClientState = sync_committee_primitives::types::LightClientState<SYNC_COMMITTEE_SIZE>;
pub type LightClientUpdate =
	sync_committee_primitives::types::LightClientUpdate<SYNC_COMMITTEE_SIZE>;

/// This function simply verifies a sync committee's attestation & it's finalized counterpart.
pub fn verify_sync_committee_attestation(
	trusted_state: LightClientState,
	update: LightClientUpdate,
) -> Result<LightClientState, Error> {
	if update.finality_proof.finality_branch.len() != FINALIZED_ROOT_INDEX_LOG2 as usize &&
		update.sync_committee_update.is_some() &&
		update.sync_committee_update.as_ref().unwrap().next_sync_committee_branch.len() !=
			NEXT_SYNC_COMMITTEE_INDEX_LOG2 as usize
	{
		Err(Error::InvalidUpdate)?
	}

	// Verify sync committee has super majority participants
	let sync_committee_bits = update.sync_aggregate.sync_committee_bits;
	let sync_aggregate_participants: u64 =
		sync_committee_bits.iter().as_bitslice().count_ones() as u64;

	if sync_aggregate_participants < (2 * sync_committee_bits.len() as u64) / 3 {
		Err(Error::SyncCommitteeParticipantsTooLow)?
	}

	// Verify update does not skip a sync committee period
	let is_valid_update = update.signature_slot > update.attested_header.slot &&
		update.attested_header.slot >= update.finalized_header.slot;
	if !is_valid_update {
		Err(Error::InvalidUpdate)?
	}

	let state_period = compute_sync_committee_period_at_slot(trusted_state.finalized_header.slot);
	let update_signature_period = compute_sync_committee_period_at_slot(update.signature_slot);
	if !(state_period..=state_period + 1).contains(&update_signature_period) {
		Err(Error::InvalidUpdate)?
	}

	// Verify update is relevant
	let update_attested_period = compute_sync_committee_period_at_slot(update.attested_header.slot);
	let update_has_next_sync_committee =
		update.sync_committee_update.is_some() && update_attested_period == state_period;

	if !(update.attested_header.slot > trusted_state.finalized_header.slot ||
		update_has_next_sync_committee)
	{
		Err(Error::InvalidUpdate)?
	}

	// Verify sync committee aggregate signature
	let sync_committee = if update_signature_period == state_period {
		trusted_state.current_sync_committee.clone()
	} else {
		trusted_state.next_sync_committee.clone()
	};

	let sync_committee_pubkeys = sync_committee.public_keys;

	let non_participant_pubkeys = sync_committee_bits
		.iter()
		.zip(sync_committee_pubkeys.iter())
		.filter_map(|(bit, key)| {
			if !bit.as_ref() {
				let mut pub_key = [0u8; BLS_COMPRESSED_KEY_SIZE];
				pub_key.copy_from_slice(key.as_slice());
				Some(pub_key)
			} else {
				None
			}
		})
		.collect::<Vec<_>>();

	let fork_version = compute_fork_version(compute_epoch_at_slot(update.signature_slot));

	let context = Context::for_mainnet();
	let domain = compute_domain(
		DOMAIN_SYNC_COMMITTEE,
		Some(fork_version),
		Some(Root::from_bytes(GENESIS_VALIDATORS_ROOT.try_into().map_err(|_| Error::InvalidRoot)?)),
		&context,
	)
	.map_err(|_| Error::InvalidUpdate)?;

	let signing_root = compute_signing_root(&mut update.attested_header.clone(), domain)
		.map_err(|_| Error::InvalidRoot)?
		.as_bytes()
		.to_vec();
	let aggregate_pub_key = {
		let mut pub_key = [0u8; BLS_COMPRESSED_KEY_SIZE];
		pub_key
			.copy_from_slice(trusted_state.current_sync_committee.aggregate_public_key.as_slice());
		pub_key
	};

	verify_aggregate_signature(
		&aggregate_pub_key,
		&non_participant_pubkeys,
		signing_root,
		&update.sync_aggregate.sync_committee_signature.to_vec(),
	)
	.map_err(|_| Error::SignatureVerification)?;

	// Verify that the `finality_branch` confirms `finalized_header`
	// to match the finalized checkpoint root saved in the state of `attested_header`.
	// Note that the genesis finalized checkpoint root is represented as a zero hash.
	let mut finalized_checkpoint = Checkpoint {
		epoch: update.finality_proof.epoch,
		root: update
			.finalized_header
			.clone()
			.hash_tree_root()
			.map_err(|_| Error::InvalidRoot)?,
	};

	let branch = update
		.finality_proof
		.finality_branch
		.iter()
		.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
		.collect::<Vec<_>>();

	let is_merkle_branch_valid = is_valid_merkle_branch(
		&finalized_checkpoint.hash_tree_root().map_err(|_| Error::InvalidRoot)?,
		branch.iter(),
		FINALIZED_ROOT_INDEX_LOG2 as usize,
		FINALIZED_ROOT_INDEX as usize,
		&update.attested_header.state_root,
	);

	if !is_merkle_branch_valid {
		Err(Error::InvalidMerkleBranch)?;
	}

	// verify the associated execution header of the finalized beacon header.
	let mut execution_payload = update.execution_payload;
	let multi_proof_vec = execution_payload.multi_proof;
	let multi_proof_nodes = multi_proof_vec
		.iter()
		.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
		.collect::<Vec<_>>();
	let execution_payload_root = calculate_multi_merkle_root(
		&[
			Node::from_bytes(
				execution_payload
					.state_root
					.as_ref()
					.try_into()
					.map_err(|_| Error::InvalidRoot)?,
			),
			execution_payload
				.block_number
				.hash_tree_root()
				.map_err(|_| Error::InvalidRoot)?,
			execution_payload.timestamp.hash_tree_root().map_err(|_| Error::InvalidRoot)?,
		],
		&multi_proof_nodes,
		&[
			GeneralizedIndex(EXECUTION_PAYLOAD_STATE_ROOT_INDEX as usize),
			GeneralizedIndex(EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX as usize),
			GeneralizedIndex(EXECUTION_PAYLOAD_TIMESTAMP_INDEX as usize),
		],
	);

	let execution_payload_branch = execution_payload
		.execution_payload_branch
		.iter()
		.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
		.collect::<Vec<_>>();

	let is_merkle_branch_valid = is_valid_merkle_branch(
		&execution_payload_root,
		execution_payload_branch.iter(),
		EXECUTION_PAYLOAD_INDEX_LOG2 as usize,
		EXECUTION_PAYLOAD_INDEX as usize,
		&update.finalized_header.state_root,
	);

	if !is_merkle_branch_valid {
		Err(Error::InvalidMerkleBranch)?;
	}

	if let Some(mut sync_committee_update) = update.sync_committee_update.clone() {
		if update_attested_period == state_period &&
			sync_committee_update.next_sync_committee !=
				trusted_state.next_sync_committee.clone()
		{
			Err(Error::InvalidUpdate)?
		}

		let next_sync_committee_branch = sync_committee_update
			.next_sync_committee_branch
			.iter()
			.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
			.collect::<Vec<_>>();
		let is_merkle_branch_valid = is_valid_merkle_branch(
			&sync_committee_update
				.next_sync_committee
				.hash_tree_root()
				.map_err(|_| Error::MerkleizationError)?,
			next_sync_committee_branch.iter(),
			NEXT_SYNC_COMMITTEE_INDEX_LOG2 as usize,
			NEXT_SYNC_COMMITTEE_INDEX as usize,
			&update.attested_header.state_root,
		);

		if !is_merkle_branch_valid {
			Err(Error::InvalidMerkleBranch)?;
		}
	}

	// verify the ancestry proofs
	for mut ancestor in update.ancestor_blocks {
		match ancestor.ancestry_proof {
			AncestryProof::BlockRoots { block_roots_proof, block_roots_branch } => {
				let block_header_branch = block_roots_proof
					.block_header_branch
					.iter()
					.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
					.collect::<Vec<_>>();

				let block_roots_root = calculate_merkle_root(
					&ancestor.header.hash_tree_root().map_err(|_| Error::MerkleizationError)?,
					&*block_header_branch,
					&GeneralizedIndex(block_roots_proof.block_header_index as usize),
				);

				let block_roots_branch_node = block_roots_branch
					.iter()
					.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
					.collect::<Vec<_>>();

				let is_merkle_branch_valid = is_valid_merkle_branch(
					&block_roots_root,
					block_roots_branch_node.iter(),
					BLOCK_ROOTS_INDEX_LOG2 as usize,
					BLOCK_ROOTS_INDEX as usize,
					&update.finalized_header.state_root,
				);
				if !is_merkle_branch_valid {
					Err(Error::InvalidMerkleBranch)?;
				}
			},
			AncestryProof::HistoricalRoots {
				block_roots_proof,
				historical_batch_proof,
				historical_roots_proof,
				historical_roots_index,
				historical_roots_branch,
			} => {
				let block_header_branch = block_roots_proof
					.block_header_branch
					.iter()
					.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
					.collect::<Vec<_>>();
				let block_roots_root = calculate_merkle_root(
					&ancestor
						.header
						.clone()
						.hash_tree_root()
						.map_err(|_| Error::MerkleizationError)?,
					&block_header_branch,
					&GeneralizedIndex(block_roots_proof.block_header_index as usize),
				);

				let historical_batch_proof_nodes = historical_batch_proof
					.iter()
					.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
					.collect::<Vec<_>>();
				let historical_batch_root = calculate_merkle_root(
					&block_roots_root,
					&historical_batch_proof_nodes,
					&GeneralizedIndex(HISTORICAL_BATCH_BLOCK_ROOTS_INDEX as usize),
				);

				let historical_roots_proof_nodes = historical_roots_proof
					.iter()
					.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
					.collect::<Vec<_>>();
				let historical_roots_root = calculate_merkle_root(
					&historical_batch_root,
					&historical_roots_proof_nodes,
					&GeneralizedIndex(historical_roots_index as usize),
				);

				let historical_roots_branch_nodes = historical_roots_branch
					.iter()
					.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
					.collect::<Vec<_>>();
				let is_merkle_branch_valid = is_valid_merkle_branch(
					&historical_roots_root,
					historical_roots_branch_nodes.iter(),
					HISTORICAL_ROOTS_INDEX_LOG2 as usize,
					HISTORICAL_ROOTS_INDEX as usize,
					&Node::from_bytes(
						update
							.finalized_header
							.state_root
							.as_ref()
							.try_into()
							.map_err(|_| Error::InvalidRoot)?,
					),
				);

				if !is_merkle_branch_valid {
					Err(Error::InvalidMerkleBranch)?;
				}
			},
		};

		// verify the associated execution paylaod header.
		let execution_payload = ancestor.execution_payload;
		let multi_proof = execution_payload
			.multi_proof
			.iter()
			.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
			.collect::<Vec<_>>();
		let execution_payload_root = calculate_multi_merkle_root(
			&[
				Node::from_bytes(
					execution_payload
						.state_root
						.as_ref()
						.try_into()
						.map_err(|_| Error::InvalidRoot)?,
				),
				Node::from_bytes(
					execution_payload
						.block_number
						.clone()
						.hash_tree_root()
						.map_err(|_| Error::MerkleizationError)?
						.as_ref()
						.try_into()
						.map_err(|_| Error::InvalidRoot)?,
				),
				Node::from_bytes(
					execution_payload
						.timestamp
						.clone()
						.hash_tree_root()
						.map_err(|_| Error::MerkleizationError)?
						.as_ref()
						.try_into()
						.map_err(|_| Error::InvalidRoot)?,
				),
			],
			&multi_proof,
			&[
				GeneralizedIndex(EXECUTION_PAYLOAD_STATE_ROOT_INDEX as usize),
				GeneralizedIndex(EXECUTION_PAYLOAD_BLOCK_NUMBER_INDEX as usize),
				GeneralizedIndex(EXECUTION_PAYLOAD_TIMESTAMP_INDEX as usize),
			],
		);

		let execution_payload_branch = execution_payload
			.execution_payload_branch
			.iter()
			.map(|node| Node::from_bytes(node.as_ref().try_into().unwrap()))
			.collect::<Vec<_>>();
		let is_merkle_branch_valid = is_valid_merkle_branch(
			&execution_payload_root,
			execution_payload_branch.iter(),
			EXECUTION_PAYLOAD_INDEX_LOG2 as usize,
			EXECUTION_PAYLOAD_INDEX as usize,
			&Node::from_bytes(
				ancestor.header.state_root.as_ref().try_into().map_err(|_| Error::InvalidRoot)?,
			),
		);

		if !is_merkle_branch_valid {
			Err(Error::InvalidMerkleBranch)?;
		}
	}

	let new_light_client_state = if let Some(sync_committee_update) = update.sync_committee_update {
		LightClientState {
			finalized_header: update.finalized_header,
			latest_finalized_epoch: update.finality_proof.epoch,
			current_sync_committee: trusted_state.next_sync_committee,
			next_sync_committee: sync_committee_update.next_sync_committee,
		}
	} else {
		LightClientState { finalized_header: update.finalized_header, ..trusted_state }
	};

	Ok(new_light_client_state)
}
