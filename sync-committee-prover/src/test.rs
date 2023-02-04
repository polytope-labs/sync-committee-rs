use super::*;
use ethereum_consensus::altair::NEXT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2;
use light_client_primitives::types::{LightClientState, LightClientUpdate, SyncCommitteeUpdate};
use light_client_primitives::util::compute_sync_committee_period_at_slot;
use light_client_verifier::light_client::EthLightClient;
use ssz_rs::Merkleized;
use std::time::Duration;
use tokio::time;
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::StreamExt;

#[cfg(test)]
#[allow(non_snake_case)]
#[actix_rt::test]
async fn fetch_block_header_works() {
    let node_url: String = "http://localhost:3500".to_string();
    let sync_committee_prover = SyncCommitteeProver::new(node_url);
    let block_header = sync_committee_prover.fetch_header("finalized").await;
    assert!(block_header.is_ok());
}

#[cfg(test)]
#[allow(non_snake_case)]
#[actix_rt::test]
async fn fetch_block_works() {
    let node_url: String = "http://localhost:3500".to_string();
    let sync_committee_prover = SyncCommitteeProver::new(node_url);
    let block = sync_committee_prover.fetch_block("100").await;
    assert!(block.is_ok());
}

#[cfg(test)]
#[allow(non_snake_case)]
#[actix_rt::test]
async fn fetch_sync_committee_works() {
    let node_url: String = "http://localhost:3500".to_string();
    let sync_committee_prover = SyncCommitteeProver::new(node_url);
    let block = sync_committee_prover.fetch_sync_committee("117").await;
    assert!(block.is_ok());
}

#[cfg(test)]
#[allow(non_snake_case)]
#[actix_rt::test]
async fn fetch_validator_works() {
    let node_url: String = "http://localhost:3500".to_string();
    let sync_committee_prover = SyncCommitteeProver::new(node_url);
    let validator = sync_committee_prover.fetch_validator("2561", "48").await;
    assert!(validator.is_ok());
}

#[cfg(test)]
#[allow(non_snake_case)]
#[actix_rt::test]
async fn fetch_processed_sync_committee_works() {
    let node_url: String = "http://localhost:3500".to_string();
    let sync_committee_prover = SyncCommitteeProver::new(node_url);
    let validator = sync_committee_prover
        .fetch_processed_sync_committee("2561")
        .await;
    assert!(validator.is_ok());
}

#[cfg(test)]
#[allow(non_snake_case)]
#[actix_rt::test]
async fn fetch_beacon_state_works() {
    let node_url: String = "http://localhost:3500".to_string();
    let sync_committee_prover = SyncCommitteeProver::new(node_url);
    let beacon_state = sync_committee_prover.fetch_beacon_state("genesis").await;
    assert!(beacon_state.is_ok());
}

#[cfg(test)]
#[allow(non_snake_case)]
#[actix_rt::test]
async fn state_root_and_block_header_root_matches() {
    let node_url: String = "http://localhost:3500".to_string();
    let sync_committee_prover = SyncCommitteeProver::new(node_url);
    let beacon_state = sync_committee_prover.fetch_beacon_state("100").await;
    assert!(beacon_state.is_ok());

    let block_header = sync_committee_prover.fetch_header("100").await;
    assert!(block_header.is_ok());

    let state = beacon_state.unwrap();
    let block_header = block_header.unwrap();
    let hash_tree_root = state.clone().hash_tree_root();

    assert!(block_header.state_root == hash_tree_root.unwrap());
}

// use tokio interval(should run every 13 minutes)
// every 13 minutes, fetch latest finalized block
// then prove the execution payload
// prove the finality branch

// prove sync committee if there is a sync committee update
// to prove sync comnmittee update, calculate state_period and the update_attested_period
// ensure they are  the same, and then prove sync committee

#[cfg(test)]
#[allow(non_snake_case)]
#[actix_rt::test]
async fn test_prover() {
    // In test config an epoch is 6 slots and we expect finalization every two epochs,
    // a slot is 12 seconds so that brings us to 144 seconds
    let mut stream = IntervalStream::new(time::interval(Duration::from_secs(160)));

    let node_url: String = "http://localhost:3500".to_string();
    let sync_committee_prover = SyncCommitteeProver::new(node_url);
    let block_header = sync_committee_prover
        .fetch_header("finalized")
        .await
        .unwrap();

    let state = sync_committee_prover
        .fetch_beacon_state("finalized")
        .await
        .unwrap();

    let mut client_state = LightClientState {
        finalized_header: block_header.clone(),
        current_sync_committee: state.current_sync_committee,
        next_sync_committee: state.next_sync_committee,
    };

    while let Some(_ts) = stream.next().await {
        let finality_checkpoint = sync_committee_prover
            .fetch_finalized_checkpoint()
            .await
            .unwrap();
        let block_id = {
            let mut block_id = hex::encode(finality_checkpoint.root.as_bytes());
            block_id.insert_str(0, "0x");
            block_id
        };
        let finalized_block = sync_committee_prover.fetch_block(&block_id).await.unwrap();

        if finalized_block.slot <= client_state.finalized_header.slot {
            continue;
        }

        let finalized_header = sync_committee_prover.fetch_header(&block_id).await.unwrap();

        let execution_payload_proof = prove_execution_payload(finalized_block.clone()).unwrap();

        let attested_header_slot = get_attestation_slots_for_finalized_header(&finalized_header, 6);
        let finalized_state = sync_committee_prover
            .fetch_beacon_state(finalized_block.slot.to_string().as_str())
            .await
            .unwrap();

        let attested_state = sync_committee_prover
            .fetch_beacon_state(attested_header_slot.to_string().as_str())
            .await
            .unwrap();

        let finality_branch_proof = prove_finalized_header(attested_state.clone()).unwrap();
        let finality_branch_proof = finality_branch_proof
            .into_iter()
            .map(|node| Bytes32::try_from(node.as_bytes()).expect("Node is always 32 byte slice"))
            .collect::<Vec<_>>();

        let state_period = compute_sync_committee_period_at_slot(finalized_header.slot);

        let attested_header = sync_committee_prover
            .fetch_header(attested_header_slot.to_string().as_str())
            .await
            .unwrap();

        let update_attested_period = compute_sync_committee_period_at_slot(attested_header_slot);

        let sync_committee_update = if state_period == attested_header_slot {
            let sync_committee_proof = prove_sync_committee_update(attested_state).unwrap();

            let sync_committee_proof = sync_committee_proof
                .into_iter()
                .map(|node| {
                    Bytes32::try_from(node.as_bytes()).expect("Node is always 32 byte slice")
                })
                .collect::<Vec<_>>();

            let sync_committee = sync_committee_prover
                .fetch_processed_sync_committee(attested_header.slot.to_string().as_str())
                .await
                .unwrap();

            Some(SyncCommitteeUpdate {
                next_sync_committee: sync_committee,
                next_sync_committee_branch: sync_committee_proof,
            })
        } else {
            None
        };

        // construct light client
        let light_client_update = LightClientUpdate {
            attested_header,
            sync_committee_update,
            finalized_header,
            execution_payload: execution_payload_proof,
            finality_branch: finality_branch_proof,
            sync_aggregate: finalized_block.body.sync_aggregate,
            signature_slot: attested_header_slot,
            ancestor_blocks: vec![],
        };

        client_state = EthLightClient::verify_sync_committee_attestation(
            client_state.clone(),
            light_client_update,
        )
        .unwrap();
        println!(
            "Sucessfully verified Ethereum block at slot {:?}",
            client_state.finalized_header.slot
        );
    }
}
