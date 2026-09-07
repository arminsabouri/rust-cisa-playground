#![cfg(feature = "regtest")]

mod harness;

use bitcoin::{Amount, TxOut};
use harness::{MiniWallet, Regtest, bytes_to_hex};

/// Exercises the harness itself: mine, distribute to n wallets, then have one
/// wallet spend everything it holds and confirm the spend.
#[tokio::test]
async fn harness_funds_and_spends() {
    let regtest = Regtest::setup().await.expect("node reachable");

    let mut wallets: Vec<MiniWallet> = (0..3).map(|_| MiniWallet::new()).collect();
    let amount = Amount::from_sat(1_000_000);
    regtest
        .distribute(&mut wallets, amount)
        .await
        .expect("distribute");

    for wallet in &wallets {
        assert_eq!(wallet.balance(), amount);
    }

    let spend = wallets[0].spend_all(vec![TxOut {
        value: amount - Amount::from_sat(1_000),
        script_pubkey: wallets[1].script_pubkey().clone(),
    }]);
    let accept = regtest.test_accept(&spend).await.expect("testmempoolaccept");
    assert_eq!(accept["allowed"], true, "{accept}");
    regtest.confirm(&spend).await.expect("confirm");
}

/// Two signers spend two witness v2 outputs as one full-aggregation group and
/// the node accepts and mines the result.
#[tokio::test]
async fn two_signers_full_aggregation_spend_is_accepted() {
    use bip460::{
        Coordinator, FULL_AGG_MARKER, Participant, SessionInput, taproot_key,
        witness_v2_script_pubkey,
    };
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::serialize;
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::sighash::TapSighashType;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Witness};

    let regtest = Regtest::setup().await.expect("node reachable");
    let mut funder = vec![MiniWallet::new()];
    regtest
        .distribute(&mut funder, Amount::from_sat(1_000_000))
        .await
        .expect("distribute");

    // Two taproot keys, each spent through the aggregation group.
    let secp = Secp256k1::new();
    let secrets = [[3u8; 32], [4u8; 32]];
    let tweaks: Vec<[u8; 32]> = secrets
        .iter()
        .map(|secret| {
            let keypair =
                Keypair::from_secret_key(&secp, &SecretKey::from_slice(secret).expect("key"));
            let internal = keypair.x_only_public_key().0.serialize();
            taproot_key(&internal, None).expect("derive").tweak
        })
        .collect();
    let scripts: Vec<ScriptBuf> = secrets
        .iter()
        .map(|secret| {
            let keypair =
                Keypair::from_secret_key(&secp, &SecretKey::from_slice(secret).expect("key"));
            let internal = keypair.x_only_public_key().0.serialize();
            let key = taproot_key(&internal, None).expect("derive");
            witness_v2_script_pubkey(&key.output_key)
        })
        .collect();

    // Create the two witness v2 outputs to spend.
    let funding = funder[0].spend_all(
        scripts
            .iter()
            .map(|script_pubkey| TxOut {
                value: Amount::from_sat(490_000),
                script_pubkey: script_pubkey.clone(),
            })
            .collect(),
    );
    println!("funding tx:    {}", bytes_to_hex(&serialize(&funding)));
    let accept = regtest.test_accept(&funding).await.expect("accept funding");
    assert_eq!(accept["allowed"], true, "funding rejected: {accept}");
    regtest.confirm(&funding).await.expect("confirm funding");
    let funding_txid = funding.compute_txid();

    let spent: Vec<TxOut> = funding.output.clone();
    let unsigned = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: (0..2)
            .map(|vout| TxIn {
                previous_output: OutPoint::new(funding_txid, vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(960_000),
            script_pubkey: funder[0].script_pubkey().clone(),
        }],
    };
    let inputs: Vec<SessionInput> = (0..2)
        .map(|index| SessionInput {
            index,
            hash_type: TapSighashType::Default,
            annex: None,
        })
        .collect();

    // Round 1: nonces.
    let mut coordinator = Coordinator::new(&unsigned, &spent);
    let mut participants = Vec::new();
    for (position, input) in inputs.iter().enumerate() {
        let (participant, pubnonce) = Participant::new(
            &secrets[position],
            Some(&tweaks[position]),
            *input,
            &unsigned,
            &spent,
        )
        .expect("participant");
        coordinator.add_nonce(*input, pubnonce).expect("add nonce");
        participants.push(participant);
    }

    // Round 2: partial signatures.
    let session = coordinator.session().expect("session");
    for participant in participants {
        let index = participant.index();
        let partial = participant.sign(&session).expect("sign");
        coordinator.add_partial(index, partial).expect("add partial");
    }
    let signed = coordinator.finalize().expect("finalize");

    // A full-aggregation member carries an empty element, the final input the
    // 64 byte aggregate followed by the marker.
    assert_eq!(signed.input[0].witness.nth(0).expect("member").len(), 0);
    let last = signed.input[1].witness.nth(0).expect("final");
    assert_eq!(last.len(), 65);
    assert_eq!(*last.last().expect("marker"), FULL_AGG_MARKER);

    println!("cisa spend tx: {}", bytes_to_hex(&serialize(&signed)));
    let accept = regtest.test_accept(&signed).await.expect("accept spend");
    assert_eq!(accept["allowed"], true, "spend rejected: {accept}");
    let txid = regtest.confirm(&signed).await.expect("confirm spend");
    assert_eq!(txid, signed.compute_txid());
}
