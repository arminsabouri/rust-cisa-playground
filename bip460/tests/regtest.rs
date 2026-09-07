#![cfg(feature = "regtest")]

mod harness;

use bitcoin::{Amount, TxOut};
use harness::{MiniWallet, Regtest};

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
