//! Regtest harness. Assumes a bitcoind is already running with RPC enabled,
//! built from a branch that implements BIP 460. Nothing here starts a node.
//!
//! Configured with BITCOIN_RPC_URL (default http://127.0.0.1:18443) and
//! BITCOIN_COOKIE (default ~/.bitcoin/regtest/.cookie).

use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::key::{Keypair, TapTweak, UntweakedPublicKey};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute::LockTime,
};
use bitcoind_async_client::{Auth, Client};
use serde_json::{Value, json};
use tokio::sync::{Mutex, OwnedMutexGuard};

// Every test shares one node, so they take turns rather than racing over the
// mempool and the chain tip.
static NODE: LazyLock<Arc<Mutex<()>>> = LazyLock::new(|| Arc::new(Mutex::new(())));

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

const COINBASE_MATURITY: u64 = 101;

static COUNTER: AtomicU64 = AtomicU64::new(0);

// Test-only key material. Distinct per wallet, no rand dependency.
fn fresh_secret() -> SecretKey {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let digest = sha256::Hash::hash(format!("cisa-harness-{nanos}-{count}").as_bytes());
    SecretKey::from_slice(&digest.to_byte_array()).expect("valid secret key")
}

fn rpc_url() -> String {
    std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18443".to_string())
}

fn cookie_path() -> PathBuf {
    match std::env::var("BITCOIN_COOKIE") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(home).join(".bitcoin/regtest/.cookie")
        }
    }
}

fn client_for(url: String) -> Result<Client> {
    Ok(Client::new(
        url,
        Auth::CookieFile(cookie_path()),
        None,
        None,
        None,
    )?)
}

/// A bag of P2TR keys. No coin selection: a spend always spends everything.
pub struct MiniWallet {
    keypair: Keypair,
    script_pubkey: ScriptBuf,
    utxos: Vec<(OutPoint, Amount)>,
}

impl MiniWallet {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &fresh_secret());
        let (internal_key, _parity) = keypair.x_only_public_key();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);
        MiniWallet {
            keypair,
            script_pubkey,
            utxos: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn internal_key(&self) -> UntweakedPublicKey {
        self.keypair.x_only_public_key().0
    }

    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }

    pub fn address(&self) -> Address {
        Address::from_script(&self.script_pubkey, Network::Regtest).expect("p2tr is standard")
    }

    pub fn balance(&self) -> Amount {
        self.utxos
            .iter()
            .map(|(_, value)| *value)
            .fold(Amount::ZERO, |a, b| a + b)
    }

    /// Records every output of `tx` that pays this wallet.
    pub fn receive(&mut self, tx: &Transaction) {
        let txid = tx.compute_txid();
        for (vout, output) in tx.output.iter().enumerate() {
            if output.script_pubkey == self.script_pubkey {
                self.utxos
                    .push((OutPoint::new(txid, vout as u32), output.value));
            }
        }
    }

    /// Spends every UTXO into `outputs`. The difference is the fee.
    pub fn spend_all(&self, outputs: Vec<TxOut>) -> Transaction {
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: self
                .utxos
                .iter()
                .map(|(outpoint, _)| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };

        let prevouts: Vec<TxOut> = self
            .utxos
            .iter()
            .map(|(_, value)| TxOut {
                value: *value,
                script_pubkey: self.script_pubkey.clone(),
            })
            .collect();

        let secp = Secp256k1::new();
        let tweaked = self.keypair.tap_tweak(&secp, None);
        let mut cache = SighashCache::new(&tx);
        let signatures: Vec<Witness> = (0..prevouts.len())
            .map(|index| {
                let sighash = cache
                    .taproot_key_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        TapSighashType::Default,
                    )
                    .expect("prevouts match inputs");
                let message = Message::from_digest(sighash.to_byte_array());
                let signature = secp.sign_schnorr_no_aux_rand(&message, &tweaked.to_keypair());
                Witness::from_slice(&[signature.serialize()])
            })
            .collect();
        for (input, witness) in tx.input.iter_mut().zip(signatures) {
            input.witness = witness;
        }
        tx
    }
}

pub struct Regtest {
    _guard: OwnedMutexGuard<()>,
    node: Client,
    miner: Client,
    miner_address: String,
}

impl Regtest {
    /// Connects, creates a throwaway Core wallet and mines it spendable coins.
    pub async fn setup() -> Result<Self> {
        let _guard = NODE.clone().lock_owned().await;
        let url = rpc_url();
        let node = client_for(url.clone())?;

        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let name = format!("cisa-harness-{nanos}");
        let _: Value = node
            .call_raw("createwallet", &[json!(name)])
            .await
            .map_err(|error| format!("createwallet failed: {error}"))?;
        let miner = client_for(format!("{url}/wallet/{name}"))?;

        let miner_address: String = miner.call_raw("getnewaddress", &[]).await?;
        let regtest = Regtest {
            _guard,
            node,
            miner,
            miner_address,
        };

        regtest.mine(COINBASE_MATURITY).await?;
        Ok(regtest)
    }

    #[allow(dead_code)]
    pub fn client(&self) -> &Client {
        &self.node
    }

    pub async fn mine(&self, blocks: u64) -> Result<()> {
        let _: Value = self
            .node
            .call_raw(
                "generatetoaddress",
                &[json!(blocks), json!(self.miner_address)],
            )
            .await?;
        Ok(())
    }

    /// Pays `amount` to each wallet in one transaction, confirms it, and hands
    /// each wallet its UTXOs. Call this at the start of every test.
    pub async fn distribute(&self, wallets: &mut [MiniWallet], amount: Amount) -> Result<()> {
        let mut targets = serde_json::Map::new();
        for wallet in wallets.iter() {
            targets.insert(wallet.address().to_string(), json!(amount.to_btc()));
        }
        let txid: String = self
            .miner
            .call_raw("sendmany", &[json!(""), Value::Object(targets)])
            .await?;

        let info: Value = self.miner.call_raw("gettransaction", &[json!(txid)]).await?;
        let raw = info["hex"].as_str().ok_or("gettransaction returned no hex")?;
        let funding: Transaction = deserialize(&hex_to_bytes(raw)?)?;
        for wallet in wallets.iter_mut() {
            wallet.receive(&funding);
        }
        self.mine(1).await?;
        Ok(())
    }

    /// Asks the node whether it would accept `tx`, without submitting it.
    pub async fn test_accept(&self, tx: &Transaction) -> Result<Value> {
        let raw = bytes_to_hex(&serialize(tx));
        let result: Vec<Value> = self
            .node
            .call_raw("testmempoolaccept", &[json!([raw])])
            .await?;
        Ok(result.into_iter().next().ok_or("empty testmempoolaccept")?)
    }

    /// Submits `tx`, mines it, and returns its txid.
    pub async fn confirm(&self, tx: &Transaction) -> Result<Txid> {
        let raw = bytes_to_hex(&serialize(tx));
        let txid: String = self
            .node
            .call_raw("sendrawtransaction", &[json!(raw)])
            .await?;
        self.mine(1).await?;
        Ok(txid.parse()?)
    }
}

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
