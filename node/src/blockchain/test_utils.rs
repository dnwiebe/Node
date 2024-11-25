// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
};
use bip39::{Language, Mnemonic, Seed};
use ethabi::Hash;
use ethereum_types::{BigEndianHash, H160, H256, U64};
use lazy_static::lazy_static;
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::to_string;
use serde::Serialize;
use serde_derive::Deserialize;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Index, Log, SignedTransaction, TransactionReceipt, H2048, U256};

lazy_static! {
    static ref BIG_MEANINGLESS_PHRASE: Vec<&'static str> = vec![
        "parent", "prevent", "vehicle", "tooth", "crazy", "cruel", "update", "mango", "female",
        "mad", "spread", "plunge", "tiny", "inch", "under", "engine", "enforce", "film", "awesome",
        "plunge", "cloud", "spell", "empower", "pipe",
    ];
}

pub fn make_meaningless_phrase_words() -> Vec<String> {
    BIG_MEANINGLESS_PHRASE.iter().map(to_string).collect()
}

pub fn make_meaningless_phrase() -> String {
    make_meaningless_phrase_words().join(" ").to_string()
}

pub fn make_meaningless_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(&make_meaningless_phrase(), Language::English).unwrap();
    Seed::new(&mnemonic, "passphrase")
}

pub fn make_blockchain_interface_web3(port: u16) -> BlockchainInterfaceWeb3 {
    let chain = Chain::PolyMainnet;
    let (event_loop_handle, transport) = Http::with_max_parallel(
        &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
        REQUESTS_IN_PARALLEL,
    )
    .unwrap();

    BlockchainInterfaceWeb3::new(transport, event_loop_handle, chain)
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RpcResponse<S: Serialize> {
    #[serde(rename = "jsonrpc")]
    json_rpc: String,
    id: u8,
    result: S,
}

#[derive(Default)]
pub struct ReceiptResponseBuilder {
    transaction_hash_opt: Option<Hash>,
    transaction_index_opt: Option<Index>,
    block_hash_opt: Option<Hash>,
    block_number_opt: Option<U64>,
    cumulative_gas_used_opt: Option<U256>,
    gas_used_opt: Option<U256>,
    contract_address_opt: Option<H160>,
    logs_opt: Option<Vec<Log>>,
    status_opt: Option<U64>,
    root_opt: Option<Hash>,
    logs_bloom_opt: Option<H2048>,
}

impl ReceiptResponseBuilder {
    pub fn transaction_hash(mut self, hash: Hash) -> ReceiptResponseBuilder {
        self.transaction_hash_opt = Some(hash);
        self
    }

    pub fn transaction_index(mut self, index: Index) -> ReceiptResponseBuilder {
        self.transaction_index_opt = Some(index);
        self
    }

    pub fn block_hash(mut self, hash: Hash) -> ReceiptResponseBuilder {
        self.block_hash_opt = Some(hash);
        self
    }

    pub fn block_number(mut self, number: U64) -> ReceiptResponseBuilder {
        self.block_number_opt = Some(number);
        self
    }

    pub fn cumulative_gas_used(mut self, number: U256) -> ReceiptResponseBuilder {
        self.cumulative_gas_used_opt = Some(number);
        self
    }

    pub fn gas_used(mut self, number: U256) -> ReceiptResponseBuilder {
        self.gas_used_opt = Some(number);
        self
    }

    pub fn contract_address(mut self, hash: H160) -> ReceiptResponseBuilder {
        self.contract_address_opt = Some(hash);
        self
    }

    pub fn logs(mut self, logs: Vec<Log>) -> ReceiptResponseBuilder {
        self.logs_opt = Some(logs);
        self
    }

    pub fn status(mut self, number: U64) -> ReceiptResponseBuilder {
        self.status_opt = Some(number);
        self
    }

    pub fn root(mut self, hash: Hash) -> ReceiptResponseBuilder {
        self.root_opt = Some(hash);
        self
    }

    pub fn logs_bloom(mut self, bloom: H2048) -> ReceiptResponseBuilder {
        self.logs_bloom_opt = Some(bloom);
        self
    }

    pub fn build(self) -> String {
        let mut transaction_receipt = TransactionReceipt::default();

        if let Some(transaction_hash) = self.transaction_hash_opt {
            transaction_receipt.transaction_hash = transaction_hash;
        }

        if let Some(index) = self.transaction_index_opt {
            transaction_receipt.transaction_index = index;
        }

        if let Some(cumulative_gas_used) = self.cumulative_gas_used_opt {
            transaction_receipt.cumulative_gas_used = cumulative_gas_used;
        }

        if let Some(logs) = self.logs_opt {
            transaction_receipt.logs = logs;
        }

        if let Some(bloom) = self.logs_bloom_opt {
            transaction_receipt.logs_bloom = bloom;
        }

        transaction_receipt.block_hash = self.block_hash_opt;
        transaction_receipt.block_number = self.block_number_opt;
        transaction_receipt.gas_used = self.gas_used_opt;
        transaction_receipt.contract_address = self.contract_address_opt;
        transaction_receipt.status = self.status_opt;
        transaction_receipt.root = self.root_opt;

        let rpc_response = RpcResponse {
            json_rpc: "2.0".to_string(),
            id: 1,
            result: transaction_receipt,
        };
        serde_json::to_string(&rpc_response).unwrap()
    }
}

pub fn make_fake_event_loop_handle() -> EventLoopHandle {
    Http::with_max_parallel("http://86.75.30.9", REQUESTS_IN_PARALLEL)
        .unwrap()
        .0
}

pub fn make_default_signed_transaction() -> SignedTransaction {
    SignedTransaction {
        message_hash: Default::default(),
        v: 0,
        r: Default::default(),
        s: Default::default(),
        raw_transaction: Default::default(),
        transaction_hash: Default::default(),
    }
}

pub fn make_tx_hash(base: u32) -> H256 {
    H256::from_uint(&U256::from(base))
}

pub fn all_chains() -> [Chain; 4] {
    [
        Chain::EthMainnet,
        Chain::PolyMainnet,
        Chain::PolyAmoy,
        Chain::Dev,
    ]
}

pub fn transport_error_code() -> u16 {
    if cfg!(target_os = "windows") {
        10061
    } else if cfg!(target_os = "macos") {
        61
    } else if cfg!(target_os = "linux") {
        111
    } else {
        0
    }
}

pub fn transport_error_message() -> String {
    if cfg!(target_os = "windows") {
        "No connection could be made because the target machine actively refused it.".to_string()
    } else {
        "Connection refused".to_string()
    }
}
