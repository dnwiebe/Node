// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
};
use crate::blockchain::blockchain_interface::data_structures::errors::{
    BlockchainAgentBuildError, BlockchainError, PayableTransactionError,
};
use crate::blockchain::blockchain_interface::data_structures::{
    ProcessedPayableFallible, RetrievedBlockchainTransactions,
};
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
// use crate::blockchain::blockchain_interface::test_utils::LowBlockchainIntMock;
use crate::blockchain::blockchain_interface::test_utils::LowBlockchainIntMock;
use crate::blockchain::blockchain_interface::BlockchainInterface;
use crate::set_arbitrary_id_stamp_in_mock_impl;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use actix::Recipient;
use bip39::{Language, Mnemonic, Seed};
use ethabi::Hash;
use ethereum_types::{BigEndianHash, H160, H256, U64};
use futures::future::result;
use futures::Future;
use lazy_static::lazy_static;
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::{find_free_port, to_string};
use serde::Serialize;
use serde_derive::Deserialize;
use std::cell::RefCell;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use web3::transports::{Batch, EventLoopHandle, Http};
use web3::types::{
    Address, BlockNumber, Index, Log, SignedTransaction, TransactionReceipt, H2048, U256,
};
use web3::Web3;

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

pub fn make_blockchain_interface_web3(port_opt: Option<u16>) -> BlockchainInterfaceWeb3 {
    let port = port_opt.unwrap_or_else(|| find_free_port());
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
            id: 0,
            result: transaction_receipt,
        };
        serde_json::to_string(&rpc_response).unwrap()
    }
}

#[derive(Default)]
pub struct BlockchainInterfaceMock {
    retrieve_transactions_parameters: Arc<Mutex<Vec<(BlockNumber, u64, Address)>>>,
    retrieve_transactions_results:
        RefCell<Vec<Result<RetrievedBlockchainTransactions, BlockchainError>>>,
    build_blockchain_agent_params: Arc<Mutex<Vec<(Wallet, ArbitraryIdStamp)>>>,
    build_blockchain_agent_results:
        RefCell<Vec<Result<Box<dyn BlockchainAgent>, BlockchainAgentBuildError>>>,
    send_batch_of_payables_params: Arc<
        Mutex<
            Vec<(
                ArbitraryIdStamp,
                Recipient<PendingPayableFingerprintSeeds>,
                Vec<PayableAccount>,
            )>,
        >,
    >,
    send_batch_of_payables_results:
        RefCell<Vec<Result<Vec<ProcessedPayableFallible>, PayableTransactionError>>>,
    get_transaction_receipt_params: Arc<Mutex<Vec<H256>>>,
    get_transaction_receipt_results:
        RefCell<Vec<Result<Option<TransactionReceipt>, BlockchainError>>>,
    lower_interface_result: Option<Box<LowBlockchainIntMock>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
    get_chain_results: RefCell<Vec<Chain>>,
    get_batch_web3_results: RefCell<Vec<Web3<Batch<Http>>>>,
}

impl BlockchainInterface for BlockchainInterfaceMock {
    fn contract_address(&self) -> Address {
        unimplemented!("not needed so far")
    }

    fn get_chain(&self) -> Chain {
        unimplemented!("not needed so far")
    }

    fn retrieve_transactions(
        &self,
        start_block: BlockNumber,
        fallback_start_block_number: u64,
        recipient: Address,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>> {
        self.retrieve_transactions_parameters.lock().unwrap().push((
            start_block,
            fallback_start_block_number,
            recipient,
        ));
        Box::new(result(
            self.retrieve_transactions_results.borrow_mut().remove(0),
        ))
    }

    fn build_blockchain_agent(
        &self,
        _consuming_wallet: Wallet,
    ) -> Box<dyn Future<Item = Box<dyn BlockchainAgent>, Error = BlockchainAgentBuildError>> {
        unimplemented!("not needed so far")
    }

    fn lower_interface(&self) -> Box<dyn LowBlockchainInt> {
        unimplemented!("not needed so far")
    }
}

impl BlockchainInterfaceMock {
    pub fn retrieve_transactions_params(
        mut self,
        params: &Arc<Mutex<Vec<(BlockNumber, u64, Address)>>>,
    ) -> Self {
        self.retrieve_transactions_parameters = params.clone();
        self
    }

    pub fn retrieve_transactions_result(
        self,
        result: Result<RetrievedBlockchainTransactions, BlockchainError>,
    ) -> Self {
        self.retrieve_transactions_results.borrow_mut().push(result);
        self
    }

    pub fn build_blockchain_agent_params(
        mut self,
        params: &Arc<Mutex<Vec<(Wallet, ArbitraryIdStamp)>>>,
    ) -> Self {
        self.build_blockchain_agent_params = params.clone();
        self
    }

    pub fn build_blockchain_agent_result(
        self,
        result: Result<Box<dyn BlockchainAgent>, BlockchainAgentBuildError>,
    ) -> Self {
        self.build_blockchain_agent_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn send_batch_of_payables_params(
        mut self,
        params: &Arc<
            Mutex<
                Vec<(
                    ArbitraryIdStamp,
                    Recipient<PendingPayableFingerprintSeeds>,
                    Vec<PayableAccount>,
                )>,
            >,
        >,
    ) -> Self {
        self.send_batch_of_payables_params = params.clone();
        self
    }

    pub fn send_batch_of_payables_result(
        self,
        result: Result<Vec<ProcessedPayableFallible>, PayableTransactionError>,
    ) -> Self {
        self.send_batch_of_payables_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn get_chain_result(self, result: Chain) -> Self {
        self.get_chain_results.borrow_mut().push(result);
        self
    }

    pub fn get_batch_web3_result(self, result: Web3<Batch<Http>>) -> Self {
        self.get_batch_web3_results.borrow_mut().push(result);
        self
    }

    pub fn get_transaction_receipt_params(mut self, params: &Arc<Mutex<Vec<H256>>>) -> Self {
        self.get_transaction_receipt_params = params.clone();
        self
    }

    pub fn get_transaction_receipt_result(
        self,
        result: Result<Option<TransactionReceipt>, BlockchainError>,
    ) -> Self {
        self.get_transaction_receipt_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn lower_interface_results(
        mut self,
        aggregated_results: Box<LowBlockchainIntMock>,
    ) -> Self {
        self.lower_interface_result = Some(aggregated_results);
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();
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
