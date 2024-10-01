// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use actix::Recipient;
use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainError, PayableTransactionError};
use crate::sub_lib::wallet::Wallet;
use ethereum_types::{H256, U64};
use futures::Future;
use web3::contract::Contract;
use web3::transports::Http;
use web3::types::{Address, Filter, Log, TransactionReceipt, U256};
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionReceiptResult;
use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible;

pub trait LowBlockchainInt {
    // TODO: GH-495 The data structures in this trait are not generic, will need associated_type_defaults to implement it.
    // see issue #29661 <https://github.com/rust-lang/rust/issues/29661> for more information

    fn get_transaction_fee_balance(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_service_fee_balance(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_gas_price(&self) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_block_number(&self) -> Box<dyn Future<Item = U64, Error = BlockchainError>>;

    fn get_transaction_id(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_transaction_receipt(
        &self,
        hash: H256,
    ) -> Box<dyn Future<Item = Option<TransactionReceipt>, Error = BlockchainError>>;

    fn get_transaction_receipt_batch(
        &self,
        hash_vec: Vec<H256>,
    ) -> Box<dyn Future<Item = Vec<TransactionReceiptResult>, Error = BlockchainError>>;

    fn get_contract(&self) -> Contract<Http>;

    fn get_transaction_logs(
        &self,
        filter: Filter,
    ) -> Box<dyn Future<Item = Vec<Log>, Error = BlockchainError>>;

    fn submit_payables_in_batch(
        &self,
        logger: Logger,
        chain: Chain,
        consuming_wallet: Wallet,
        fingerprints_recipient: Recipient<PendingPayableFingerprintSeeds>,
        affordable_accounts: Vec<PayableAccount>,
    ) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError>>;
}
