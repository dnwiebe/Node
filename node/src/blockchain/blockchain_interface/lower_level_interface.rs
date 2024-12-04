// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError;
use ethereum_types::{H256, U64};
use futures::Future;
use serde_json::Value;
use web3::transports::{Batch, Http};
use web3::types::{Address, Filter, Log, U256};
use web3::{Error, Web3};

pub trait LowBlockchainInt {
    // TODO: GH-495 The data structures in this trait are not generic, will need associated_type_defaults to implement it.
    // see issue #29661 <https://github.com/rust-lang/rust/issues/29661> for more information

    // TODO: Address can be a wrapper type
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

    fn get_transaction_receipt_in_batch(
        &self,
        hash_vec: Vec<H256>,
    ) -> Box<dyn Future<Item = Vec<Result<Value, Error>>, Error = BlockchainError>>;

    fn get_contract_address(&self) -> Address;

    fn get_transaction_logs(
        &self,
        filter: Filter,
    ) -> Box<dyn Future<Item = Vec<Log>, Error = BlockchainError>>;

    fn get_web3_batch(&self) -> Web3<Batch<Http>>;
}
