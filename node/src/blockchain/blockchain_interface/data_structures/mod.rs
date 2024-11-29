// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod errors;
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::sub_lib::wallet::Wallet;
use web3::types::{BlockNumber, H256};
use web3::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockchainTransaction {
    pub block_number: u64,
    pub from: Wallet,
    pub wei_amount: u128,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RetrievedBlockchainTransactions {
    pub new_start_block: BlockNumber,
    pub transactions: Vec<BlockchainTransaction>,
}

pub type ProcessedPayableFallible = Result<PendingPayable, RpcPayablesFailure>;

#[derive(Debug, PartialEq, Clone)]
pub struct RpcPayablesFailure {
    pub rpc_error: Error,
    pub recipient_wallet: Wallet,
    pub hash: H256,
}
