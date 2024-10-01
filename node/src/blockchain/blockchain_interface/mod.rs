// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod blockchain_interface_web3;
pub mod data_structures;
pub mod lower_level_interface;
pub mod test_utils;

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_interface::data_structures::errors::{
    BlockchainAgentBuildError, BlockchainError,
};
use crate::blockchain::blockchain_interface::data_structures::RetrievedBlockchainTransactions;
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::sub_lib::wallet::Wallet;
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use web3::types::{Address, BlockNumber};

pub trait BlockchainInterface {
    fn contract_address(&self) -> Address;

    fn get_chain(&self) -> Chain;

    fn lower_interface(&self) -> Box<dyn LowBlockchainInt>;

    fn retrieve_transactions(
        &self,
        start_block: BlockNumber,
        fallback_start_block_number: u64,
        recipient: Address,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>>;

    fn build_blockchain_agent(
        &self,
        consuming_wallet: Wallet,
    ) -> Box<dyn Future<Item = Box<dyn BlockchainAgent>, Error = BlockchainAgentBuildError>>;

    as_any_ref_in_trait!();
}
