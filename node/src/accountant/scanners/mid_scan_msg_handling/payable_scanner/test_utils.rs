// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use std::cell::RefCell;

#[derive(Default)]
pub struct BlockchainAgentMock {
    consuming_wallet_balances_results: RefCell<Vec<ConsumingWalletBalances>>,
    agreed_fee_per_computation_unit_results: RefCell<Vec<u128>>,
    consuming_wallet_result_opt: Option<Wallet>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl BlockchainAgent for BlockchainAgentMock {
    fn estimated_transaction_fee_total(&self, _number_of_transactions: usize) -> u128 {
        todo!("to be implemented by GH-711")
    }

    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances {
        todo!("to be implemented by GH-711")
    }

    fn agreed_fee_per_computation_unit(&self) -> u128 {
        self.agreed_fee_per_computation_unit_results
            .borrow_mut()
            .remove(0)
    }

    fn consuming_wallet(&self) -> &Wallet {
        self.consuming_wallet_result_opt.as_ref().unwrap()
    }

    fn dup(&self) -> Box<dyn BlockchainAgent> {
        intentionally_blank!()
    }

    arbitrary_id_stamp_in_trait_impl!();
}

impl BlockchainAgentMock {
    pub fn consuming_wallet_balances_result(self, result: ConsumingWalletBalances) -> Self {
        self.consuming_wallet_balances_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn agreed_fee_per_computation_unit_result(self, result: u128) -> Self {
        self.agreed_fee_per_computation_unit_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn consuming_wallet_result(mut self, consuming_wallet_result: Wallet) -> Self {
        self.consuming_wallet_result_opt = Some(consuming_wallet_result);
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}
