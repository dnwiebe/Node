// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;

use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use ethereum_types::U256;
use masq_lib::logger::Logger;

#[derive(Clone)]
pub struct BlockchainAgentNull {
    wallet: Wallet,
    logger: Logger,
}

impl BlockchainAgent for BlockchainAgentNull {
    fn estimated_transaction_fee_total(&self, _number_of_transactions: usize) -> u128 {
        self.log_function_call("estimated_transaction_fee_total()");
        0
    }

    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances {
        self.log_function_call("consuming_wallet_balances()");
        ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: U256::zero(),
            masq_token_balance_in_minor_units: U256::zero(),
        }
    }

    fn agreed_fee_per_computation_unit(&self) -> u128 {
        self.log_function_call("agreed_fee_per_computation_unit()");
        0
    }

    fn consuming_wallet(&self) -> &Wallet {
        self.log_function_call("consuming_wallet()");
        &self.wallet
    }

    #[cfg(test)]
    fn dup(&self) -> Box<dyn BlockchainAgent> {
        intentionally_blank!()
    }

    #[cfg(test)]
    as_any_ref_in_trait_impl!();
}

impl BlockchainAgentNull {
    pub fn new() -> Self {
        Self {
            wallet: Wallet::null(),
            logger: Logger::new("BlockchainAgentNull"),
        }
    }

    fn log_function_call(&self, function_call: &str) {
        error!(
            self.logger,
            "calling null version of {function_call} for BlockchainAgentNull will be without effect",
        );
    }
}

impl Default for BlockchainAgentNull {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_null::BlockchainAgentNull;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;

    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::sub_lib::wallet::Wallet;

    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use web3::types::U256;

    fn blockchain_agent_null_constructor_works<C>(constructor: C)
    where
        C: Fn() -> BlockchainAgentNull,
    {
        init_test_logging();

        let result = constructor();

        assert_eq!(result.wallet, Wallet::null());
        warning!(result.logger, "blockchain_agent_null_constructor_works");
        TestLogHandler::default().exists_log_containing(
            "WARN: BlockchainAgentNull: \
        blockchain_agent_null_constructor_works",
        );
    }

    #[test]
    fn blockchain_agent_null_constructor_works_for_new() {
        blockchain_agent_null_constructor_works(BlockchainAgentNull::new)
    }

    #[test]
    fn blockchain_agent_null_constructor_works_for_default() {
        blockchain_agent_null_constructor_works(BlockchainAgentNull::default)
    }

    fn assert_error_log(test_name: &str, expected_operation: &str) {
        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling \
            null version of {expected_operation}() for BlockchainAgentNull \
            will be without effect"
        ));
    }

    #[test]
    fn null_agent_estimated_transaction_fee_total() {
        init_test_logging();
        let test_name = "null_agent_estimated_transaction_fee_total";
        let mut subject = BlockchainAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.estimated_transaction_fee_total(4);

        assert_eq!(result, 0);
        assert_error_log(test_name, "estimated_transaction_fee_total");
    }

    #[test]
    fn null_agent_consuming_wallet_balances() {
        init_test_logging();
        let test_name = "null_agent_consuming_wallet_balances";
        let mut subject = BlockchainAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.consuming_wallet_balances();

        assert_eq!(
            result,
            ConsumingWalletBalances {
                transaction_fee_balance_in_minor_units: U256::zero(),
                masq_token_balance_in_minor_units: U256::zero()
            }
        );
        assert_error_log(test_name, "consuming_wallet_balances")
    }

    #[test]
    fn null_agent_agreed_fee_per_computation_unit() {
        init_test_logging();
        let test_name = "null_agent_agreed_fee_per_computation_unit";
        let mut subject = BlockchainAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.agreed_fee_per_computation_unit();

        assert_eq!(result, 0);
        assert_error_log(test_name, "agreed_fee_per_computation_unit")
    }

    #[test]
    fn null_agent_consuming_wallet() {
        init_test_logging();
        let test_name = "null_agent_consuming_wallet";
        let mut subject = BlockchainAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.consuming_wallet();

        assert_eq!(result, &Wallet::null());
        assert_error_log(test_name, "consuming_wallet")
    }
}
