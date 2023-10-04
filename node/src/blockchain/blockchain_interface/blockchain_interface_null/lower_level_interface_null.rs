// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError;
use crate::blockchain::blockchain_interface::lower_level_interface::{
    LatestBlockNumber, LowerBCI, ResultForBalance, ResultForNonce,
};
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;

pub struct LowerBCINull {
    logger: Logger,
}

impl LowerBCI for LowerBCINull {
    fn get_transaction_fee_balance(&self, _wallet: &Wallet) -> ResultForBalance {
        Err(self.handle_null_call("transaction fee balance"))
    }

    fn get_masq_balance(&self, _wallet: &Wallet) -> ResultForBalance {
        Err(self.handle_null_call("masq balance"))
    }

    fn get_block_number(&self) -> LatestBlockNumber {
        Err(self.handle_null_call("block number"))
    }

    fn get_transaction_id(&self, _wallet: &Wallet) -> ResultForNonce {
        Err(self.handle_null_call("transaction id"))
    }
}

impl LowerBCINull {
    pub fn new(logger: &Logger) -> Self {
        Self {
            logger: logger.clone(),
        }
    }

    fn handle_null_call(&self, operation: &str) -> BlockchainError {
        error!(self.logger, "Null version can't fetch {operation}");
        BlockchainError::UninitializedBlockchainInterface
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::blockchain::blockchain_interface::blockchain_interface_null::lower_level_interface_null::LowerBCINull;
    use crate::blockchain::blockchain_interface::lower_level_interface::LowerBCI;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::fmt::Debug;

    #[test]
    fn lower_bci_null_gets_no_transaction_fee_balance() {
        let test_name = "lower_bci_null_gets_no_transaction_fee_balance";
        let act =
            |subject: &LowerBCINull, wallet: &Wallet| subject.get_transaction_fee_balance(wallet);

        test_null_method(test_name, act, "transaction fee balance");
    }

    #[test]
    fn lower_bci_null_gets_no_masq_balance() {
        let test_name = "lower_bci_null_gets_no_masq_balance";
        let act = |subject: &LowerBCINull, wallet: &Wallet| subject.get_masq_balance(wallet);

        test_null_method(test_name, act, "masq balance");
    }

    #[test]
    fn lower_bci_null_gets_no_block_number() {
        let test_name = "lower_bci_null_gets_no_block_number";
        let act = |subject: &LowerBCINull, _wallet: &Wallet| subject.get_block_number();

        test_null_method(test_name, act, "block number");
    }

    #[test]
    fn lower_bci_null_gets_no_transaction_id() {
        let test_name = "lower_bci_null_gets_no_transaction_id";
        let act = |subject: &LowerBCINull, wallet: &Wallet| subject.get_transaction_id(wallet);

        test_null_method(test_name, act, "transaction id");
    }

    fn test_null_method<T: Debug + PartialEq>(
        test_name: &str,
        act: fn(&LowerBCINull, &Wallet) -> Result<T, BlockchainError>,
        expected_method_name: &str,
    ) {
        init_test_logging();
        let wallet = make_wallet("blah");
        let subject = LowerBCINull::new(&Logger::new(test_name));

        let result = act(&subject, &wallet);

        assert_eq!(
            result,
            Err(BlockchainError::UninitializedBlockchainInterface)
        );
        let _expected_log_msg = TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Null version can't fetch {expected_method_name}"
        ));
    }
}
