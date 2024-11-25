// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::arbitrary_id_stamp_in_trait;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;

// Table of chains by
//
// a) adoption of the fee market (variations on "gas price")
// b) customizable limit of allowed computation ("gas limit")
//
// CHAINS                    a)  |  b)
//-------------------------------+------
// Ethereum                 yes  |  yes
// Polygon                  yes  |  yes
// Qtum                     yes  |  yes
// NEO                      yes  |  no*
// Cardano                  no   |  yes
// Bitcoin                  yes  |  no

//* defaulted limit

pub trait BlockchainAgent: Send {
    fn estimated_transaction_fee_total(&self, number_of_transactions: usize) -> u128;
    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances;
    fn agreed_fee_per_computation_unit(&self) -> u128;
    fn consuming_wallet(&self) -> &Wallet;

    #[cfg(test)]
    fn dup(&self) -> Box<dyn BlockchainAgent> {
        intentionally_blank!()
    }
    as_any_ref_in_trait!();
    arbitrary_id_stamp_in_trait!();
}
