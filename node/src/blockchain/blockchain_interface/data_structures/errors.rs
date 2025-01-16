// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::comma_joined_stringifiable;
use itertools::Either;
use std::fmt;
use std::fmt::{Display, Formatter};
use variant_count::VariantCount;
use web3::types::{Address, H256};

const BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED: &str = "Uninitialized blockchain interface. To avoid \
being delinquency-banned, you should restart the Node with a value for blockchain-service-url";

#[derive(Clone, Debug, PartialEq, Eq, VariantCount)]
pub enum BlockchainError {
    InvalidUrl,
    InvalidAddress,
    InvalidResponse,
    QueryFailed(String),
    UninitializedBlockchainInterface,
}

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let err_spec = match self {
            Self::InvalidUrl => Either::Left("Invalid url"),
            Self::InvalidAddress => Either::Left("Invalid address"),
            Self::InvalidResponse => Either::Left("Invalid response"),
            Self::QueryFailed(msg) => Either::Right(format!("Query failed: {}", msg)),
            Self::UninitializedBlockchainInterface => {
                Either::Left(BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED)
            }
        };
        write!(f, "Blockchain error: {}", err_spec)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, VariantCount)]
pub enum PayableTransactionError {
    MissingConsumingWallet,
    GasPriceQueryFailed(BlockchainError),
    TransactionID(BlockchainError),
    UnusableWallet(String),
    Signing(String),
    Sending { msg: String, hashes: Vec<H256> },
    UninitializedBlockchainInterface,
}

impl Display for PayableTransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConsumingWallet => {
                write!(f, "Missing consuming wallet to pay payable from")
            }
            Self::GasPriceQueryFailed(msg) => {
                write!(f, "Unsuccessful gas price query: \"{}\"", msg)
            }
            Self::TransactionID(blockchain_err) => {
                write!(f, "Transaction id fetching failed: {}", blockchain_err)
            }
            Self::UnusableWallet(msg) => write!(
                f,
                "Unusable wallet for signing payable transactions: \"{}\"",
                msg
            ),
            Self::Signing(msg) => write!(f, "Signing phase: \"{}\"", msg),
            Self::Sending { msg, hashes } => write!(
                f,
                "Sending phase: \"{}\". Signed and hashed transactions: {}",
                msg,
                comma_joined_stringifiable(hashes, |hash| format!("{:?}", hash))
            ),
            Self::UninitializedBlockchainInterface => {
                write!(f, "{}", BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, VariantCount)]
pub enum BlockchainAgentBuildError {
    GasPrice(BlockchainError),
    TransactionFeeBalance(Address, BlockchainError),
    ServiceFeeBalance(Address, BlockchainError),
    UninitializedBlockchainInterface,
}

impl Display for BlockchainAgentBuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let preformatted_or_complete = match self {
            Self::GasPrice(blockchain_e) => {
                Either::Left(format!("gas price due to: {:?}", blockchain_e))
            }
            Self::TransactionFeeBalance(address, blockchain_e) => Either::Left(format!(
                "transaction fee balance for our earning wallet {:#x} due to: {}",
                address, blockchain_e
            )),
            Self::ServiceFeeBalance(address, blockchain_e) => Either::Left(format!(
                "masq balance for our earning wallet {:#x} due to {}",
                address, blockchain_e
            )),
            Self::UninitializedBlockchainInterface => {
                Either::Right(BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED.to_string())
            }
        };

        match preformatted_or_complete {
            Either::Left(ending) => write!(
                f,
                "Blockchain agent construction failed at fetching {}",
                ending
            ),
            Either::Right(msg) => write!(f, "{}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::data_structures::errors::{
        PayableTransactionError, BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED,
    };
    use crate::blockchain::blockchain_interface::{BlockchainAgentBuildError, BlockchainError};
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::test_utils::make_wallet;
    use masq_lib::utils::{slice_of_strs_to_vec_of_strings, to_string};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED,
            "Uninitialized blockchain interface. To avoid being delinquency-banned, you should \
            restart the Node with a value for blockchain-service-url"
        )
    }

    #[test]
    fn blockchain_error_implements_display() {
        let original_errors = [
            BlockchainError::InvalidUrl,
            BlockchainError::InvalidAddress,
            BlockchainError::InvalidResponse,
            BlockchainError::QueryFailed(
                "Don't query so often, it gives me a headache".to_string(),
            ),
            BlockchainError::UninitializedBlockchainInterface,
        ];

        let actual_error_msgs = original_errors.iter().map(to_string).collect::<Vec<_>>();

        assert_eq!(
            original_errors.len(),
            BlockchainError::VARIANT_COUNT,
            "you forgot to add all variants in this test"
        );
        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Blockchain error: Invalid url",
                "Blockchain error: Invalid address",
                "Blockchain error: Invalid response",
                "Blockchain error: Query failed: Don't query so often, it gives me a headache",
                &format!("Blockchain error: {}", BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED)
            ])
        );
    }

    #[test]
    fn payable_payment_error_implements_display() {
        let original_errors = [
            PayableTransactionError::MissingConsumingWallet,
            PayableTransactionError::GasPriceQueryFailed(BlockchainError::QueryFailed(
                "Gas halves shut, no drop left".to_string(),
            )),
            PayableTransactionError::TransactionID(BlockchainError::InvalidResponse),
            PayableTransactionError::UnusableWallet(
                "This is a LEATHER wallet, not LEDGER wallet, stupid.".to_string(),
            ),
            PayableTransactionError::Signing(
                "You cannot sign with just three crosses here, clever boy".to_string(),
            ),
            PayableTransactionError::Sending {
                msg: "Sending to cosmos belongs elsewhere".to_string(),
                hashes: vec![make_tx_hash(0x6f), make_tx_hash(0xde)],
            },
            PayableTransactionError::UninitializedBlockchainInterface,
        ];

        let actual_error_msgs = original_errors.iter().map(to_string).collect::<Vec<_>>();

        assert_eq!(
            original_errors.len(),
            PayableTransactionError::VARIANT_COUNT,
            "you forgot to add all variants in this test"
        );
        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Missing consuming wallet to pay payable from",
                "Unsuccessful gas price query: \"Blockchain error: Query failed: Gas halves shut, no drop left\"",
                "Transaction id fetching failed: Blockchain error: Invalid response",
                "Unusable wallet for signing payable transactions: \"This is a LEATHER wallet, not \
                LEDGER wallet, stupid.\"",
                "Signing phase: \"You cannot sign with just three crosses here, clever boy\"",
                "Sending phase: \"Sending to cosmos belongs elsewhere\". Signed and hashed \
                transactions: 0x000000000000000000000000000000000000000000000000000000000000006f, \
                0x00000000000000000000000000000000000000000000000000000000000000de",
                BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED
            ])
        )
    }

    #[test]
    fn blockchain_agent_build_error_implements_display() {
        let wallet = make_wallet("abc");
        let original_errors = [
            BlockchainAgentBuildError::GasPrice(BlockchainError::InvalidResponse),
            BlockchainAgentBuildError::TransactionFeeBalance(
                wallet.address(),
                BlockchainError::InvalidResponse,
            ),
            BlockchainAgentBuildError::ServiceFeeBalance(
                wallet.address(),
                BlockchainError::InvalidAddress,
            ),
            BlockchainAgentBuildError::UninitializedBlockchainInterface,
        ];

        let actual_error_msgs = original_errors.iter().map(to_string).collect::<Vec<_>>();

        assert_eq!(
            original_errors.len(),
            BlockchainAgentBuildError::VARIANT_COUNT,
            "you forgot to add all variants in this test"
        );
        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Blockchain agent construction failed at fetching gas price due to: InvalidResponse",
                "Blockchain agent construction failed at fetching transaction fee balance for our earning \
                wallet 0x0000000000000000000000000000000000616263 due to: Blockchain error: Invalid response",
                "Blockchain agent construction failed at fetching masq balance for our earning wallet \
                0x0000000000000000000000000000000000616263 due to Blockchain error: Invalid address",
                BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED
            ])
        )
    }
}
