// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod batch_payable_tools;
pub mod lower_level_interface_web3;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError;
use crate::blockchain::blockchain_interface::data_structures::BlockchainTransaction;
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::blockchain::blockchain_interface::RetrievedBlockchainTransactions;
use crate::blockchain::blockchain_interface::{BlockchainAgentBuildError, BlockchainInterface};
use crate::sub_lib::wallet::Wallet;
use futures::{Future, future};
use indoc::indoc;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use std::convert::{From, TryInto};
use std::fmt::Debug;
use ethereum_types::U64;
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Address, BlockNumber, Log, H256, U256, FilterBuilder};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::LowBlockchainIntWeb3;
use crate::blockchain::blockchain_interface_utils::{create_blockchain_agent_web3, BlockchainAgentFutureResult};

const CONTRACT_ABI: &str = indoc!(
    r#"[{
    "constant":true,
    "inputs":[{"name":"owner","type":"address"}],
    "name":"balanceOf",
    "outputs":[{"name":"","type":"uint256"}],
    "payable":false,
    "stateMutability":"view",
    "type":"function"
    },{
    "constant":false,
    "inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],
    "name":"transfer",
    "outputs":[{"name":"","type":"bool"}],
    "payable":false,
    "stateMutability":"nonpayable",
    "type":"function"
    }]"#
);

pub const TRANSACTION_LITERAL: H256 = H256([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

pub const TRANSFER_METHOD_ID: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

pub const REQUESTS_IN_PARALLEL: usize = 1;

pub const BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED: &str =
    "To avoid being delinquency-banned, you should \
restart the Node with a value for blockchain-service-url";

pub struct BlockchainInterfaceWeb3 {
    pub logger: Logger,
    chain: Chain,
    gas_limit_const_part: u64,
    // This must not be dropped for Web3 requests to be completed
    _event_loop_handle: EventLoopHandle,
    transport: Http,
}

pub const GWEI: U256 = U256([1_000_000_000u64, 0, 0, 0]);

pub fn to_wei(gwub: u64) -> U256 {
    let subgwei = U256::from(gwub);
    subgwei.full_mul(GWEI).try_into().expect("Internal Error")
}

impl BlockchainInterface for BlockchainInterfaceWeb3 {
    fn contract_address(&self) -> Address {
        self.chain.rec().contract
    }

    fn get_chain(&self) -> Chain {
        self.chain
    }

    fn retrieve_transactions(
        &self,
        start_block: BlockNumber,
        fallback_start_block_number: u64,
        recipient: Address,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>> {
        let lower_level_interface = self.lower_interface();
        let logger = self.logger.clone();
        let contract_address = lower_level_interface.get_contract().address();
        let num_chain_id = self.chain.rec().num_chain_id;
        return Box::new(
            lower_level_interface.get_block_number().then(move |response_block_number_result| {
                let response_block_number = match response_block_number_result {
                    Ok(block_number) => {
                        debug!(logger, "Latest block number: {}", block_number.as_u64());
                        block_number.as_u64()
                    }
                    Err(_) => {
                        debug!(logger,"Using fallback block number: {}", fallback_start_block_number);
                        fallback_start_block_number
                    }
                };
                debug!(
                    logger,
                    "Retrieving transactions from start block: {:?} to end block: {:?} for: {} chain_id: {} contract: {:#x}",
                    start_block,
                    response_block_number,
                    recipient,
                    num_chain_id,
                    contract_address
                );
                let filter = FilterBuilder::default()
                    .address(vec![contract_address])
                    .from_block(start_block)
                    .to_block(BlockNumber::Number(U64::from(response_block_number)))
                    .topics(
                        Some(vec![TRANSACTION_LITERAL]),
                        None,
                        Some(vec![recipient.into()]),
                        None,
                    )
                    .build();
                lower_level_interface.get_transaction_logs(filter)
                    .then(move |logs| {
                        debug!(logger, "Transaction retrieval completed: {:?}", logs);
                        future::result::<RetrievedBlockchainTransactions, BlockchainError>(
                            match logs {
                                Ok(logs) => {
                                    Self::handle_transaction_logs(logger, logs, response_block_number)
                                }
                                Err(e) => Err(e),
                            },
                        )
                    })
                },
            )
        );
    }

    fn build_blockchain_agent(
        &self,
        // TODO: Change wallet to address in the future
        consuming_wallet: Wallet,
    ) -> Box<dyn Future<Item = Box<dyn BlockchainAgent>, Error = BlockchainAgentBuildError>> {
        let wallet_address = consuming_wallet.address();
        let gas_limit_const_part = self.gas_limit_const_part;
        let get_gas_price = self.lower_interface().get_gas_price();
        let get_transaction_fee_balance = self
            .lower_interface()
            .get_transaction_fee_balance(wallet_address);
        let get_service_fee_balance = self
            .lower_interface()
            .get_service_fee_balance(wallet_address);
        let get_transaction_id = self.lower_interface().get_transaction_id(wallet_address);

        Box::new(
            get_gas_price
                .map_err(BlockchainAgentBuildError::GasPrice)
                .and_then(move |gas_price_wei| {
                    get_transaction_fee_balance
                        .map_err(move |e| {
                            BlockchainAgentBuildError::TransactionFeeBalance(wallet_address, e)
                        })
                        .and_then(move |transaction_fee_balance| {
                            get_service_fee_balance
                                .map_err(move |e| {
                                    BlockchainAgentBuildError::ServiceFeeBalance(wallet_address, e)
                                })
                                .and_then(move |masq_token_balance| {
                                    get_transaction_id
                                        .map_err(move |e| {
                                            BlockchainAgentBuildError::TransactionID(
                                                wallet_address,
                                                e,
                                            )
                                        })
                                        .and_then(move |pending_transaction_id| {
                                            let blockchain_agent_future_result =
                                                BlockchainAgentFutureResult {
                                                    gas_price_wei,
                                                    transaction_fee_balance,
                                                    masq_token_balance,
                                                    pending_transaction_id,
                                                };
                                            Ok(create_blockchain_agent_web3(
                                                gas_limit_const_part,
                                                blockchain_agent_future_result,
                                                consuming_wallet,
                                            ))
                                        })
                                })
                        })
                }),
        )
    }

    fn lower_interface(&self) -> Box<dyn LowBlockchainInt> {
        Box::new(LowBlockchainIntWeb3::new(
            self.transport.clone(),
            self.contract_address(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct HashAndAmount {
    pub hash: H256,
    pub amount: u128,
}

impl BlockchainInterfaceWeb3 {
    pub fn new(transport: Http, event_loop_handle: EventLoopHandle, chain: Chain) -> Self {
        let gas_limit_const_part = Self::web3_gas_limit_const_part(chain);

        Self {
            logger: Logger::new("BlockchainInterface"),
            chain,
            gas_limit_const_part,
            _event_loop_handle: event_loop_handle,
            transport,
        }
    }

    pub fn web3_gas_limit_const_part(chain: Chain) -> u64 {
        match chain {
            Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => 55_000,
            Chain::PolyMainnet | Chain::PolyAmoy => 70_000,
        }
    }

    fn extract_transactions_from_logs(logs: Vec<Log>) -> Vec<BlockchainTransaction> {
        logs.iter()
            .filter_map(|log: &Log| match log.block_number {
                None => None,
                Some(block_number) => {
                    let wei_amount = U256::from(log.data.0.as_slice()).as_u128();
                    Some(BlockchainTransaction {
                        block_number: block_number.as_u64(),
                        from: Wallet::from(log.topics[1]),
                        wei_amount,
                    })
                }
            })
            .collect()
    }

    fn find_largest_transaction_block_number(
        response_block_number: u64,
        transactions: &[BlockchainTransaction],
    ) -> u64 {
        if transactions.is_empty() {
            response_block_number
        } else {
            transactions
                .iter()
                .fold(response_block_number, |a, b| a.max(b.block_number))
        }
    }

    fn handle_transaction_logs(
        logger: Logger,
        logs: Vec<Log>,
        response_block_number: u64,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError> {
        let logs_len = logs.len();
        if logs
            .iter()
            .any(|log| log.topics.len() < 2 || log.data.0.len() > 32)
        {
            warning!(
                logger,
                "Invalid response from blockchain server: {:?}",
                logs
            );
            Err(BlockchainError::InvalidResponse)
        } else {
            let transactions: Vec<BlockchainTransaction> =
                Self::extract_transactions_from_logs(logs);
            debug!(logger, "Retrieved transactions: {:?}", transactions);
            if transactions.is_empty() && logs_len != transactions.len() {
                warning!(
                    logger,
                    "Retrieving transactions: logs: {}, transactions: {}",
                    logs_len,
                    transactions.len()
                )
            }

            // Get the largest transaction block number, unless there are no
            // transactions, in which case use end_block, unless get_latest_block()
            // was not successful.
            let transaction_max_block_number =
                Self::find_largest_transaction_block_number(response_block_number, &transactions);
            debug!(
                logger,
                "Discovered transaction max block nbr: {}", transaction_max_block_number
            );

            Ok(RetrievedBlockchainTransactions {
                new_start_block: 1u64 + transaction_max_block_number,
                transactions,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        BlockchainInterfaceWeb3, CONTRACT_ABI, REQUESTS_IN_PARALLEL, TRANSACTION_LITERAL,
        TRANSFER_METHOD_ID,
    };
    use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
    use crate::blockchain::blockchain_interface::data_structures::BlockchainTransaction;
    use crate::blockchain::blockchain_interface::{
        BlockchainAgentBuildError, BlockchainError, BlockchainInterface,
        RetrievedBlockchainTransactions,
    };
    use crate::blockchain::blockchain_interface_utils::calculate_fallback_start_block_number;
    use crate::blockchain::test_utils::{all_chains, make_blockchain_interface_web3};
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::{make_wallet, TestRawTransaction};
    use ethsign_crypto::Keccak256;
    use futures::Future;
    use indoc::indoc;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::find_free_port;
    use serde_derive::Deserialize;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use web3::transports::Http;
    use web3::types::{BlockNumber, Bytes, TransactionParameters, H256, U256};
    use web3::Web3;

    #[test]
    fn constants_are_correct() {
        let contract_abi_expected: &str = indoc!(
            r#"[{
            "constant":true,
            "inputs":[{"name":"owner","type":"address"}],
            "name":"balanceOf",
            "outputs":[{"name":"","type":"uint256"}],
            "payable":false,
            "stateMutability":"view",
            "type":"function"
            },{
            "constant":false,
            "inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],
            "name":"transfer",
            "outputs":[{"name":"","type":"bool"}],
            "payable":false,
            "stateMutability":"nonpayable",
            "type":"function"
            }]"#
        );
        let transaction_literal_expected: H256 = H256 {
            0: [
                0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37,
                0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d,
                0xf5, 0x23, 0xb3, 0xef,
            ],
        };
        assert_eq!(CONTRACT_ABI, contract_abi_expected);
        assert_eq!(TRANSACTION_LITERAL, transaction_literal_expected);
        assert_eq!(TRANSFER_METHOD_ID, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(REQUESTS_IN_PARALLEL, 1);
    }

    #[test]
    fn blockchain_interface_web3_can_return_contract() {
        all_chains().iter().for_each(|chain| {
            let mut subject = make_blockchain_interface_web3(None);
            subject.chain = *chain;

            assert_eq!(subject.contract_address(), chain.rec().contract)
        })
    }

    #[test]
    fn blockchain_interface_web3_retrieves_transactions() {
        let to = "0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let port = find_free_port();
        #[rustfmt::skip]
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x178def", 1)
            .raw_response(
                r#"{
                "jsonrpc":"2.0",
                "id":3,
                "result":[
                    {
                        "address":"0xcd6c588e005032dd882cd43bf53a32129be81302",
                        "blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a",
                        "blockNumber":"0x4be663",
                        "data":"0x0000000000000000000000000000000000000000000000000010000000000000",
                        "logIndex":"0x0",
                        "removed":false,
                        "topics":[
                            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                            "0x0000000000000000000000003ab28ecedea6cdb6feed398e93ae8c7b316b1182",
                            "0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"
                        ],
                        "transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681",
                        "transactionIndex":"0x0"
                    },
                    {
                        "address":"0xcd6c588e005032dd882cd43bf53a32129be81302",
                        "blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732b",
                        "blockNumber":"0x4be662",
                        "data":"0x0000000000000000000000000000000000000000000000000010000000000000",
                        "logIndex":"0x0",
                        "removed":false,
                        "topics":[
                            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                            "0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc",
                            "0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"
                        ],
                        "transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0680",
                        "transactionIndex":"0x0"
                    }
                ]
            }"#.to_string()
            )
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let end_block_nbr = 1024u64;

        let result = subject
            .retrieve_transactions(
                BlockNumber::Number(42u64.into()),
                end_block_nbr,
                Wallet::from_str(&to).unwrap().address(),
            )
            .wait()
            .unwrap();

        assert_eq!(
            result,
            RetrievedBlockchainTransactions {
                new_start_block: 0x4be664,
                transactions: vec![
                    BlockchainTransaction {
                        block_number: 0x4be663,
                        from: Wallet::from_str("0x3ab28ecedea6cdb6feed398e93ae8c7b316b1182")
                            .unwrap(),
                        wei_amount: 4_503_599_627_370_496u128,
                    },
                    BlockchainTransaction {
                        block_number: 0x4be662,
                        from: Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                            .unwrap(),
                        wei_amount: 4_503_599_627_370_496u128,
                    },
                ]
            }
        )
    }

    #[test]
    fn blockchain_interface_web3_handles_no_retrieved_transactions() {
        let to_wallet = make_paying_wallet(b"test_wallet");
        let port = find_free_port();
        let empty_transactions_result: Vec<String> = vec![];
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x178def".to_string(), 2)
            .response(empty_transactions_result, 2)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let end_block_nbr = 1024u64;

        let result = subject
            .retrieve_transactions(
                BlockNumber::Number(42u64.into()),
                end_block_nbr,
                to_wallet.address(),
            )
            .wait();

        assert_eq!(
            result,
            Ok(RetrievedBlockchainTransactions {
                new_start_block: 1543664,
                transactions: vec![]
            })
        );
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_web3_retrieve_transactions_returns_an_error_if_the_to_address_is_invalid(
    ) {
        let port = find_free_port();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject
            .retrieve_transactions(
                BlockNumber::Number(42u64.into()),
                555u64,
                Wallet::new("0x3f69f9efd4f2592fd70beecd9dce71c472fc").address(),
            )
            .wait();

        assert_eq!(
            result.expect_err("Expected an Err, got Ok"),
            BlockchainError::InvalidAddress
        );
    }

    #[test]
    fn blockchain_interface_web3_retrieve_transactions_returns_an_error_if_a_response_with_too_few_topics_is_returned(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x178def", 1)
            .raw_response(r#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d63100000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject
            .retrieve_transactions(
                BlockNumber::Number(42u64.into()),
                555u64,
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        assert_eq!(
            result.expect_err("Expected an Err, got Ok"),
            BlockchainError::InvalidResponse
        );
    }

    #[test]
    fn blockchain_interface_web3_retrieve_transactions_returns_an_error_if_a_response_with_data_that_is_too_long_is_returned(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x178def", 1)
            .raw_response(r#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d6310000001","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject
            .retrieve_transactions(
                BlockNumber::Number(42u64.into()),
                555u64,
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        assert_eq!(result, Err(BlockchainError::InvalidResponse));
    }

    #[test]
    fn blockchain_interface_web3_retrieve_transactions_ignores_transaction_logs_that_have_no_block_number(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x178def", 1)
            .raw_response(r#"{"jsonrpc":"2.0","id":2,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_string())
            .start();
        init_test_logging();
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();

        let end_block_nbr = 1024u64;
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .retrieve_transactions(
                BlockNumber::Number(42u64.into()),
                end_block_nbr,
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        assert_eq!(
            result,
            Ok(RetrievedBlockchainTransactions {
                new_start_block: 1543664,
                transactions: vec![]
            })
        );
        let test_log_handler = TestLogHandler::new();
        test_log_handler.exists_log_containing(
            "WARN: BlockchainInterface: Retrieving transactions: logs: 1, transactions: 0",
        );
    }

    #[test]
    fn blockchain_interface_non_clandestine_retrieve_transactions_uses_block_number_latest_as_fallback_start_block_plus_one(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("trash", 1)
            .raw_response(r#"{"jsonrpc":"2.0","id":2,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let start_block_nbr = 42u64;
        let start_block = BlockNumber::Number(start_block_nbr.into());
        let fallback_number = calculate_fallback_start_block_number(start_block_nbr, u64::MAX);

        let result = subject
            .retrieve_transactions(
                start_block,
                fallback_number,
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        let expected_fallback_start_block = start_block_nbr + 1u64;

        assert_eq!(
            result,
            Ok(RetrievedBlockchainTransactions {
                new_start_block: 1 + expected_fallback_start_block,
                transactions: vec![]
            })
        );
    }

    #[test]
    fn blockchain_interface_web3_can_build_blockchain_agent() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            // gas_price
            .response("0x3B9ACA00".to_string(), 0) // 1000000000
            // transaction_fee_balance
            .response("0xFFF0".to_string(), 0) // 65520
            // masq_balance
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(), // 65535
                0,
            )
            // transaction_id
            .response("0x23".to_string(), 1)
            .start();
        let chain = Chain::PolyMainnet;
        let wallet = make_wallet("abc");
        let subject = make_blockchain_interface_web3(Some(port));
        let transaction_fee_balance = U256::from(65_520);
        let masq_balance = U256::from(65_535);
        let transaction_id = U256::from(35);

        let result = subject
            .build_blockchain_agent(wallet.clone())
            .wait()
            .unwrap();

        let expected_gas_price_gwei = 2;
        assert_eq!(result.consuming_wallet(), &wallet);
        assert_eq!(result.pending_transaction_id(), transaction_id);
        assert_eq!(
            result.consuming_wallet_balances(),
            ConsumingWalletBalances {
                transaction_fee_balance_in_minor_units: transaction_fee_balance,
                masq_token_balance_in_minor_units: masq_balance
            }
        );
        assert_eq!(
            result.agreed_fee_per_computation_unit(),
            expected_gas_price_gwei
        );
        let expected_fee_estimation = (3
            * (BlockchainInterfaceWeb3::web3_gas_limit_const_part(chain)
                + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)
            * expected_gas_price_gwei) as u128;
        assert_eq!(
            result.estimated_transaction_fee_total(3),
            expected_fee_estimation
        )
    }

    #[test]
    fn build_of_the_blockchain_agent_fails_on_fetching_gas_price() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let wallet = make_wallet("abc");
        let subject = make_blockchain_interface_web3(Some(port));

        let err = subject.build_blockchain_agent(wallet).wait().err().unwrap();

        let expected_err = BlockchainAgentBuildError::GasPrice(QueryFailed(
            "Transport error: Error(IncompleteMessage)".to_string(),
        ));
        assert_eq!(err, expected_err)
    }

    fn build_of_the_blockchain_agent_fails_on_blockchain_interface_error<F>(
        port: u16,
        expected_err_factory: F,
    ) where
        F: FnOnce(&Wallet) -> BlockchainAgentBuildError,
    {
        let wallet = make_wallet("bcd");
        let subject = make_blockchain_interface_web3(Some(port));
        let result = subject.build_blockchain_agent(wallet.clone()).wait();
        let err = match result {
            Err(e) => e,
            _ => panic!("we expected Err() but got Ok()"),
        };
        let expected_err = expected_err_factory(&wallet);
        assert_eq!(err, expected_err)
    }

    #[test]
    fn build_of_the_blockchain_agent_fails_on_transaction_fee_balance() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .start();
        let expected_err_factory = |wallet: &Wallet| {
            BlockchainAgentBuildError::TransactionFeeBalance(
                wallet.address(),
                BlockchainError::QueryFailed(
                    "Transport error: Error(IncompleteMessage)".to_string(),
                ),
            )
        };

        build_of_the_blockchain_agent_fails_on_blockchain_interface_error(
            port,
            expected_err_factory,
        );
    }

    #[test]
    fn build_of_the_blockchain_agent_fails_on_masq_balance() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .response("0xFFF0".to_string(), 0)
            .start();
        let expected_err_factory = |wallet: &Wallet| {
            BlockchainAgentBuildError::ServiceFeeBalance(
                wallet.address(),
                BlockchainError::QueryFailed(
                    "Api error: Transport error: Error(IncompleteMessage)".to_string(),
                ),
            )
        };

        build_of_the_blockchain_agent_fails_on_blockchain_interface_error(
            port,
            expected_err_factory,
        );
    }

    #[test]
    fn build_of_the_blockchain_agent_fails_on_transaction_id() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .response("0xFFF0".to_string(), 0)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .start();

        let expected_err_factory = |wallet: &Wallet| {
            BlockchainAgentBuildError::TransactionID(
                wallet.address(),
                BlockchainError::QueryFailed(
                    "Transport error: Error(IncompleteMessage) for wallet 0x0000…6364".to_string(),
                ),
            )
        };

        build_of_the_blockchain_agent_fails_on_blockchain_interface_error(
            port,
            expected_err_factory,
        );
    }

    #[test]
    fn web3_gas_limit_const_part_returns_reasonable_values() {
        type Subject = BlockchainInterfaceWeb3;
        assert_eq!(
            Subject::web3_gas_limit_const_part(Chain::EthMainnet),
            55_000
        );
        assert_eq!(
            Subject::web3_gas_limit_const_part(Chain::EthRopsten),
            55_000
        );
        assert_eq!(
            Subject::web3_gas_limit_const_part(Chain::PolyMainnet),
            70_000
        );
        assert_eq!(Subject::web3_gas_limit_const_part(Chain::PolyAmoy), 70_000);
        assert_eq!(Subject::web3_gas_limit_const_part(Chain::Dev), 55_000);
    }

    //an adapted test from old times when we had our own signing method
    //I don't have data for the new chains so I omit them in this kind of tests
    #[test]
    fn signs_various_transactions_for_eth_mainnet() {
        let signatures = &[
            &[
                248, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53, 53, 53, 53, 53, 53,
                53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 136, 13, 224, 182, 179, 167,
                100, 0, 0, 128, 37, 160, 40, 239, 97, 52, 11, 217, 57, 188, 33, 149, 254, 83, 117,
                103, 134, 96, 3, 225, 161, 93, 60, 113, 255, 99, 225, 89, 6, 32, 170, 99, 98, 118,
                160, 103, 203, 233, 216, 153, 127, 118, 26, 236, 183, 3, 48, 75, 56, 0, 204, 245,
                85, 201, 243, 220, 100, 33, 75, 41, 127, 177, 150, 106, 59, 109, 131,
            ][..],
            &[
                248, 106, 128, 134, 213, 86, 152, 55, 36, 49, 131, 30, 132, 128, 148, 240, 16, 159,
                200, 223, 40, 48, 39, 182, 40, 92, 200, 137, 245, 170, 98, 78, 172, 31, 85, 132,
                59, 154, 202, 0, 128, 37, 160, 9, 235, 182, 202, 5, 122, 5, 53, 214, 24, 100, 98,
                188, 11, 70, 91, 86, 28, 148, 162, 149, 189, 176, 98, 31, 193, 146, 8, 171, 20,
                154, 156, 160, 68, 15, 253, 119, 92, 233, 26, 131, 58, 180, 16, 119, 114, 4, 213,
                52, 26, 111, 159, 169, 18, 22, 166, 243, 238, 44, 5, 31, 234, 106, 4, 40,
            ][..],
            &[
                248, 117, 128, 134, 9, 24, 78, 114, 160, 0, 130, 39, 16, 128, 128, 164, 127, 116,
                101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 96, 0, 87, 38, 160, 122, 155, 12, 58, 133, 108, 183, 145, 181,
                210, 141, 44, 236, 17, 96, 40, 55, 87, 204, 250, 142, 83, 122, 168, 250, 5, 113,
                172, 203, 5, 12, 181, 160, 9, 100, 95, 141, 167, 178, 53, 101, 115, 131, 83, 172,
                199, 242, 208, 96, 246, 121, 25, 18, 211, 89, 60, 94, 165, 169, 71, 3, 176, 157,
                167, 50,
            ][..],
        ];
        assert_signature(Chain::EthMainnet, signatures)
    }

    // Adapted test from old times when we had our own signing method.
    // Don't have data for new chains, so I omit them in this kind of tests
    #[test]
    fn signs_various_transactions_for_ropsten() {
        let signatures = &[
            &[
                248, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53, 53, 53, 53, 53, 53,
                53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 136, 13, 224, 182, 179, 167,
                100, 0, 0, 128, 41, 160, 8, 220, 80, 201, 100, 41, 178, 35, 151, 227, 210, 85, 27,
                41, 27, 82, 217, 176, 64, 92, 205, 10, 195, 169, 66, 91, 213, 199, 124, 52, 3, 192,
                160, 94, 220, 102, 179, 128, 78, 150, 78, 230, 117, 10, 10, 32, 108, 241, 50, 19,
                148, 198, 6, 147, 110, 175, 70, 157, 72, 31, 216, 193, 229, 151, 115,
            ][..],
            &[
                248, 106, 128, 134, 213, 86, 152, 55, 36, 49, 131, 30, 132, 128, 148, 240, 16, 159,
                200, 223, 40, 48, 39, 182, 40, 92, 200, 137, 245, 170, 98, 78, 172, 31, 85, 132,
                59, 154, 202, 0, 128, 41, 160, 186, 65, 161, 205, 173, 93, 185, 43, 220, 161, 63,
                65, 19, 229, 65, 186, 247, 197, 132, 141, 184, 196, 6, 117, 225, 181, 8, 81, 198,
                102, 150, 198, 160, 112, 126, 42, 201, 234, 236, 168, 183, 30, 214, 145, 115, 201,
                45, 191, 46, 3, 113, 53, 80, 203, 164, 210, 112, 42, 182, 136, 223, 125, 232, 21,
                205,
            ][..],
            &[
                248, 117, 128, 134, 9, 24, 78, 114, 160, 0, 130, 39, 16, 128, 128, 164, 127, 116,
                101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 96, 0, 87, 41, 160, 146, 204, 57, 32, 218, 236, 59, 94, 106, 72,
                174, 211, 223, 160, 122, 186, 126, 44, 200, 41, 222, 117, 117, 177, 189, 78, 203,
                8, 172, 155, 219, 66, 160, 83, 82, 37, 6, 243, 61, 188, 102, 176, 132, 102, 74,
                111, 180, 105, 33, 122, 106, 109, 73, 180, 65, 10, 117, 175, 190, 19, 196, 17, 128,
                193, 75,
            ][..],
        ];
        assert_signature(Chain::EthRopsten, signatures)
    }

    #[derive(Deserialize)]
    struct Signing {
        signed: Vec<u8>,
        private_key: H256,
    }

    fn assert_signature(chain: Chain, slice_of_slices: &[&[u8]]) {
        let first_part_tx_1 = r#"[{"nonce": "0x9", "gasPrice": "0x4a817c800", "gasLimit": "0x5208", "to": "0x3535353535353535353535353535353535353535", "value": "0xde0b6b3a7640000", "data": []}, {"private_key": "0x4646464646464646464646464646464646464646464646464646464646464646", "signed": "#;
        let first_part_tx_2 = r#"[{"nonce": "0x0", "gasPrice": "0xd55698372431", "gasLimit": "0x1e8480", "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", "value": "0x3b9aca00", "data": []}, {"private_key": "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", "signed": "#;
        let first_part_tx_3 = r#"[{"nonce": "0x00", "gasPrice": "0x09184e72a000", "gasLimit": "0x2710", "to": null, "value": "0x00", "data": [127,116,101,115,116,50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,87]}, {"private_key": "0xe331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109", "signed": "#;
        fn compose(first_part: &str, slice: &[u8]) -> String {
            let third_part_jrc = "}]";
            format!("{}{:?}{}", first_part, slice, third_part_jrc)
        }
        let all_transactions = format!(
            "[{}]",
            vec![first_part_tx_1, first_part_tx_2, first_part_tx_3]
                .iter()
                .zip(slice_of_slices.iter())
                .zip(0usize..2)
                .fold(String::new(), |so_far, actual| [
                    so_far,
                    compose(actual.0 .0, actual.0 .1)
                ]
                .join(if actual.1 == 0 { "" } else { ", " }))
        );
        let txs: Vec<(TestRawTransaction, Signing)> =
            serde_json::from_str(&all_transactions).unwrap();
        let constant_parts = &[
            &[
                248u8, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53, 53, 53, 53, 53,
                53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 136, 13, 224, 182, 179,
                167, 100, 0, 0, 128,
            ][..],
            &[
                248, 106, 128, 134, 213, 86, 152, 55, 36, 49, 131, 30, 132, 128, 148, 240, 16, 159,
                200, 223, 40, 48, 39, 182, 40, 92, 200, 137, 245, 170, 98, 78, 172, 31, 85, 132,
                59, 154, 202, 0, 128,
            ][..],
            &[
                248, 117, 128, 134, 9, 24, 78, 114, 160, 0, 130, 39, 16, 128, 128, 164, 127, 116,
                101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 96, 0, 87,
            ][..],
        ];

        let subject = make_blockchain_interface_web3(None);
        let lengths_of_constant_parts: Vec<usize> =
            constant_parts.iter().map(|part| part.len()).collect();
        for (((tx, signed), length), constant_part) in txs
            .iter()
            .zip(lengths_of_constant_parts)
            .zip(constant_parts)
        {
            let secret = Wallet::from(
                Bip32EncryptionKeyProvider::from_raw_secret(&signed.private_key.0.as_ref())
                    .unwrap(),
            )
            .prepare_secp256k1_secret()
            .unwrap();
            let tx_params = from_raw_transaction_to_transaction_parameters(tx, chain);
            let web3 = Web3::new(subject.transport.clone());
            let sign = web3
                .accounts()
                .sign_transaction(tx_params, &secret)
                .wait()
                .unwrap();
            let signed_data_bytes = sign.raw_transaction.0;
            assert_eq!(signed_data_bytes, signed.signed);
            assert_eq!(signed_data_bytes[..length], **constant_part)
        }
    }

    fn from_raw_transaction_to_transaction_parameters(
        raw_transaction: &TestRawTransaction,
        chain: Chain,
    ) -> TransactionParameters {
        TransactionParameters {
            nonce: Some(raw_transaction.nonce),
            to: raw_transaction.to,
            gas: raw_transaction.gas_limit,
            gas_price: Some(raw_transaction.gas_price),
            value: raw_transaction.value,
            data: Bytes(raw_transaction.data.clone()),
            chain_id: Some(chain.rec().num_chain_id),
        }
    }

    #[test]
    fn hash_the_smart_contract_transfer_function_signature() {
        assert_eq!(
            "transfer(address,uint256)".keccak256()[0..4],
            TRANSFER_METHOD_ID,
        );
    }
}
