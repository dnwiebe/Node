// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::blockchain_interface_web3::CONTRACT_ABI;
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError;
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use ethereum_types::{H256, U256, U64};
use futures::Future;
use serde_json::Value;
use web3::contract::{Contract, Options};
use web3::transports::{Batch, Http};
use web3::types::{Address, BlockNumber, Filter, Log, TransactionReceipt};
use web3::{Error, Web3};

#[derive(Debug, PartialEq, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum TransactionReceiptResult {
    NotPresent,
    Found(TransactionReceipt),
    TransactionFailed(TransactionReceipt), // RemoteFailure
    Error(String),                         // LocalFailure
}

pub struct LowBlockchainIntWeb3 {
    web3: Web3<Http>,
    web3_batch: Web3<Batch<Http>>,
    contract: Contract<Http>,
    // TODO waiting for GH-707 (note: consider to query the balances together with the id)
}

impl LowBlockchainInt for LowBlockchainIntWeb3 {
    fn get_transaction_fee_balance(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .balance(address, None)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_service_fee_balance(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.contract
                .query("balanceOf", address, None, Options::default(), None)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_gas_price(&self) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .gas_price()
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_block_number(&self) -> Box<dyn Future<Item = U64, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .block_number()
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_transaction_id(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .transaction_count(address, Some(BlockNumber::Pending))
                .map_err(move |e| QueryFailed(format!("{} for wallet {}", e, address))),
        )
    }

    fn get_transaction_receipt_in_batch(
        &self,
        hash_vec: Vec<H256>,
    ) -> Box<dyn Future<Item = Vec<Result<Value, Error>>, Error = BlockchainError>> {
        let _ = hash_vec.into_iter().map(|hash| {
            self.web3_batch.eth().transaction_receipt(hash);
        });
        Box::new(
            self.web3_batch
                .transport()
                .submit_batch()
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_contract_address(&self) -> Address {
        self.contract.address()
    }

    fn get_transaction_logs(
        &self,
        filter: Filter,
    ) -> Box<dyn Future<Item = Vec<Log>, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .logs(filter)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_web3_batch(&self) -> Web3<Batch<Http>> {
        self.web3_batch.clone()
    }
}

impl LowBlockchainIntWeb3 {
    pub fn new(transport: Http, contract_address: Address) -> Self {
        let web3 = Web3::new(transport.clone());
        let web3_batch = Web3::new(Batch::new(transport));
        let contract = Contract::from_json(web3.eth(), contract_address, CONTRACT_ABI.as_bytes())
            .expect("Unable to initialize contract.");

        Self {
            web3,
            web3_batch,
            contract,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::TRANSACTION_LITERAL;
    use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
    use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
    use crate::blockchain::test_utils::make_blockchain_interface_web3;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use ethereum_types::{H256, U64};
    use futures::Future;
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::utils::find_free_port;
    use std::str::FromStr;
    use web3::types::{BlockNumber, Bytes, FilterBuilder, Log, U256};

    #[test]
    fn get_transaction_fee_balance_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_transaction_fee_balance(wallet.address())
            .wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_transaction_fee_balance_returns_an_error_for_unintelligible_response_to_requesting_eth_balance(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xFFFQ".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_transaction_fee_balance(
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        match result {
            Err(BlockchainError::QueryFailed(msg)) if msg.contains("invalid hex character: Q") => {
                ()
            }
            x => panic!("Expected complaint about hex character, but got {:?}", x),
        };
    }

    #[test]
    fn get_gas_price_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x01".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject.lower_interface().get_gas_price().wait().unwrap();

        assert_eq!(result, 1.into());
    }

    #[test]
    fn get_gas_price_returns_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let subject = make_blockchain_interface_web3(port);

        let error = subject
            .lower_interface()
            .get_gas_price()
            .wait()
            .unwrap_err();

        assert_eq!(
            error,
            QueryFailed("Transport error: Error(IncompleteMessage)".to_string())
        );
    }

    #[test]
    fn get_block_number_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject.lower_interface().get_block_number().wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_block_number_returns_an_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("trash".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let error = subject
            .lower_interface()
            .get_block_number()
            .wait()
            .unwrap_err();

        assert_eq!(
            error,
            QueryFailed(
                "Decoder error: Error(\"0x prefix is missing\", line: 0, column: 0)".to_string()
            )
        );
    }

    #[test]
    fn get_transaction_id_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(port);
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();

        let result = subject
            .lower_interface()
            .get_transaction_id(wallet.address())
            .wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_transaction_id_returns_an_error_for_unintelligible_response() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xFFFQ".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_transaction_id(
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        match result {
            Err(BlockchainError::QueryFailed(msg)) if msg.contains("invalid hex character: Q") => {
                ()
            }
            x => panic!("Expected complaint about hex character, but got {:?}", x),
        };
    }

    #[test]
    fn get_token_balance_can_retrieve_token_balance_of_a_wallet() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_service_fee_balance(
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait()
            .unwrap();

        assert_eq!(result, U256::from(65_535));
    }

    #[test]
    fn get_token_balance_returns_error_for_unintelligible_response_to_token_balance() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFQ".to_string(),
                0,
            )
            .start();
        let expected_err_msg = "Invalid hex";
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_service_fee_balance(
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        let err_msg = match result {
            Err(BlockchainError::QueryFailed(msg)) => msg,
            x => panic!("Expected BlockchainError::QueryFailed, but got {:?}", x),
        };
        assert!(
            err_msg.contains(expected_err_msg),
            "Expected this fragment {} in this err msg: {}",
            expected_err_msg,
            err_msg
        )
    }

    #[test]
    fn transaction_receipt_batch_fails_on_submit_batch() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let subject = make_blockchain_interface_web3(port);
        let tx_hash_1 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e")
                .unwrap();
        let tx_hash_2 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0f")
                .unwrap();
        let tx_hash_vec = vec![tx_hash_1, tx_hash_2];

        let result = subject
            .lower_interface()
            .get_transaction_receipt_in_batch(tx_hash_vec)
            .wait()
            .unwrap_err();

        assert_eq!(
            result,
            BlockchainError::QueryFailed("Transport error: Error(IncompleteMessage)".to_string())
        );
    }

    #[test]
    fn get_transaction_logs_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .raw_response(r#"{
              "jsonrpc": "2.0",
              "id": 1,
              "result": [
                {
                  "address": "0x0000000000000000000000000070617965655f31",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000003e3310720058c51f0de456e273c626cdd3",
                  "logIndex": "0x1d",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80"
                  ],
                  "transactionHash": "0x3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50",
                  "transactionIndex": "0x1d"
                },
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000003e3310720058c51f0de456e273c626cdd3",
                  "logIndex": "0x57",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80"
                  ],
                  "transactionHash": "0x788b1442414cb9c9a36dba2abe250763161a6f6395788a2e808f1b34e92beec1",
                  "transactionIndex": "0x54"
                }
              ]
            }"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(port);
        let contract_address = subject.chain.rec().contract;
        let start_block = BlockNumber::Number(U64::from(100));
        let response_block_number = BlockNumber::Number(U64::from(200));
        let recipient = make_wallet("test_wallet").address();
        let filter = FilterBuilder::default()
            .address(vec![contract_address])
            .from_block(start_block)
            .to_block(response_block_number)
            .topics(
                Some(vec![TRANSACTION_LITERAL]),
                None,
                Some(vec![recipient.into()]),
                None,
            )
            .build();

        let result = subject
            .lower_interface()
            .get_transaction_logs(filter)
            .wait()
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            Log {
                address: make_wallet("payee_1").address(),
                topics: vec![H256::from_str(
                    "241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80"
                )
                .unwrap()],
                data: Bytes(vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 51, 16, 114, 0, 88, 197, 31, 13, 228,
                    86, 226, 115, 198, 38, 205, 211
                ]),
                block_hash: Some(
                    H256::from_str(
                        "7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70"
                    )
                    .unwrap()
                ),
                block_number: Some(U64::from(6040059)),
                transaction_hash: Some(
                    H256::from_str(
                        "3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50"
                    )
                    .unwrap()
                ),
                transaction_index: Some(U64::from(29)),
                log_index: Some(U256::from(29)),
                transaction_log_index: None,
                log_type: None,
                removed: Some(false),
            }
        );
    }

    #[test]
    fn get_transaction_logs_fails() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .raw_response(r#"{
              "jsonrpc": "2.0",
              "id": 1,
              "result": [
                {
                  "address": "0x0000000000000000000000000070617965655f31",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000003e331",
                  "logIndex": "0x1d",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80"
                  ],
                  "transactionHash": "0x3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50",
                  "transactionIndex": "0x1d"
                }
              ]
            }"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(port);
        let contract_address = subject.chain.rec().contract;
        let start_block = BlockNumber::Number(U64::from(100));
        let response_block_number = BlockNumber::Number(U64::from(200));
        let recipient = make_wallet("test_wallet").address();
        let filter = FilterBuilder::default()
            .address(vec![contract_address])
            .from_block(start_block)
            .to_block(response_block_number)
            .topics(
                Some(vec![TRANSACTION_LITERAL]),
                None,
                Some(vec![recipient.into()]),
                None,
            )
            .build();

        let result = subject
            .lower_interface()
            .get_transaction_logs(filter)
            .wait()
            .unwrap_err();

        assert_eq!(
            result,
            QueryFailed(
                "Decoder error: Error(\"Invalid hex: Invalid input length\", line: 0, column: 0)"
                    .to_string()
            )
        );
    }
}
