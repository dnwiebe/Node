// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::CONTRACT_ABI;
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
use crate::blockchain::blockchain_interface::data_structures::errors::{
    BlockchainError, PayableTransactionError,
};
use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible;
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::blockchain::blockchain_interface_utils::{
    convert_wei_to_gwei, send_payables_within_batch,
};
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use ethereum_types::{H256, U256, U64};
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use web3::contract::{Contract, Options};
use web3::transports::{Batch, Http};
use web3::types::{Address, BlockNumber, Filter, Log, TransactionReceipt};
use web3::Web3;

#[derive(Debug, PartialEq, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum TransactionReceiptResult {
    NotPresent,
    Found(TransactionReceipt),
    Error(String),
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

    fn get_transaction_receipt(
        &self,
        hash: H256,
    ) -> Box<dyn Future<Item = Option<TransactionReceipt>, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .transaction_receipt(hash)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_transaction_receipt_batch(
        &self,
        hash_vec: Vec<H256>,
    ) -> Box<dyn Future<Item = Vec<TransactionReceiptResult>, Error = BlockchainError>> {
        let _ = hash_vec.into_iter().map(|hash| {
            self.web3_batch.eth().transaction_receipt(hash);
        });
        Box::new(
            self.web3_batch
                .transport()
                .submit_batch()
                .map_err(|e| QueryFailed(e.to_string()))
                .and_then(move |batch_response| {
                    Ok(batch_response
                        .into_iter()
                        .map(|response| match response {
                            Ok(result) => {
                                match serde_json::from_value::<TransactionReceipt>(result) {
                                    Ok(receipt) => TransactionReceiptResult::Found(receipt),
                                    Err(e) => {
                                        if e.to_string().contains("invalid type: null") {
                                            TransactionReceiptResult::NotPresent
                                        } else {
                                            TransactionReceiptResult::Error(e.to_string())
                                        }
                                    }
                                }
                            }
                            Err(e) => TransactionReceiptResult::Error(e.to_string()),
                        })
                        .collect::<Vec<TransactionReceiptResult>>())
                }),
        )
    }

    fn get_contract(&self) -> Contract<Http> {
        self.contract.clone()
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

    fn submit_payables_in_batch(
        &self,
        logger: Logger,
        chain: Chain,
        consuming_wallet: Wallet,
        fingerprints_recipient: Recipient<PendingPayableFingerprintSeeds>,
        affordable_accounts: Vec<PayableAccount>,
    ) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError>>
    {
        let web3_batch = self.web3_batch.clone();
        let get_transaction_id = self.get_transaction_id(consuming_wallet.address());
        let get_gas_price = self.get_gas_price();

        Box::new(
            get_transaction_id
                .map_err(PayableTransactionError::TransactionID)
                .and_then(move |pending_nonce| {
                    get_gas_price
                        .map_err(PayableTransactionError::GasPriceQueryFailed)
                        .and_then(move |gas_price_wei| {
                            let gas_price = convert_wei_to_gwei(gas_price_wei);
                            send_payables_within_batch(
                                logger,
                                chain,
                                web3_batch,
                                consuming_wallet,
                                gas_price,
                                pending_nonce,
                                fingerprints_recipient,
                                affordable_accounts,
                            )
                        })
                }),
        )
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
    use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
    use crate::sub_lib::wallet::Wallet;
    use masq_lib::utils::find_free_port;
    use std::str::FromStr;
    use ethereum_types::{H256, U64};
    use futures::Future;
    use web3::types::{BlockNumber, Bytes, FilterBuilder, H2048, Log, TransactionReceipt, U256};
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::TRANSACTION_LITERAL;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionReceiptResult;
    use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
    use crate::blockchain::test_utils::{make_blockchain_interface_web3, make_tx_hash, ReceiptResponseBuilder};
    use crate::test_utils::{assert_string_contains, make_wallet};

    #[test]
    fn get_transaction_fee_balance_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let subject = make_blockchain_interface_web3(Some(port));

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
        let subject = make_blockchain_interface_web3(Some(port));

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
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_gas_price().wait().unwrap();

        assert_eq!(result, 1.into());
    }

    #[test]
    fn get_gas_price_returns_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let subject = make_blockchain_interface_web3(Some(port));

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
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_block_number().wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_block_number_returns_an_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("trash".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

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
        let subject = make_blockchain_interface_web3(Some(port));
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
        let subject = make_blockchain_interface_web3(Some(port));

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
        let subject = make_blockchain_interface_web3(Some(port));

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
        let subject = make_blockchain_interface_web3(Some(port));

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
    fn transaction_receipt_works() {
        let port = find_free_port();
        let tx_hash =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e")
                .unwrap();
        let block_hash =
            H256::from_str("6d0abccae617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18")
                .unwrap();
        let block_number = U64::from_str("b0328d").unwrap();
        let cumulative_gas_used = U256::from_str("60ef").unwrap();
        let gas_used = U256::from_str("60ef").unwrap();
        let status = U64::from(0);
        let tx_receipt_response = ReceiptResponseBuilder::default()
            .transaction_hash(tx_hash)
            .block_hash(block_hash)
            .block_number(block_number)
            .cumulative_gas_used(cumulative_gas_used)
            .gas_used(gas_used)
            .status(status)
            .build();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .raw_response(tx_receipt_response)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject
            .lower_interface()
            .get_transaction_receipt(tx_hash)
            .wait();

        let expected_receipt = TransactionReceipt {
            transaction_hash: tx_hash,
            transaction_index: Default::default(),
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            cumulative_gas_used,
            gas_used: Some(gas_used),
            contract_address: None,
            logs: vec![],
            status: Some(status),
            root: None,
            logs_bloom: Default::default(),
        };
        assert_eq!(result, Ok(Some(expected_receipt)));
    }

    #[test]
    fn get_transaction_receipt_handles_errors() {
        let port = find_free_port();
        let subject = make_blockchain_interface_web3(Some(port));
        let tx_hash = make_tx_hash(4564546);

        let actual_error = subject
            .lower_interface()
            .get_transaction_receipt(tx_hash)
            .wait()
            .unwrap_err();
        let error_message = if let BlockchainError::QueryFailed(em) = actual_error {
            em
        } else {
            panic!("Expected BlockchainError::QueryFailed(msg)");
        };
        assert_string_contains(
            error_message.as_str(),
            "Transport error: Error(Connect, Os { code: ",
        );
        assert_string_contains(
            error_message.as_str(),
            ", kind: ConnectionRefused, message: ",
        );
    }

    #[test]
    fn transaction_receipt_batch_works() {
        let port = find_free_port();
        let tx_hash_1 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e")
                .unwrap();
        let tx_hash_2 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0f")
                .unwrap();
        let tx_hash_3 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0a")
                .unwrap();
        let tx_hash_4 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0b")
                .unwrap();
        let tx_hash_vec = vec![tx_hash_1, tx_hash_2, tx_hash_3, tx_hash_4];
        let block_hash =
            H256::from_str("6d0abccae617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18")
                .unwrap();
        let block_number = U64::from_str("b0328d").unwrap();
        let cumulative_gas_used = U256::from_str("60ef").unwrap();
        let gas_used = U256::from_str("60ef").unwrap();
        let status = U64::from(0);
        let logs_bloom = H2048::from_str("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000").unwrap();
        let tx_receipt_response = ReceiptResponseBuilder::default()
            .transaction_hash(tx_hash_1)
            .block_hash(block_hash)
            .block_number(block_number)
            .cumulative_gas_used(cumulative_gas_used)
            .gas_used(gas_used)
            .status(status)
            .logs_bloom(logs_bloom)
            .build();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .raw_response(tx_receipt_response)
            .response("trash".to_string(), 0)
            .end_batch()
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject
            .lower_interface()
            .get_transaction_receipt_batch(tx_hash_vec)
            .wait()
            .unwrap();

        assert_eq!(result[0], TransactionReceiptResult::Error("RPC error: Error { code: ServerError(429), message: \"The requests per second (RPS) of your requests are higher than your plan allows.\", data: None }".to_string()));
        assert_eq!(result[1], TransactionReceiptResult::NotPresent);
        assert_eq!(
            result[2],
            TransactionReceiptResult::Found(TransactionReceipt {
                transaction_hash: tx_hash_1,
                transaction_index: Default::default(),
                block_hash: Some(block_hash),
                block_number: Some(block_number),
                cumulative_gas_used,
                gas_used: Some(gas_used),
                contract_address: None,
                logs: vec![],
                status: Some(status),
                root: None,
                logs_bloom
            })
        );
        assert_eq!(
            result[3],
            TransactionReceiptResult::Error(
                "invalid type: string \"trash\", expected struct Receipt".to_string()
            )
        );
    }

    #[test]
    fn transaction_receipt_batch_fails_on_submit_batch() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let subject = make_blockchain_interface_web3(Some(port));
        let tx_hash_1 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e")
                .unwrap();
        let tx_hash_2 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0f")
                .unwrap();
        let tx_hash_vec = vec![tx_hash_1, tx_hash_2];

        let result = subject
            .lower_interface()
            .get_transaction_receipt_batch(tx_hash_vec)
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
        let subject = make_blockchain_interface_web3(Some(port));
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
        let subject = make_blockchain_interface_web3(Some(port));
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
