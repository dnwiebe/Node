// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::BlockchainAgentWeb3;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    to_wei, BlockchainInterfaceWeb3, HashAndAmount, TRANSFER_METHOD_ID,
};
use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError;
use crate::blockchain::blockchain_interface::data_structures::{
    ProcessedPayableFallible, RpcPayableFailure,
};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use secp256k1secrets::SecretKey;
use serde_json::Value;
use std::iter::once;
use std::time::SystemTime;
use thousands::Separable;
use web3::transports::{Batch, Http};
use web3::types::{Bytes, SignedTransaction, TransactionParameters, H256, U256};
use web3::Error as Web3Error;
use web3::Web3;

const GWEI_UNIT: u64 = 1_000_000_000; // 1 Gwei = 1e9 Wei

#[derive(Debug)]
pub struct BlockchainAgentFutureResult {
    pub gas_price_wei: U256,
    pub transaction_fee_balance: U256,
    pub masq_token_balance: U256,
    pub pending_transaction_id: U256,
}
pub fn advance_used_nonce(current_nonce: U256) -> U256 {
    current_nonce
        .checked_add(U256::one())
        .expect("unexpected limits")
}

fn error_with_hashes(
    error: Web3Error,
    hashes_and_paid_amounts: Vec<HashAndAmount>,
) -> PayableTransactionError {
    let hashes = hashes_and_paid_amounts
        .into_iter()
        .map(|hash_and_amount| hash_and_amount.hash)
        .collect();
    PayableTransactionError::Sending {
        msg: error.to_string(),
        hashes,
    }
}

pub fn merged_output_data(
    responses: Vec<web3::transports::Result<Value>>,
    hashes_and_paid_amounts: Vec<HashAndAmount>,
    accounts: Vec<PayableAccount>,
) -> Vec<ProcessedPayableFallible> {
    let iterator_with_all_data = responses
        .into_iter()
        .zip(hashes_and_paid_amounts.into_iter())
        .zip(accounts.iter());
    iterator_with_all_data
        .map(
            |((rpc_result, hash_and_amount), account)| match rpc_result {
                Ok(_rpc_result) => {
                    // TODO: This rpc_result should be validated
                    ProcessedPayableFallible::Correct(PendingPayable {
                        recipient_wallet: account.wallet.clone(),
                        hash: hash_and_amount.hash,
                    })
                }
                Err(rpc_error) => ProcessedPayableFallible::Failed(RpcPayableFailure {
                    rpc_error,
                    recipient_wallet: account.wallet.clone(),
                    hash: hash_and_amount.hash,
                }),
            },
        )
        .collect()
}

pub fn transmission_log(chain: Chain, accounts: &[PayableAccount], gas_price: u64) -> String {
    let chain_name = chain
        .rec()
        .literal_identifier
        .chars()
        .skip_while(|char| char != &'-')
        .skip(1)
        .collect::<String>();
    let introduction = once(format!(
        "\
        Paying to creditors...\n\
        Transactions in the batch:\n\
        \n\
        gas price:                                   {} gwei\n\
        chain:                                       {}\n\
        \n\
        [wallet address]                             [payment in wei]\n",
        gas_price, chain_name
    ));
    let body = accounts.iter().map(|account| {
        format!(
            "{}   {}\n",
            account.wallet,
            account.balance_wei.separate_with_commas()
        )
    });
    introduction.chain(body).collect()
}

pub fn sign_transaction_data(amount: u128, recipient_wallet: Wallet) -> [u8; 68] {
    let mut data = [0u8; 4 + 32 + 32];
    data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
    data[16..36].copy_from_slice(&recipient_wallet.address().0[..]);
    U256::from(amount).to_big_endian(&mut data[36..68]);
    data
}

pub fn gas_limit(data: [u8; 68], chain: Chain) -> U256 {
    let base_gas_limit = BlockchainInterfaceWeb3::web3_gas_limit_const_part(chain);
    let gas_limit = ethereum_types::U256::try_from(data.iter().fold(base_gas_limit, |acc, v| {
        acc + if v == &0u8 { 4 } else { 68 }
    }))
    .expect("Internal error");
    gas_limit
}

pub fn sign_transaction(
    chain: Chain,
    web3_batch: Web3<Batch<Http>>,
    recipient_wallet: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price_in_gwei: u64,
) -> SignedTransaction {
    let data = sign_transaction_data(amount, recipient_wallet);
    let gas_limit = gas_limit(data, chain);
    let gas_price_in_wei = to_wei(gas_price_in_gwei);
    // If you flip gas_price or nonce to None this function will start making RPC calls (Do it at your own risk).
    let transaction_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(chain.rec().contract),
        gas: gas_limit,
        gas_price: Some(gas_price_in_wei),
        value: ethereum_types::U256::zero(),
        data: Bytes(data.to_vec()),
        chain_id: Some(chain.rec().num_chain_id),
    };
    let key = consuming_wallet
        .prepare_secp256k1_secret()
        .expect("Consuming wallet doesnt contain a secret key");

    sign_transaction_locally(web3_batch, transaction_parameters, &key)
}

pub fn sign_transaction_locally(
    web3_batch: Web3<Batch<Http>>,
    transaction_parameters: TransactionParameters,
    key: &SecretKey,
) -> SignedTransaction {
    if transaction_parameters.nonce.is_none()
        || transaction_parameters.chain_id.is_none()
        || transaction_parameters.gas_price.is_none()
    {
        panic!("Signing should be done locally");
    }

    // This wait call doesn't actually make any RPC call and signing is done locally.
    web3_batch
        .accounts()
        .sign_transaction(transaction_parameters, key)
        .wait()
        .expect("Web call wasn't allowed")
}

pub fn handle_new_transaction(
    chain: Chain,
    web3_batch: Web3<Batch<Http>>,
    recipient_wallet: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price: u64,
) -> H256 {
    let signed_tx = sign_transaction(
        chain,
        web3_batch.clone(),
        recipient_wallet,
        consuming_wallet,
        amount,
        nonce,
        gas_price,
    );
    append_signed_transaction_to_batch(web3_batch, signed_tx.raw_transaction);
    signed_tx.transaction_hash
}

pub fn append_signed_transaction_to_batch(web3_batch: Web3<Batch<Http>>, raw_transaction: Bytes) {
    // This function only prepares a raw transaction for a batch call and doesn't actually send it right here.
    web3_batch.eth().send_raw_transaction(raw_transaction);
}

pub fn sign_and_append_payment(
    chain: Chain,
    web3_batch: Web3<Batch<Http>>,
    consuming_wallet: Wallet,
    nonce: U256,
    gas_price: u64,
    account: PayableAccount,
) -> HashAndAmount {
    let hash = handle_new_transaction(
        chain,
        web3_batch,
        account.wallet.clone(),
        consuming_wallet,
        account.balance_wei,
        nonce,
        gas_price,
    );
    HashAndAmount {
        hash,
        amount: account.balance_wei,
    }
}

pub fn sign_and_append_multiple_payments(
    logger: Logger,
    chain: Chain,
    web3_batch: Web3<Batch<Http>>,
    consuming_wallet: Wallet,
    gas_price: u64,
    mut pending_nonce: U256,
    accounts: Vec<PayableAccount>,
) -> Vec<HashAndAmount> {
    let mut hash_and_amount_list = vec![];
    accounts.into_iter().for_each(|payable| {
        debug!(
            logger,
            "Preparing payable future of {} wei to {} with nonce {}",
            payable.balance_wei.separate_with_commas(),
            payable.wallet,
            pending_nonce
        );

        let hash_and_amount = sign_and_append_payment(
            chain,
            web3_batch.clone(),
            consuming_wallet.clone(),
            pending_nonce,
            gas_price,
            payable,
        );

        pending_nonce = advance_used_nonce(pending_nonce);
        hash_and_amount_list.push(hash_and_amount);
    });
    hash_and_amount_list
}

#[allow(clippy::too_many_arguments)]
pub fn send_payables_within_batch(
    logger: Logger,
    chain: Chain,
    web3_batch: Web3<Batch<Http>>,
    consuming_wallet: Wallet,
    gas_price_in_gwei: u64,
    pending_nonce: U256,
    new_fingerprints_recipient: Recipient<PendingPayableFingerprintSeeds>,
    accounts: Vec<PayableAccount>,
) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError> + 'static>
{
    debug!(
            logger,
            "Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}, gas_price: {}",
            consuming_wallet,
            chain.rec().contract,
            chain.rec().num_chain_id,
            gas_price_in_gwei
        );

    let hashes_and_paid_amounts = sign_and_append_multiple_payments(
        logger.clone(),
        chain,
        web3_batch.clone(),
        consuming_wallet,
        gas_price_in_gwei,
        pending_nonce,
        accounts.clone(),
    );

    let timestamp = SystemTime::now();
    let hashes_and_paid_amounts_error = hashes_and_paid_amounts.clone();
    let hashes_and_paid_amounts_ok = hashes_and_paid_amounts.clone();

    // TODO: We are sending hashes_and_paid_amounts to the Accountant even if the payments fail.
    new_fingerprints_recipient
        .try_send(PendingPayableFingerprintSeeds {
            batch_wide_timestamp: timestamp,
            hashes_and_balances: hashes_and_paid_amounts,
        })
        .expect("Accountant is dead");

    info!(
        logger,
        "{}",
        transmission_log(chain, &accounts, gas_price_in_gwei)
    );

    return Box::new(
        web3_batch
            .transport()
            .submit_batch()
            .map_err(|e| error_with_hashes(e, hashes_and_paid_amounts_error))
            .and_then(move |batch_response| {
                Ok(merged_output_data(
                    batch_response,
                    hashes_and_paid_amounts_ok,
                    accounts,
                ))
            }),
    );
}

pub fn calculate_fallback_start_block_number(start_block_number: u64, max_block_count: u64) -> u64 {
    if max_block_count == u64::MAX {
        start_block_number + 1u64
    } else {
        start_block_number + max_block_count
    }
}

pub fn convert_wei_to_gwei(wei: U256) -> u64 {
    (wei / U256::from(GWEI_UNIT)).as_u64() + 1
}

pub fn create_blockchain_agent_web3(
    gas_limit_const_part: u64,
    blockchain_agent_future_result: BlockchainAgentFutureResult,
    wallet: Wallet,
) -> Box<dyn BlockchainAgent> {
    Box::new(BlockchainAgentWeb3::new(
        convert_wei_to_gwei(blockchain_agent_future_result.gas_price_wei),
        gas_limit_const_part,
        wallet,
        ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: blockchain_agent_future_result
                .transaction_fee_balance,
            masq_token_balance_in_minor_units: blockchain_agent_future_result.masq_token_balance,
        },
        blockchain_agent_future_result.pending_transaction_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::utils::from_time_t;
    use crate::accountant::gwei_to_wei;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
    use crate::accountant::test_utils::{
        make_payable_account, make_payable_account_with_wallet_and_balance_and_timestamp_opt,
    };
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
    };
    use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError::Sending;
    use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible::{
        Correct, Failed,
    };
    use crate::blockchain::test_utils::{
        make_tx_hash, transport_error_code, transport_error_message,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::unshared_test_utils::decode_hex;
    use actix::{Actor, System};
    use ethabi::Address;
    use jsonrpc_core::ErrorCode::ServerError;
    use jsonrpc_core::{Error, ErrorCode};
    use masq_lib::constants::{DEFAULT_CHAIN, DEFAULT_GAS_PRICE};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::find_free_port;
    use serde_json::Value;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::SystemTime;
    use web3::api::Namespace;
    use web3::Error::Rpc;

    #[test]
    fn calculate_fallback_start_block_number_works() {
        assert_eq!(
            calculate_fallback_start_block_number(10_000, u64::MAX),
            10_000 + 1
        );
        assert_eq!(
            calculate_fallback_start_block_number(5_000, 10_000),
            5_000 + 10_000
        );
    }

    #[test]
    fn append_signed_transaction_to_batch_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .response(
                "0x8290c22bd9b4d61bc57222698799edd7bbc8df5214be44e239a95f679249c59c".to_string(),
                7,
            )
            .end_batch()
            .start();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let pending_nonce = 1;
        let chain = TEST_DEFAULT_CHAIN;
        let gas_price = DEFAULT_GAS_PRICE;
        let consuming_wallet = make_paying_wallet(b"paying_wallet");
        let account = make_payable_account(1);
        let signed_transaction = sign_transaction(
            chain,
            web3_batch.clone(),
            account.wallet,
            consuming_wallet,
            account.balance_wei,
            pending_nonce.into(),
            gas_price,
        );

        append_signed_transaction_to_batch(web3_batch.clone(), signed_transaction.raw_transaction);

        let mut batch_result = web3_batch.eth().transport().submit_batch().wait().unwrap();
        let result = batch_result.pop().unwrap().unwrap();
        assert_eq!(
            result,
            Value::String(
                "0x8290c22bd9b4d61bc57222698799edd7bbc8df5214be44e239a95f679249c59c".to_string()
            )
        );
    }

    #[test]
    fn handle_new_transaction_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .response(
                "0x94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2".to_string(),
                7,
            )
            .end_batch()
            .start();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let pending_nonce = 1;
        let chain = DEFAULT_CHAIN;
        let gas_price = DEFAULT_GAS_PRICE;
        let consuming_wallet = make_paying_wallet(b"paying_wallet");
        let account = make_payable_account(1);
        let web3_batch = Web3::new(Batch::new(transport));
        let result = handle_new_transaction(
            chain,
            web3_batch.clone(),
            account.wallet,
            consuming_wallet,
            account.balance_wei,
            pending_nonce.into(),
            gas_price,
        );

        let mut batch_result = web3_batch.eth().transport().submit_batch().wait().unwrap();

        assert_eq!(
            result,
            H256::from_str("94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2")
                .unwrap()
        );
        assert_eq!(
            batch_result.pop().unwrap().unwrap(),
            Value::String(
                "0x94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2".to_string()
            )
        );
    }

    #[test]
    fn sign_and_append_payment_works() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let pending_nonce = 1;
        let chain = DEFAULT_CHAIN;
        let gas_price = DEFAULT_GAS_PRICE;
        let consuming_wallet = make_paying_wallet(b"paying_wallet");
        let account = make_payable_account(1);
        let amount = account.balance_wei;

        let result = sign_and_append_payment(
            chain,
            web3_batch,
            consuming_wallet,
            pending_nonce.into(),
            gas_price,
            account,
        );

        let expected_hash_and_amount = HashAndAmount {
            hash: H256::from_str(
                "94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2",
            )
            .unwrap(),
            amount,
        };
        assert_eq!(result, expected_hash_and_amount);
    }

    #[test]
    fn send_and_append_multiple_payments_works() {
        let port = find_free_port();
        let logger = Logger::new("send_and_append_multiple_payments_works");
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let chain = DEFAULT_CHAIN;
        let gas_price = DEFAULT_GAS_PRICE;
        let pending_nonce = 1;
        let consuming_wallet = make_paying_wallet(b"paying_wallet");
        let account_1 = make_payable_account(1);
        let account_2 = make_payable_account(2);
        let accounts = vec![account_1, account_2];

        let result = sign_and_append_multiple_payments(
            logger,
            chain,
            web3_batch,
            consuming_wallet,
            gas_price,
            pending_nonce.into(),
            accounts,
        );

        assert_eq!(
            result,
            vec![
                HashAndAmount {
                    hash: H256::from_str(
                        "94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2"
                    )
                    .unwrap(),
                    amount: 1000000000
                },
                HashAndAmount {
                    hash: H256::from_str(
                        "3811874d2b73cecd51234c94af46bcce918d0cb4de7d946c01d7da606fe761b5"
                    )
                    .unwrap(),
                    amount: 2000000000
                }
            ]
        );
    }

    #[test]
    fn transmission_log_just_works() {
        init_test_logging();
        let test_name = "transmission_log_just_works";
        let gas_price = 120;
        let logger = Logger::new(test_name);
        let amount_1 = gwei_to_wei(900_000_000_u64);
        let account_1 = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("w123"),
            amount_1,
            None,
        );
        let amount_2 = 123_456_789_u128;
        let account_2 = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("w555"),
            amount_2,
            None,
        );
        let amount_3 = gwei_to_wei(33_355_666_u64);
        let account_3 = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("w987"),
            amount_3,
            None,
        );
        let accounts_to_process = vec![account_1, account_2, account_3];

        info!(
            logger,
            "{}",
            transmission_log(TEST_DEFAULT_CHAIN, &accounts_to_process, gas_price)
        );

        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(
            "INFO: transmission_log_just_works: Paying to creditors...\n\
        Transactions in the batch:\n\
        \n\
        gas price:                                   120 gwei\n\
        chain:                                       ropsten\n\
        \n\
        [wallet address]                             [payment in wei]\n\
        0x0000000000000000000000000000000077313233   900,000,000,000,000,000\n\
        0x0000000000000000000000000000000077353535   123,456,789\n\
        0x0000000000000000000000000000000077393837   33,355,666,000,000,000\n",
        );
    }

    #[test]
    fn output_by_joining_sources_works() {
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("4567"),
                balance_wei: 2_345_678,
                last_paid_timestamp: from_time_t(4500000),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("5656"),
                balance_wei: 6_543_210,
                last_paid_timestamp: from_time_t(333000),
                pending_payable_opt: None,
            },
        ];
        let fingerprint_inputs = vec![
            HashAndAmount {
                hash: make_tx_hash(444),
                amount: 2_345_678,
            },
            HashAndAmount {
                hash: make_tx_hash(333),
                amount: 6_543_210,
            },
        ];
        let responses = vec![
            Ok(Value::String(String::from("blah"))),
            Err(web3::Error::Rpc(Error {
                code: ErrorCode::ParseError,
                message: "I guess we've got a problem".to_string(),
                data: None,
            })),
        ];

        let result = merged_output_data(responses, fingerprint_inputs, accounts.to_vec());

        assert_eq!(
            result,
            vec![
                Correct(PendingPayable {
                    recipient_wallet: make_wallet("4567"),
                    hash: make_tx_hash(444)
                }),
                Failed(RpcPayableFailure {
                    rpc_error: web3::Error::Rpc(Error {
                        code: ErrorCode::ParseError,
                        message: "I guess we've got a problem".to_string(),
                        data: None,
                    }),
                    recipient_wallet: make_wallet("5656"),
                    hash: make_tx_hash(333)
                })
            ]
        )
    }

    #[test]
    fn send_payables_within_batch_fails_on_submit_batch_call() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        let recipient_wallet = make_wallet("blah123");
        let unimportant_recipient = Recorder::new().start().recipient();
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            recipient_wallet.clone(),
            5000,
            None,
        );
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let gas_price = 123;
        let nonce = U256::from(1);
        let os_code = transport_error_code();
        let os_msg = transport_error_message();

        let result = send_payables_within_batch(
            Logger::new("test"),
            TEST_DEFAULT_CHAIN,
            Web3::new(Batch::new(transport)),
            consuming_wallet,
            gas_price,
            nonce,
            unimportant_recipient,
            vec![account],
        )
        .wait();

        assert_eq!(
            result,
            Err(
                Sending {
                    msg: format!("Transport error: Error(Connect, Os {{ code: {}, kind: ConnectionRefused, message: {:?} }})", os_code, os_msg).to_string(),
                    hashes: vec![H256::from_str("424c0231591a9879d82f25e0d81e09f39499b2bfd56b3aba708491995e35b4ac").unwrap()]
                }
            )
        );
    }

    #[test]
    fn advance_used_nonce_works() {
        let initial_nonce = U256::from(55);

        let result = advance_used_nonce(initial_nonce);

        assert_eq!(result, U256::from(56))
    }

    #[test]
    #[should_panic(
        expected = "Consuming wallet doesnt contain a secret key: Signature(\"Cannot sign with non-keypair wallet: Address(0x000000000000000000006261645f77616c6c6574).\")"
    )]
    fn sign_transaction_panics_on_signing_itself() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let recipient_wallet = make_wallet("unlucky man");
        let consuming_wallet = make_wallet("bad_wallet");
        let gas_price = 123;
        let nonce = U256::from(1);

        sign_transaction(
            Chain::PolyAmoy,
            Web3::new(Batch::new(transport)),
            recipient_wallet,
            consuming_wallet,
            444444,
            nonce,
            gas_price,
        );
    }

    #[test]
    fn send_payables_within_batch_works() {
        init_test_logging();
        let test_name = "send_payables_within_batch_works";
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .response("rpc_result".to_string(), 7)
            .response("rpc_result_2".to_string(), 7)
            .end_batch()
            .start();
        let web3_batch = Web3::new(Batch::new(transport));
        let (accountant, _, accountant_recording) = make_recorder();
        let logger = Logger::new(test_name);
        let chain = DEFAULT_CHAIN;
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let gas_price = 1u64;
        let pending_nonce: U256 = 1.into();
        let new_fingerprints_recipient = accountant.start().recipient();
        let accounts_1 = make_payable_account(1);
        let accounts_2 = make_payable_account(2);
        let accounts = vec![accounts_1.clone(), accounts_2.clone()];
        let system = System::new(test_name);
        let timestamp_before = SystemTime::now();

        let result = send_payables_within_batch(
            logger,
            chain,
            web3_batch,
            consuming_wallet.clone(),
            gas_price.clone(),
            pending_nonce,
            new_fingerprints_recipient,
            accounts.clone(),
        )
        .wait();

        System::current().stop();
        system.run();
        let tlh = TestLogHandler::new();
        let timestamp_after = SystemTime::now();
        let recording_result = accountant_recording.lock().unwrap();
        let processed_payments = result.unwrap();
        let message = recording_result.get_record::<PendingPayableFingerprintSeeds>(0);
        assert_eq!(recording_result.len(), 1);
        assert!(timestamp_before <= message.batch_wide_timestamp);
        assert!(timestamp_after >= message.batch_wide_timestamp);
        assert_eq!(
            message.hashes_and_balances,
            vec![
                HashAndAmount {
                    hash: H256::from_str(
                        "35f42b260f090a559e8b456718d9c91a9da0f234ed0a129b9d5c4813b6615af4"
                    )
                    .unwrap(),
                    amount: accounts_1.balance_wei
                },
                HashAndAmount {
                    hash: H256::from_str(
                        "7f3221109e4f1de8ba1f7cd358aab340ecca872a1456cb1b4f59ca33d3e22ee3"
                    )
                    .unwrap(),
                    amount: accounts_2.balance_wei
                },
            ]
        );
        assert_eq!(
            processed_payments[0],
            ProcessedPayableFallible::Correct(PendingPayable {
                recipient_wallet: accounts_1.wallet,
                hash: H256::from_str(
                    "35f42b260f090a559e8b456718d9c91a9da0f234ed0a129b9d5c4813b6615af4"
                )
                .unwrap()
            })
        );
        assert_eq!(
            processed_payments[1],
            ProcessedPayableFallible::Correct(PendingPayable {
                recipient_wallet: accounts_2.wallet,
                hash: H256::from_str(
                    "7f3221109e4f1de8ba1f7cd358aab340ecca872a1456cb1b4f59ca33d3e22ee3"
                )
                .unwrap()
            })
        );
        tlh.exists_log_containing(
            &format!("DEBUG: {test_name}: Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}, gas_price: {}",
                     consuming_wallet,
                     chain.rec().contract,
                     chain.rec().num_chain_id,
                     gas_price
            )
        );
        tlh.exists_log_containing(&format!(
            "INFO: {test_name}: {}",
            transmission_log(chain, &accounts, gas_price)
        ));
    }

    #[test]
    fn send_payables_within_batch_all_payments_fail() {
        init_test_logging();
        let test_name = "send_payables_within_batch_all_payments_fail";
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .end_batch()
            .start();
        let web3_batch = Web3::new(Batch::new(transport));
        let (accountant, _, accountant_recording) = make_recorder();
        let logger = Logger::new(test_name);
        let chain = DEFAULT_CHAIN;
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let gas_price = 1u64;
        let pending_nonce: U256 = 1.into();
        let new_fingerprints_recipient = accountant.start().recipient();
        let accounts_1 = make_payable_account(1);
        let accounts_2 = make_payable_account(2);
        let accounts = vec![accounts_1.clone(), accounts_2.clone()];
        let system = System::new(test_name);
        let timestamp_before = SystemTime::now();

        let result = send_payables_within_batch(
            logger,
            chain,
            web3_batch,
            consuming_wallet.clone(),
            gas_price.clone(),
            pending_nonce,
            new_fingerprints_recipient,
            accounts.clone(),
        )
        .wait();

        System::current().stop();
        system.run();
        let tlh = TestLogHandler::new();
        let timestamp_after = SystemTime::now();
        let recording_result = accountant_recording.lock().unwrap();
        let processed_payments = result.unwrap();
        let message = recording_result.get_record::<PendingPayableFingerprintSeeds>(0);
        assert_eq!(recording_result.len(), 1);
        assert!(timestamp_before <= message.batch_wide_timestamp);
        assert!(timestamp_after >= message.batch_wide_timestamp);
        assert_eq!(
            message.hashes_and_balances,
            vec![
                HashAndAmount {
                    hash: H256::from_str(
                        "35f42b260f090a559e8b456718d9c91a9da0f234ed0a129b9d5c4813b6615af4"
                    )
                    .unwrap(),
                    amount: accounts_1.balance_wei
                },
                HashAndAmount {
                    hash: H256::from_str(
                        "7f3221109e4f1de8ba1f7cd358aab340ecca872a1456cb1b4f59ca33d3e22ee3"
                    )
                    .unwrap(),
                    amount: accounts_2.balance_wei
                },
            ]
        );
        assert_eq!(processed_payments[0], Failed(RpcPayableFailure{
            rpc_error: Rpc(Error {
                code: ServerError(429),
                message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string(),
                data: None,
            }),
            recipient_wallet: accounts_1.wallet,
            hash: H256::from_str("35f42b260f090a559e8b456718d9c91a9da0f234ed0a129b9d5c4813b6615af4").unwrap(),
        }));
        assert_eq!(processed_payments[1], Failed(RpcPayableFailure{
            rpc_error: Rpc(Error {
                code: ServerError(429),
                message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string(),
                data: None,
            }),
            recipient_wallet: accounts_2.wallet,
            hash: H256::from_str("7f3221109e4f1de8ba1f7cd358aab340ecca872a1456cb1b4f59ca33d3e22ee3").unwrap(),
        }));
        tlh.exists_log_containing(
            &format!("DEBUG: {test_name}: Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}, gas_price: {}",
                     consuming_wallet,
                     chain.rec().contract,
                     chain.rec().num_chain_id,
                     gas_price
            )
        );
        tlh.exists_log_containing(&format!(
            "INFO: {test_name}: {}",
            transmission_log(chain, &accounts, gas_price)
        ));
    }

    #[test]
    fn send_payables_within_batch_one_payment_works_the_other_fails() {
        init_test_logging();
        let test_name = "send_payables_within_batch_one_payment_works_the_other_fails";
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .response("rpc_result".to_string(), 7)
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .end_batch()
            .start();
        let web3_batch = Web3::new(Batch::new(transport.clone()));

        let (accountant, _, accountant_recording) = make_recorder();
        let logger = Logger::new(test_name);
        let chain = DEFAULT_CHAIN;
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let gas_price = 1u64;
        let pending_nonce: U256 = 1.into();
        let new_fingerprints_recipient = accountant.start().recipient();
        let accounts_1 = make_payable_account(1);
        let accounts_2 = make_payable_account(2);
        let accounts = vec![accounts_1.clone(), accounts_2.clone()];
        let system = System::new(test_name);
        let timestamp_before = SystemTime::now();

        let result = send_payables_within_batch(
            logger,
            chain,
            web3_batch,
            consuming_wallet.clone(),
            gas_price.clone(),
            pending_nonce,
            new_fingerprints_recipient,
            accounts.clone(),
        )
        .wait();

        System::current().stop();
        system.run();
        let tlh = TestLogHandler::new();
        let timestamp_after = SystemTime::now();
        let recording_result = accountant_recording.lock().unwrap();
        let processed_payments = result.unwrap();
        let message = recording_result.get_record::<PendingPayableFingerprintSeeds>(0);
        assert_eq!(recording_result.len(), 1);
        assert!(timestamp_before <= message.batch_wide_timestamp);
        assert!(timestamp_after >= message.batch_wide_timestamp);
        assert_eq!(
            message.hashes_and_balances,
            vec![
                HashAndAmount {
                    hash: H256::from_str(
                        "35f42b260f090a559e8b456718d9c91a9da0f234ed0a129b9d5c4813b6615af4"
                    )
                    .unwrap(),
                    amount: accounts_1.balance_wei
                },
                HashAndAmount {
                    hash: H256::from_str(
                        "7f3221109e4f1de8ba1f7cd358aab340ecca872a1456cb1b4f59ca33d3e22ee3"
                    )
                    .unwrap(),
                    amount: accounts_2.balance_wei
                },
            ]
        );
        assert_eq!(
            processed_payments[0],
            ProcessedPayableFallible::Correct(PendingPayable {
                recipient_wallet: accounts_1.wallet,
                hash: H256::from_str(
                    "35f42b260f090a559e8b456718d9c91a9da0f234ed0a129b9d5c4813b6615af4"
                )
                .unwrap()
            })
        );
        assert_eq!(processed_payments[1], ProcessedPayableFallible::Failed(RpcPayableFailure{
            rpc_error: Rpc(Error {
                code: ServerError(429),
                message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string(),
                data: None,
            }),
            recipient_wallet: accounts_2.wallet,
            hash: H256::from_str("7f3221109e4f1de8ba1f7cd358aab340ecca872a1456cb1b4f59ca33d3e22ee3").unwrap(),
        }));
        tlh.exists_log_containing(
            &format!("DEBUG: {test_name}: Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}, gas_price: {}",
                     consuming_wallet,
                     chain.rec().contract,
                     chain.rec().num_chain_id,
                     gas_price
            )
        );
        tlh.exists_log_containing(&format!(
            "INFO: {test_name}: {}",
            transmission_log(chain, &accounts, gas_price)
        ));
    }

    #[test]
    fn sign_transaction_just_works() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3 = Web3::new(transport.clone());
        let chain = DEFAULT_CHAIN;
        let amount = 11_222_333_444;
        let gas_price_in_gwei = 123000000000_u64;
        let nonce = U256::from(5);
        let recipient_wallet = make_wallet("recipient_wallet");
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let consuming_wallet_secret_key = consuming_wallet.prepare_secp256k1_secret().unwrap();
        let data = sign_transaction_data(amount, recipient_wallet.clone());
        let tx_parameters = TransactionParameters {
            nonce: Some(nonce),
            to: Some(chain.rec().contract),
            gas: gas_limit(data, chain),
            gas_price: Some(to_wei(gas_price_in_gwei)),
            value: U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(chain.rec().num_chain_id),
        };
        let result = sign_transaction(
            chain,
            Web3::new(Batch::new(transport)),
            recipient_wallet,
            consuming_wallet,
            amount,
            nonce,
            gas_price_in_gwei,
        );

        let expected_tx_result = web3
            .accounts()
            .sign_transaction(tx_parameters, &consuming_wallet_secret_key)
            .wait()
            .unwrap();

        assert_eq!(result, expected_tx_result);
    }

    #[test]
    #[should_panic(
        expected = "Consuming wallet doesnt contain a secret key: Signature(\"Cannot sign with non-keypair wallet: Address(0x00000000636f6e73756d696e675f77616c6c6574).\")"
    )]
    fn sign_transaction_panics_on_bad_consuming_wallet() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = DEFAULT_CHAIN;
        let amount = 11_222_333_444;
        let gas_price_in_gwei = 123000000000_u64;
        let nonce = U256::from(5);
        let recipient_wallet = make_wallet("recipient_wallet");
        let consuming_wallet = make_wallet("consuming_wallet");

        let _result = sign_transaction(
            chain,
            Web3::new(Batch::new(transport)),
            recipient_wallet,
            consuming_wallet,
            amount,
            nonce,
            gas_price_in_gwei,
        );
    }

    #[test]
    #[should_panic(expected = "Signing should be done locally")]
    fn sign_transaction_locally_panics_on_signed_transaction() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = DEFAULT_CHAIN;
        let amount = 11_222_333_444;
        let gas_limit = U256::from(5);
        let gas_price = U256::from(5);
        let recipient_wallet = make_wallet("recipient_wallet");
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let data = sign_transaction_data(amount, recipient_wallet);
        // sign_transaction makes a blockchain call because nonce is set to None
        let transaction_parameters = TransactionParameters {
            nonce: None,
            to: Some(chain.rec().contract),
            gas: gas_limit,
            gas_price: Some(gas_price),
            value: U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(chain.rec().num_chain_id),
        };
        let key = consuming_wallet
            .prepare_secp256k1_secret()
            .expect("Consuming wallet doesnt contain a secret key");

        let _result = sign_transaction_locally(
            Web3::new(Batch::new(transport)),
            transaction_parameters,
            &key,
        );
    }

    #[test]
    fn sign_and_append_payment_just_works() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let system = System::new("test");
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            9000,
            None,
        );
        let gas_price = 123;
        let nonce = U256::from(1);

        let result = sign_and_append_payment(
            TEST_DEFAULT_CHAIN,
            Web3::new(Batch::new(transport)),
            consuming_wallet,
            nonce,
            gas_price,
            account,
        );

        System::current().stop();
        system.run();
        let expected_hash =
            H256::from_str("8d278f82f42ee4f3b9eef2e099cccc91ff117e80c28d6369fec38ec50f5bd2c2")
                .unwrap();
        assert_eq!(result.hash, expected_hash);
        assert_eq!(result.amount, 9000);
    }

    //with a real confirmation through a transaction sent with this data to the network
    #[test]
    fn web3_interface_signing_a_transaction_works_for_polygon_amoy() {
        let chain = Chain::PolyAmoy;
        let nonce = 4;
        let signed_transaction_data = "f8ad04850ba43b74008301198094d98c3ebd6b7f9b7cda2449ecac00d1e5f47a819380b844a9\
        059cbb0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b0000000000000000000000000000000000000000000\
        00000000000e8d4a5100083027127a0ef0873170be31c30f532edf3c97fe8a1d577859fd4045b060007cf9e75bda875a01e4a3f7e06d12b22\
        68d9889e279643ad8e1d291bca8f9f741bd6ec1aca2c0766";
        let in_bytes = decode_hex(signed_transaction_data).unwrap();

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &in_bytes)
    }

    //with a real confirmation through a transaction sent with this data to the network
    #[test]
    fn web3_interface_signing_a_transaction_works_for_eth_ropsten() {
        let chain = Chain::EthRopsten;
        let nonce = 1; //must stay like this!
        let signed_transaction_data = "f8a90185199c82cc0082dee894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cb\
        b0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b000000000000000000000000000000000000000000000000000\
        000e8d4a510002aa0635fbb3652e1c3063afac6ffdf47220e0431825015aef7daff9251694e449bfca00b2ed6d556bd030ac75291bf58817da15\
        a891cd027a4c261bb80b51f33b78adf";
        let in_bytes = decode_hex(signed_transaction_data).unwrap();

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &in_bytes)
    }

    //not confirmed on the real network
    #[test]
    fn web3_interface_signing_a_transaction_for_polygon_mainnet() {
        let chain = Chain::PolyMainnet;
        let nonce = 10;
        //generated locally
        let signed_transaction_data = [
            248, 172, 10, 133, 11, 164, 59, 116, 0, 131, 1, 25, 128, 148, 238, 154, 53, 47, 106,
            172, 74, 241, 165, 185, 244, 103, 246, 169, 62, 15, 251, 233, 221, 53, 128, 184, 68,
            169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 136, 223, 118, 187, 217,
            160, 199, 195, 229, 191, 15, 119, 187, 40, 198, 10, 22, 122, 123, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 212, 165, 16, 0, 130,
            1, 53, 160, 7, 203, 40, 44, 202, 233, 15, 5, 64, 218, 199, 239, 94, 126, 152, 2, 108,
            30, 157, 75, 124, 129, 117, 27, 109, 163, 132, 27, 11, 123, 137, 10, 160, 18, 170, 130,
            198, 73, 190, 158, 235, 0, 77, 118, 213, 244, 229, 225, 143, 156, 214, 219, 204, 193,
            155, 199, 164, 162, 31, 134, 51, 139, 130, 152, 104,
        ];

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &signed_transaction_data)
    }

    //not confirmed on the real network
    #[test]
    fn web3_interface_signing_a_transaction_for_eth_mainnet() {
        let chain = Chain::EthMainnet;
        let nonce = 10;
        //generated locally
        let signed_transaction_data = [
            248, 169, 10, 133, 25, 156, 130, 204, 0, 130, 222, 232, 148, 6, 243, 195, 35, 240, 35,
            140, 114, 191, 53, 1, 16, 113, 242, 181, 183, 244, 58, 5, 76, 128, 184, 68, 169, 5,
            156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 136, 223, 118, 187, 217, 160, 199,
            195, 229, 191, 15, 119, 187, 40, 198, 10, 22, 122, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 212, 165, 16, 0, 38, 160, 199,
            155, 76, 106, 39, 227, 3, 151, 90, 117, 245, 211, 86, 98, 187, 117, 120, 103, 165, 131,
            99, 72, 36, 211, 10, 224, 252, 104, 51, 200, 230, 158, 160, 84, 18, 140, 248, 119, 22,
            193, 14, 148, 253, 48, 59, 185, 11, 38, 152, 103, 150, 120, 60, 74, 56, 159, 206, 22,
            15, 73, 173, 153, 11, 76, 74,
        ];

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &signed_transaction_data)
    }

    #[test]
    fn gas_limit_for_polygon_mumbai_lies_within_limits_for_raw_transaction() {
        test_gas_limit_is_between_limits(Chain::PolyAmoy);
    }

    #[test]
    fn gas_limit_for_polygon_mainnet_lies_within_limits_for_raw_transaction() {
        test_gas_limit_is_between_limits(Chain::PolyMainnet);
    }

    #[test]
    fn gas_limit_for_eth_mainnet_lies_within_limits_for_raw_transaction() {
        test_gas_limit_is_between_limits(Chain::EthMainnet)
    }

    fn assert_that_signed_transactions_agrees_with_template(
        chain: Chain,
        nonce: u64,
        template: &[u8],
    ) {
        const TEST_PAYMENT_AMOUNT: u128 = 1_000_000_000_000;
        const TEST_GAS_PRICE_ETH: u64 = 110;
        const TEST_GAS_PRICE_POLYGON: u64 = 50;

        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let consuming_wallet = {
            let key_pair = Bip32EncryptionKeyProvider::from_raw_secret(
                &decode_hex("97923d8fd8de4a00f912bfb77ef483141dec551bd73ea59343ef5c4aac965d04")
                    .unwrap(),
            )
            .unwrap();
            Wallet::from(key_pair)
        };
        let recipient_wallet = {
            let hex_part = &"0x7788df76BBd9a0C7c3e5bf0f77bb28C60a167a7b"[2..];
            let recipient_address_bytes = decode_hex(hex_part).unwrap();
            let address = Address::from_slice(&recipient_address_bytes);
            Wallet::from(address)
        };
        let nonce_correct_type = U256::from(nonce);
        let gas_price = match chain {
            Chain::EthMainnet => TEST_GAS_PRICE_ETH,
            Chain::EthRopsten => TEST_GAS_PRICE_ETH,
            Chain::PolyMainnet => TEST_GAS_PRICE_POLYGON,
            Chain::PolyAmoy => TEST_GAS_PRICE_POLYGON,
            _ => panic!("isn't our interest in this test"),
        };
        let payable_account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            recipient_wallet,
            TEST_PAYMENT_AMOUNT,
            None,
        );

        let signed_transaction = sign_transaction(
            chain,
            Web3::new(Batch::new(transport)),
            payable_account.wallet,
            consuming_wallet,
            payable_account.balance_wei,
            nonce_correct_type,
            gas_price,
        );

        let byte_set_to_compare = signed_transaction.raw_transaction.0;
        assert_eq!(byte_set_to_compare.as_slice(), template)
    }

    fn test_gas_limit_is_between_limits(chain: Chain) {
        let not_under_this_value = BlockchainInterfaceWeb3::web3_gas_limit_const_part(chain);
        let not_above_this_value = not_under_this_value + WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
        let data = sign_transaction_data(1_000_000_000, make_wallet("wallet1"));

        let gas_limit = gas_limit(data, chain);

        assert!(
            gas_limit >= U256::from(not_under_this_value),
            "actual gas limit {} isn't above or equal {}",
            gas_limit,
            not_under_this_value
        );
        assert!(
            gas_limit <= U256::from(not_above_this_value),
            "actual gas limit {} isn't below or equal {}",
            gas_limit,
            not_above_this_value
        );
    }
}
