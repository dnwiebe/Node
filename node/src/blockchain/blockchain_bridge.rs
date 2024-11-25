// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::msgs::{
    BlockchainAgentWithContextMessage, QualifiedPayablesMessage,
};
use crate::accountant::{
    PaymentsAndStartBlock, ReceivedPayments, ResponseSkeleton, ScanError,
    SentPayables, SkeletonOptHolder,
};
use crate::accountant::{ReportTransactionReceipts, RequestTransactionReceipts};
use crate::actor_system_factory::SubsFactory;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::HashAndAmount;
use crate::blockchain::blockchain_interface::data_structures::errors::{
    BlockchainError, PayableTransactionError,
};
use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible;
use crate::blockchain::blockchain_interface::BlockchainInterface;
use crate::blockchain::blockchain_interface_initializer::BlockchainInterfaceInitializer;
use crate::database::db_initializer::{DbInitializationConfig, DbInitializer, DbInitializerReal};
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::blockchain_bridge::{
    BlockchainBridgeSubs, OutboundPaymentsInstructions,
};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::utils::{db_connection_launch_panic, handle_ui_crash_request};
use crate::sub_lib::wallet::{Wallet};
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Addr, Recipient};
use futures::Future;
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use masq_lib::ui_gateway::NodeFromUiMessage;
use regex::Regex;
use std::path::Path;
use std::string::ToString;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use ethabi::Hash;
use web3::types::{BlockNumber, H256};
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionReceiptResult;

pub const CRASH_KEY: &str = "BLOCKCHAINBRIDGE";
pub const DEFAULT_BLOCKCHAIN_SERVICE_URL: &str = "https://0.0.0.0";

pub struct BlockchainBridge {
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config_arc: Arc<Mutex<dyn PersistentConfiguration>>,
    sent_payable_subs_opt: Option<Recipient<SentPayables>>,
    payable_payments_setup_subs_opt: Option<Recipient<BlockchainAgentWithContextMessage>>,
    received_payments_subs_opt: Option<Recipient<ReceivedPayments>>,
    scan_error_subs_opt: Option<Recipient<ScanError>>,
    crashable: bool,
    pending_payable_confirmation: TransactionConfirmationTools,
}

struct TransactionConfirmationTools {
    new_pp_fingerprints_sub_opt: Option<Recipient<PendingPayableFingerprintSeeds>>,
    report_transaction_receipts_sub_opt: Option<Recipient<ReportTransactionReceipts>>,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.pending_payable_confirmation
            .new_pp_fingerprints_sub_opt =
            Some(msg.peer_actors.accountant.init_pending_payable_fingerprints);
        self.pending_payable_confirmation
            .report_transaction_receipts_sub_opt =
            Some(msg.peer_actors.accountant.report_transaction_receipts);
        self.payable_payments_setup_subs_opt =
            Some(msg.peer_actors.accountant.report_payable_payments_setup);
        self.sent_payable_subs_opt = Some(msg.peer_actors.accountant.report_sent_payments);
        self.received_payments_subs_opt = Some(msg.peer_actors.accountant.report_inbound_payments);
        self.scan_error_subs_opt = Some(msg.peer_actors.accountant.scan_errors);
        // There's a multinode integration test looking for this message
        debug!(self.logger, "Received BindMessage");
    }
}

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct RetrieveTransactions {
    pub recipient: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for RetrieveTransactions {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

impl Handler<RetrieveTransactions> for BlockchainBridge {
    type Result = ();

    fn handle(
        &mut self,
        msg: RetrieveTransactions,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RetrieveTransactions>>::Result {
        self.handle_scan_future(
            Self::handle_retrieve_transactions,
            ScanType::Receivables,
            msg,
        )
    }
}

impl Handler<RequestTransactionReceipts> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: RequestTransactionReceipts, _ctx: &mut Self::Context) {
        self.handle_scan_future(
            Self::handle_request_transaction_receipts,
            ScanType::PendingPayables,
            msg,
        )
    }
}

impl Handler<QualifiedPayablesMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: QualifiedPayablesMessage, _ctx: &mut Self::Context) {
        self.handle_scan_future(Self::handle_qualified_payable_msg, ScanType::Payables, msg);
    }
}

impl Handler<OutboundPaymentsInstructions> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: OutboundPaymentsInstructions, _ctx: &mut Self::Context) {
        self.handle_scan_future(
            Self::handle_outbound_payments_instructions,
            ScanType::Payables,
            msg,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub struct PendingPayableFingerprintSeeds {
    pub batch_wide_timestamp: SystemTime,
    pub hashes_and_balances: Vec<HashAndAmount>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PendingPayableFingerprint {
    // Sqlite begins counting from 1
    pub rowid: u64,
    pub timestamp: SystemTime,
    pub hash: H256,
    // We have Sqlite begin counting from 1
    pub attempt: u16,
    pub amount: u128,
    pub process_error: Option<String>,
}

impl Handler<NodeFromUiMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
    }
}

impl BlockchainBridge {
    pub fn new(
        blockchain_interface: Box<dyn BlockchainInterface>,
        persistent_config: Arc<Mutex<dyn PersistentConfiguration>>,
        crashable: bool,
    ) -> BlockchainBridge {
        BlockchainBridge {
            blockchain_interface,
            persistent_config_arc: persistent_config,
            sent_payable_subs_opt: None,
            payable_payments_setup_subs_opt: None,
            received_payments_subs_opt: None,
            scan_error_subs_opt: None,
            crashable,
            logger: Logger::new("BlockchainBridge"),
            pending_payable_confirmation: TransactionConfirmationTools {
                new_pp_fingerprints_sub_opt: None,
                report_transaction_receipts_sub_opt: None,
            },
        }
    }

    pub fn initialize_persistent_configuration(
        data_directory: &Path,
    ) -> Arc<Mutex<dyn PersistentConfiguration>> {
        let config_dao = Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(data_directory, DbInitializationConfig::panic_on_migration())
                .unwrap_or_else(|err| db_connection_launch_panic(err, data_directory)),
        ));
        Arc::new(Mutex::new(PersistentConfigurationReal::new(config_dao)))
    }

    pub fn initialize_blockchain_interface(
        blockchain_service_url_opt: Option<String>,
        chain: Chain,
        logger: Logger,
    ) -> Box<dyn BlockchainInterface> {
        match blockchain_service_url_opt {
            Some(url) => {
                // TODO if we decided to have interchangeably runtime switchable or simultaneously usable interfaces we will
                // probably want to make BlockchainInterfaceInitializer a collaborator that's a part of the actor
                info!(logger, "Blockchain service url has been set to {}", url);
                BlockchainInterfaceInitializer {}.initialize_interface(&url, chain)
            }
            None => {
                info!(logger, "The Blockchain service url is not set yet. its been defaulted to a wild card IP");
                BlockchainInterfaceInitializer {}
                    .initialize_interface(DEFAULT_BLOCKCHAIN_SERVICE_URL, chain)
            }
        }
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: recipient!(addr, BindMessage),
            outbound_payments_instructions: recipient!(addr, OutboundPaymentsInstructions),
            qualified_payables: recipient!(addr, QualifiedPayablesMessage),
            retrieve_transactions: recipient!(addr, RetrieveTransactions),
            ui_sub: recipient!(addr, NodeFromUiMessage),
            request_transaction_receipts: recipient!(addr, RequestTransactionReceipts),
        }
    }

    fn handle_qualified_payable_msg(
        &mut self,
        incoming_message: QualifiedPayablesMessage,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        // TODO rewrite this into a batch call as soon as GH-629 gets into master
        let accountant_recipient = self.payable_payments_setup_subs_opt.clone();
        Box::new(
            self.blockchain_interface
                .build_blockchain_agent(incoming_message.consuming_wallet)
                .map_err(|e| format!("Blockchain agent build error: {:?}", e))
                .and_then(move |agent| {
                    let outgoing_message = BlockchainAgentWithContextMessage::new(
                        incoming_message.protected_qualified_payables,
                        agent,
                        incoming_message.response_skeleton_opt,
                    );
                    accountant_recipient
                        .expect("Accountant is unbound")
                        .try_send(outgoing_message)
                        .expect("Accountant is dead");
                    Ok(())
                }),
        )
    }

    fn handle_outbound_payments_instructions(
        &mut self,
        msg: OutboundPaymentsInstructions,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let skeleton_opt = msg.response_skeleton_opt;
        let sent_payable_subs = self
            .sent_payable_subs_opt
            .as_ref()
            .expect("Accountant is unbound")
            .clone();

        let send_message_if_failure = move |msg: SentPayables| {
            sent_payable_subs.try_send(msg).expect("Accountant is dead");
        };
        let send_message_if_successful = send_message_if_failure.clone();

        Box::new(
            self.process_payments(msg.agent, msg.affordable_accounts)
                .map_err(move |e: PayableTransactionError| {
                    send_message_if_failure(SentPayables {
                        payment_procedure_result: Err(e.clone()),
                        response_skeleton_opt: skeleton_opt,
                    });
                    format!("ReportAccountsPayable: {}", e)
                })
                .and_then(move |payment_result| {
                    send_message_if_successful(SentPayables {
                        payment_procedure_result: Ok(payment_result),
                        response_skeleton_opt: skeleton_opt,
                    });
                    Ok(())
                }),
        )
    }

    fn handle_retrieve_transactions(
        &mut self,
        msg: RetrieveTransactions,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let (start_block_nbr, max_block_count) = {
            let persistent_config_lock = self
                .persistent_config_arc
                .lock()
                .expect("Unable to lock persistent config in BlockchainBridge");

            let start_block_nbr = match persistent_config_lock.start_block() {
                Ok(sb) => sb,
                Err(e) => panic!("Cannot retrieve start block from database; payments to you may not be processed: {:?}", e)
            };
            let max_block_count = match persistent_config_lock.max_block_count() {
                Ok(Some(mbc)) => mbc,
                _ => u64::MAX,
            };
            (start_block_nbr, max_block_count)
        };

        let logger = self.logger.clone();
        let fallback_next_start_block_number =
            Self::calculate_fallback_start_block_number(start_block_nbr, max_block_count);
        let start_block = BlockNumber::Number(start_block_nbr.into());
        let received_payments_subs = self
            .received_payments_subs_opt
            .as_ref()
            .expect("Accountant is unbound")
            .clone();
        let persistent_config_arc = self.persistent_config_arc.clone();

        Box::new(
            self.blockchain_interface
                .retrieve_transactions(
                    start_block,
                    fallback_next_start_block_number,
                    msg.recipient.address(),
                )
                .map_err(move |e| {
                    if let Some(max_block_count) =
                        BlockchainBridge::extract_max_block_count(e.clone())
                    {
                        match persistent_config_arc
                            .lock()
                            .expect("Unable to lock persistent config in BlockchainBridge")
                            .set_max_block_count(Some(max_block_count))
                        {
                            Ok(()) => {
                                debug!(
                                    logger,
                                    "Updated max_block_count to {} in database.", max_block_count
                                );
                            }
                            Err(e) => {
                                panic!(
                                    "Attempt to set new max block to {} failed due to: {:?}",
                                    max_block_count, e
                                )
                            }
                        }
                    }
                    format!("Error while retrieving transactions: {:?}", e)
                })
                .and_then(move |transactions| {
                    let payments_and_start_block = PaymentsAndStartBlock {
                        payments: transactions.transactions,
                        new_start_block: transactions.new_start_block,
                    };

                    received_payments_subs
                        .try_send(ReceivedPayments {
                            timestamp: SystemTime::now(),
                            payments_and_start_block,
                            response_skeleton_opt: msg.response_skeleton_opt,
                        })
                        .expect("Accountant is dead.");
                    Ok(())
                }),
        )
    }

    fn handle_request_transaction_receipts(
        &mut self,
        msg: RequestTransactionReceipts,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let logger = self.logger.clone();
        let accountant_recipient = self
            .pending_payable_confirmation
            .report_transaction_receipts_sub_opt
            .clone()
            .expect("Accountant is unbound");

        let transaction_hashes = msg
            .pending_payable
            .iter()
            .map(|finger_print| finger_print.hash)
            .collect::<Vec<Hash>>();

        Box::new(
            self.blockchain_interface
                .process_transaction_receipts(transaction_hashes)
                .map_err(move |e| e.to_string())
                .and_then(move |transaction_receipts_results| {
                    let length = transaction_receipts_results.len();
                    let mut transactions_found = 0;
                    for transaction_receipt in &transaction_receipts_results {
                        if let TransactionReceiptResult::Found(_) = transaction_receipt {
                            transactions_found += 1;
                        }
                    }
                    let pairs = transaction_receipts_results
                        .into_iter()
                        .zip(msg.pending_payable.into_iter())
                        .collect_vec();
                    accountant_recipient
                        .try_send(ReportTransactionReceipts {
                            fingerprints_with_receipts: pairs,
                            response_skeleton_opt: msg.response_skeleton_opt,
                        })
                        .expect("Accountant is dead");
                    if length != transactions_found {
                        debug!(
                            logger,
                            "Aborting scanning; {} transactions succeed and {} transactions failed",
                            transactions_found,
                            length - transactions_found
                        );
                    };
                    Ok(())
                }),
        )
    }

    fn handle_scan_future<M, F>(&mut self, handler: F, scan_type: ScanType, msg: M)
    where
        F: FnOnce(&mut BlockchainBridge, M) -> Box<dyn Future<Item = (), Error = String>>,
        M: SkeletonOptHolder,
    {
        let skeleton_opt = msg.skeleton_opt();
        let logger = self.logger.clone();
        let scan_error_subs_opt = self.scan_error_subs_opt.clone();
        let future = handler(self, msg).map_err(move |e| {
            warning!(logger, "{}", e);
            scan_error_subs_opt
                .as_ref()
                .expect("Accountant not bound")
                .try_send(ScanError {
                    scan_type,
                    response_skeleton_opt: skeleton_opt,
                    msg: e,
                })
                .expect("Accountant is dead");
        });

        actix::spawn(future);
    }

    fn calculate_fallback_start_block_number(start_block_number: u64, max_block_count: u64) -> u64 {
        if max_block_count == u64::MAX {
            start_block_number + 1u64
        } else {
            start_block_number + max_block_count
        }
    }

    fn process_payments(
        &self,
        agent: Box<dyn BlockchainAgent>,
        affordable_accounts: Vec<PayableAccount>,
    ) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError>>
    {
        let new_fingerprints_recipient = self.new_fingerprints_recipient();
        let logger = self.logger.clone();
        let chain = self.blockchain_interface.get_chain();
        self.blockchain_interface.submit_payables_in_batch(
            logger,
            chain,
            agent,
            new_fingerprints_recipient,
            affordable_accounts,
        )
    }

    fn new_fingerprints_recipient(&self) -> Recipient<PendingPayableFingerprintSeeds> {
        self.pending_payable_confirmation
            .new_pp_fingerprints_sub_opt
            .clone()
            .expect("Accountant unbound")
    }

    pub fn extract_max_block_count(error: BlockchainError) -> Option<u64> {
        let regex_result =
            Regex::new(r".* (max: |allowed for your plan: |is limited to |block range limit \()(?P<max_block_count>\d+).*")
                .expect("Invalid regex");
        let max_block_count = match error {
            BlockchainError::QueryFailed(msg) => match regex_result.captures(msg.as_str()) {
                Some(captures) => match captures.name("max_block_count") {
                    Some(m) => match m.as_str().parse::<u64>() {
                        Ok(value) => Some(value),
                        Err(_) => None,
                    },
                    _ => None,
                },
                None => match msg.as_str() {
                    "Got invalid response: Expected batch, got single." => Some(1000),
                    _ => None,
                },
            },
            _ => None,
        };
        max_block_count
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct PendingTxInfo {
    hash: H256,
    when_sent: SystemTime,
}

pub struct BlockchainBridgeSubsFactoryReal {}

impl SubsFactory<BlockchainBridge, BlockchainBridgeSubs> for BlockchainBridgeSubsFactoryReal {
    fn make(&self, addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridge::make_subs_from(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
    use crate::accountant::db_access_objects::utils::from_time_t;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::accountant::scanners::test_utils::{
        make_empty_payments_and_start_block, protect_payables_in_test,
    };
    use crate::accountant::test_utils::{make_payable_account, make_pending_payable_fingerprint};
    use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError::TransactionID;
    use crate::blockchain::blockchain_interface::data_structures::errors::{
        BlockchainAgentBuildError, PayableTransactionError,
    };
    use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible::Correct;
    use crate::blockchain::blockchain_interface::data_structures::{
        BlockchainTransaction, RetrievedBlockchainTransactions,
    };
    use crate::blockchain::test_utils::{
        make_blockchain_interface_web3, make_tx_hash, ReceiptResponseBuilder,
    };
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::match_every_type_id;
    use crate::node_test_utils::check_timestamp;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{
        make_accountant_subs_from_recorder, make_recorder, peer_actors_builder,
    };
    use crate::test_utils::recorder_stop_conditions::StopCondition;
    use crate::test_utils::recorder_stop_conditions::StopConditions;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use crate::test_utils::unshared_test_utils::{
        assert_on_initialization_with_panic_on_migration, configure_default_persistent_config,
        prove_that_crash_request_handler_is_hooked_up, AssertionsMessage, ZERO,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::System;
    use ethereum_types::U64;
    use masq_lib::messages::ScanType;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_exists, LogObject, TEST_DEFAULT_CHAIN,
    };
    use masq_lib::utils::find_free_port;
    use std::any::TypeId;
    use std::path::Path;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use web3::types::{TransactionReceipt, H160};

    impl Handler<AssertionsMessage<Self>> for BlockchainBridge {
        type Result = ();

        fn handle(
            &mut self,
            msg: AssertionsMessage<Self>,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            (msg.assertions)(self)
        }
    }

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "BLOCKCHAINBRIDGE");
        assert_eq!(DEFAULT_BLOCKCHAIN_SERVICE_URL, "https://0.0.0.0");
    }

    fn stub_bi() -> Box<dyn BlockchainInterface> {
        Box::new(make_blockchain_interface_web3(find_free_port()))
    }

    #[test]
    fn blockchain_bridge_receives_bind_message() {
        init_test_logging();
        let subject = BlockchainBridge::new(
            stub_bi(),
            Arc::new(Mutex::new(configure_default_persistent_config(ZERO))),
            false,
        );
        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new()
            .exists_log_containing("DEBUG: BlockchainBridge: Received BindMessage");
    }

    #[test]
    fn blockchain_interface_is_constructed_with_missing_blockchain_service_url() {
        init_test_logging();
        let subject = BlockchainBridge::initialize_blockchain_interface(
            None,
            TEST_DEFAULT_CHAIN,
            Logger::new("test"),
        );

        let chain = subject.get_chain();

        assert_eq!(chain, TEST_DEFAULT_CHAIN);
        TestLogHandler::new().exists_log_containing("INFO: test: The Blockchain service url is not set yet. its been defaulted to a wild card IP");
    }

    #[test]
    fn blockchain_interface_is_constructed_with_a_blockchain_service_url() {
        init_test_logging();
        let blockchain_service_url = "https://example.com";
        let subject = BlockchainBridge::initialize_blockchain_interface(
            Some(blockchain_service_url.to_string()),
            TEST_DEFAULT_CHAIN,
            Logger::new("test"),
        );

        let chain = subject.get_chain();

        assert_eq!(chain, TEST_DEFAULT_CHAIN);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: test: Blockchain service url has been set to {}",
            blockchain_service_url
        ));
    }

    #[test]
    fn qualified_payables_msg_is_handled_and_new_msg_with_an_added_blockchain_agent_returns_to_accountant(
    ) {
        let system = System::new(
            "qualified_payables_msg_is_handled_and_new_msg_with_an_added_blockchain_agent_returns_to_accountant",
        );
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x230000000".to_string(), 1)
            .response("0x23".to_string(), 1)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_recipient = accountant.start().recipient();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let persistent_configuration = PersistentConfigurationMock::default();
        let wallet_1 = make_wallet("booga");
        let wallet_2 = make_wallet("gulp");
        let qualified_payables = vec![
            PayableAccount {
                wallet: wallet_1.clone(),
                balance_wei: 78_654_321_124,
                last_paid_timestamp: SystemTime::now()
                    .checked_sub(Duration::from_secs(1000))
                    .unwrap(),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: wallet_2.clone(),
                balance_wei: 60_457_111_003,
                last_paid_timestamp: SystemTime::now()
                    .checked_sub(Duration::from_secs(500))
                    .unwrap(),
                pending_payable_opt: None,
            },
        ];
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_configuration)),
            false,
        );
        subject.payable_payments_setup_subs_opt = Some(accountant_recipient);
        let qualified_payables = protect_payables_in_test(qualified_payables.clone());
        let qualified_payables_msg = QualifiedPayablesMessage {
            protected_qualified_payables: qualified_payables.clone(),
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 11122,
                context_id: 444,
            }),
        };

        subject
            .handle_qualified_payable_msg(qualified_payables_msg)
            .wait()
            .unwrap();

        System::current().stop();
        system.run();

        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        let blockchain_agent_with_context_msg_actual: &BlockchainAgentWithContextMessage =
            accountant_received_payment.get_record(0);
        assert_eq!(
            blockchain_agent_with_context_msg_actual.protected_qualified_payables,
            qualified_payables
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual
                .agent
                .consuming_wallet(),
            &consuming_wallet
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual
                .agent
                .agreed_fee_per_computation_unit(),
            9395240960
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual
                .agent
                .consuming_wallet_balances(),
            ConsumingWalletBalances::new(35.into(), 65535.into())
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual
                .agent
                .estimated_transaction_fee_total(1),
            688_934_229_114_880
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 11122,
                context_id: 444
            })
        );
        assert_eq!(accountant_received_payment.len(), 1);
    }

    #[test]
    fn qualified_payables_msg_is_handled_but_fails_on_build_blockchain_agent() {
        let system =
            System::new("qualified_payables_msg_is_handled_but_fails_on_build_blockchain_agent");
        let port = find_free_port();
        // build blockchain agent fails by not providing the third response.
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .response("0x23".to_string(), 1)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_recipient = accountant.start().recipient();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            false,
        );
        subject.payable_payments_setup_subs_opt = Some(accountant_recipient);
        let qualified_payables = protect_payables_in_test(vec![]);
        let qualified_payables_msg = QualifiedPayablesMessage {
            protected_qualified_payables: qualified_payables,
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 11122,
                context_id: 444,
            }),
        };

        let error_msg = subject
            .handle_qualified_payable_msg(qualified_payables_msg)
            .wait()
            .unwrap_err();

        System::current().stop();
        system.run();

        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
        let service_fee_balance_error = BlockchainAgentBuildError::ServiceFeeBalance(
            consuming_wallet.address(),
            BlockchainError::QueryFailed(
                "Api error: Transport error: Error(IncompleteMessage)".to_string(),
            ),
        );
        assert_eq!(
            error_msg,
            format!(
                "Blockchain agent build error: {:?}",
                service_fee_balance_error
            )
        )
    }

    #[test]
    fn handle_outbound_payments_instructions_sees_payments_happen_and_sends_payment_results_back_to_accountant(
    ) {
        let system = System::new(
            "handle_outbound_payments_instructions_sees_payments_happen_and_sends_payment_results_back_to_accountant",
        );
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x20".to_string(), 1)
            .begin_batch()
            .response("rpc result".to_string(), 1)
            .end_batch()
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(SentPayables))
            .start();
        let wallet_account = make_wallet("blah");
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_configuration_mock = PersistentConfigurationMock::default();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_configuration_mock)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let mut peer_actors = peer_actors_builder().build();
        peer_actors.accountant = make_accountant_subs_from_recorder(&accountant_addr);
        let accounts = vec![PayableAccount {
            wallet: wallet_account,
            balance_wei: 111_420_204,
            last_paid_timestamp: from_time_t(150_000_000),
            pending_payable_opt: None,
        }];
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .agreed_fee_per_computation_unit_result(123)
            .consuming_wallet_result(consuming_wallet);

        send_bind_message!(subject_subs, peer_actors);

        let _ = addr
            .try_send(OutboundPaymentsInstructions {
                affordable_accounts: accounts.clone(),
                agent: Box::new(agent),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            })
            .unwrap();

        let time_before = SystemTime::now();
        system.run();
        let time_after = SystemTime::now();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let pending_payable_fingerprint_seeds_msg =
            accountant_recording.get_record::<PendingPayableFingerprintSeeds>(0);
        let sent_payables_msg = accountant_recording.get_record::<SentPayables>(1);
        assert_eq!(
            sent_payables_msg,
            &SentPayables {
                payment_procedure_result: Ok(vec![Correct(PendingPayable {
                    recipient_wallet: accounts[0].wallet.clone(),
                    hash: H256::from_str(
                        "36e9d7cdd657181317dd461192d537d9944c57a51ee950607de5a618b00e57a1"
                    )
                    .unwrap()
                })]),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                })
            }
        );
        assert!(pending_payable_fingerprint_seeds_msg.batch_wide_timestamp >= time_before);
        assert!(pending_payable_fingerprint_seeds_msg.batch_wide_timestamp <= time_after);
        assert_eq!(
            pending_payable_fingerprint_seeds_msg.hashes_and_balances,
            vec![HashAndAmount {
                hash: H256::from_str(
                    "36e9d7cdd657181317dd461192d537d9944c57a51ee950607de5a618b00e57a1"
                )
                .unwrap(),
                amount: accounts[0].balance_wei
            }]
        );
        assert_eq!(accountant_recording.len(), 2);
    }

    #[test]
    fn handle_outbound_payments_instructions_sends_error_when_failing_on_submit_batch() {
        let system = System::new(
            "handle_outbound_payments_instructions_sends_error_when_failing_on_submit_batch",
        );
        let port = find_free_port();
        // To make submit_batch failed we didn't provide any responses for batch calls
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x20".to_string(), 1)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(SentPayables))
            .start();
        let wallet_account = make_wallet("blah");
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_configuration_mock = PersistentConfigurationMock::default();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_configuration_mock)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let mut peer_actors = peer_actors_builder().build();
        peer_actors.accountant = make_accountant_subs_from_recorder(&accountant_addr);
        let accounts = vec![PayableAccount {
            wallet: wallet_account,
            balance_wei: 111_420_204,
            last_paid_timestamp: from_time_t(150_000_000),
            pending_payable_opt: None,
        }];
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let agent = BlockchainAgentMock::default()
            .consuming_wallet_result(consuming_wallet)
            .agreed_fee_per_computation_unit_result(123);
        send_bind_message!(subject_subs, peer_actors);

        let _ = addr
            .try_send(OutboundPaymentsInstructions {
                affordable_accounts: accounts.clone(),
                agent: Box::new(agent),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            })
            .unwrap();

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let pending_payable_fingerprint_seeds_msg =
            accountant_recording.get_record::<PendingPayableFingerprintSeeds>(0);
        let sent_payables_msg = accountant_recording.get_record::<SentPayables>(1);
        let scan_error_msg = accountant_recording.get_record::<ScanError>(2);
        assert_sending_error(
            sent_payables_msg
                .payment_procedure_result
                .as_ref()
                .unwrap_err(),
            "Transport error: Error(IncompleteMessage)",
        );
        assert_eq!(
            pending_payable_fingerprint_seeds_msg.hashes_and_balances,
            vec![HashAndAmount {
                hash: H256::from_str(
                    "36e9d7cdd657181317dd461192d537d9944c57a51ee950607de5a618b00e57a1"
                )
                .unwrap(),
                amount: accounts[0].balance_wei
            }]
        );
        assert_eq!(
            *scan_error_msg,
            ScanError {
                scan_type: ScanType::Payables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: format!(
                    "ReportAccountsPayable: Sending phase: \"Transport error: Error(IncompleteMessage)\". Signed and hashed transactions: 0x36e9d7cdd657181317dd461192d537d9944c57a51ee950607de5a618b00e57a1"
                )
            }
        );
        assert_eq!(accountant_recording.len(), 3);
    }

    #[test]
    fn process_payments_works() {
        let test_name = "process_payments_works";
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x01".to_string(), 1)
            .begin_batch()
            .response("rpc_result".to_string(), 7)
            .response("rpc_result_2".to_string(), 7)
            .end_batch()
            .start();
        let blockchain_interface_web3 = make_blockchain_interface_web3(port);
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let accounts_1 = make_payable_account(1);
        let accounts_2 = make_payable_account(2);
        let accounts = vec![accounts_1.clone(), accounts_2.clone()];
        let system = System::new(test_name);
        let agent = BlockchainAgentMock::default()
            .consuming_wallet_result(consuming_wallet)
            .agreed_fee_per_computation_unit_result(1);
        let msg = OutboundPaymentsInstructions::new(accounts, Box::new(agent), None);
        let persistent_config = PersistentConfigurationMock::new();
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_web3),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let (accountant, _, accountant_recording) = make_recorder();
        subject
            .pending_payable_confirmation
            .new_pp_fingerprints_sub_opt = Some(accountant.start().recipient());

        let result = subject
            .process_payments(msg.agent, msg.affordable_accounts)
            .wait();

        System::current().stop();
        system.run();
        let processed_payments = result.unwrap();
        assert_eq!(
            processed_payments[0],
            Correct(PendingPayable {
                recipient_wallet: accounts_1.wallet,
                hash: H256::from_str(
                    "cc73f3d5fe9fc3dac28b510ddeb157b0f8030b201e809014967396cdf365488a"
                )
                .unwrap()
            })
        );
        assert_eq!(
            processed_payments[1],
            Correct(PendingPayable {
                recipient_wallet: accounts_2.wallet,
                hash: H256::from_str(
                    "891d9ffa838aedc0bb2f6f7e9737128ce98bb33d07b4c8aa5645871e20d6cd13"
                )
                .unwrap()
            })
        );
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(recording.len(), 1);
    }

    #[test]
    fn process_payments_fails_on_get_transaction_count() {
        let test_name = "process_payments_fails_on_get_transaction_count";
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("trash transaction id".to_string(), 1)
            .start();
        let blockchain_interface_web3 = make_blockchain_interface_web3(port);
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let system = System::new(test_name);
        let agent = BlockchainAgentMock::default()
            .consuming_wallet_result(consuming_wallet)
            .agreed_fee_per_computation_unit_result(123);
        let msg = OutboundPaymentsInstructions::new(vec![], Box::new(agent), None);
        let persistent_config = configure_default_persistent_config(ZERO);
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_web3),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let (accountant, _, accountant_recording) = make_recorder();
        subject
            .pending_payable_confirmation
            .new_pp_fingerprints_sub_opt = Some(accountant.start().recipient());

        let result = subject
            .process_payments(msg.agent, msg.affordable_accounts)
            .wait();

        System::current().stop();
        system.run();
        let error_result = result.unwrap_err();
        assert_eq!(
            error_result,
            TransactionID(BlockchainError::QueryFailed(
                "Decoder error: Error(\"0x prefix is missing\", line: 0, column: 0) for wallet 0x2581…7849".to_string()
            ))
        );
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    fn assert_sending_error(error: &PayableTransactionError, error_msg: &str) {
        if let PayableTransactionError::Sending { msg, .. } = error {
            assert!(
                msg.contains(error_msg),
                "Actual Error message: {} does not contain this fragment {}",
                msg,
                error_msg
            );
        } else {
            panic!("Received wrong error: {:?}", error);
        }
    }

    #[test]
    fn blockchain_bridge_processes_requests_for_a_complete_and_null_transaction_receipt() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant = accountant.system_stop_conditions(match_every_type_id!(ScanError));
        let pending_payable_fingerprint_1 = make_pending_payable_fingerprint();
        let hash_1 = pending_payable_fingerprint_1.hash;
        let hash_2 = make_tx_hash(78989);
        let pending_payable_fingerprint_2 = PendingPayableFingerprint {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let first_response = ReceiptResponseBuilder::default()
            .status(U64::from(1))
            .transaction_hash(hash_1)
            .build();
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .raw_response(first_response)
            // A transaction receipt is null when the transaction is not available
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .end_batch()
            .start();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![
                pending_payable_fingerprint_1.clone(),
                pending_payable_fingerprint_2.clone(),
            ],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        let _ = addr.try_send(msg).unwrap();

        let system = System::new("transaction receipts");
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let report_transaction_receipt_message =
            accountant_recording.get_record::<ReportTransactionReceipts>(0);
        let mut expected_receipt = TransactionReceipt::default();
        expected_receipt.transaction_hash = hash_1;
        expected_receipt.status = Some(U64::from(1));
        assert_eq!(
            report_transaction_receipt_message,
            &ReportTransactionReceipts {
                fingerprints_with_receipts: vec![
                    (
                        TransactionReceiptResult::Found(expected_receipt),
                        pending_payable_fingerprint_1
                    ),
                    (
                        TransactionReceiptResult::NotPresent,
                        pending_payable_fingerprint_2
                    ),
                ],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn blockchain_bridge_logs_error_from_retrieving_received_payments() {
        init_test_logging();
        let port = find_free_port();
        // We have intentionally left out responses to cause this error
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.clone().recipient();
        let received_payments_subs: Recipient<ReceivedPayments> = accountant_addr.recipient();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_config = PersistentConfigurationMock::new()
            .max_block_count_result(Ok(Some(100_000)))
            .start_block_result(Ok(5)); // no set_start_block_result: set_start_block() must not be called
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        subject.received_payments_subs_opt = Some(received_payments_subs);
        let msg = RetrieveTransactions {
            recipient: make_wallet("blah"),
            response_skeleton_opt: None,
        };
        let subject_addr = subject.start();
        let system = System::new("test");

        subject_addr.try_send(msg).unwrap();

        system.run();
        let recording = accountant_recording_arc.lock().unwrap();
        let scan_error = recording.get_record::<ScanError>(0);
        assert_eq!(
            scan_error,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: None,
                msg: "Error while retrieving transactions: QueryFailed(\"Transport error: Error(IncompleteMessage)\")".to_string()
            }
        );
        assert_eq!(recording.len(), 1);
        TestLogHandler::new().exists_log_containing(
            "WARN: BlockchainBridge: Error while retrieving transactions: QueryFailed(\"Transport error: Error(IncompleteMessage)\")",
        );
    }

    #[test]
    fn handle_request_transaction_receipts_short_circuits_on_failure_from_remote_process_sends_back_all_good_results_and_logs_abort(
    ) {
        init_test_logging();
        let port = find_free_port();
        let block_number = U64::from(4545454);
        let contract_address = H160::from_low_u64_be(887766);
        let tx_receipt_response = ReceiptResponseBuilder::default()
            .block_number(block_number)
            .status(U64::from(1))
            .contract_address(contract_address)
            .build();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .raw_response(tx_receipt_response)
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .end_batch()
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ReportTransactionReceipts, ScanError))
            .start();
        let report_transaction_receipt_recipient: Recipient<ReportTransactionReceipts> =
            accountant_addr.clone().recipient();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.recipient();
        let hash_1 = make_tx_hash(111334);
        let hash_2 = make_tx_hash(100000);
        let hash_3 = make_tx_hash(0x1348d);
        let hash_4 = make_tx_hash(11111);
        let mut fingerprint_1 = make_pending_payable_fingerprint();
        fingerprint_1.hash = hash_1;
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 454,
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt: 3,
            amount: 3333,
            process_error: None,
        };
        let fingerprint_3 = PendingPayableFingerprint {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: hash_3,
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let fingerprint_4 = PendingPayableFingerprint {
            rowid: 450,
            timestamp: from_time_t(230_000_000),
            hash: hash_4,
            attempt: 1,
            amount: 7879,
            process_error: None,
        };
        let mut transaction_receipt = TransactionReceipt::default();
        transaction_receipt.block_number = Some(block_number);
        transaction_receipt.contract_address = Some(contract_address);
        transaction_receipt.status = Some(U64::from(1));
        let blockchain_interface = make_blockchain_interface_web3(port);
        let system = System::new("test_transaction_receipts");
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            false,
        );
        subject
            .pending_payable_confirmation
            .report_transaction_receipts_sub_opt = Some(report_transaction_receipt_recipient);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![
                fingerprint_1.clone(),
                fingerprint_2.clone(),
                fingerprint_3.clone(),
                fingerprint_4.clone(),
            ],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let subject_addr = subject.start();

        subject_addr.try_send(msg).unwrap();

        assert_eq!(system.run(), 0);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let report_receipts_msg = accountant_recording.get_record::<ReportTransactionReceipts>(0);
        assert_eq!(
            *report_receipts_msg,
            ReportTransactionReceipts {
                fingerprints_with_receipts: vec![
                    (TransactionReceiptResult::NotPresent, fingerprint_1),
                    (TransactionReceiptResult::Found(transaction_receipt), fingerprint_2),
                    (TransactionReceiptResult::NotPresent, fingerprint_3),
                    (TransactionReceiptResult::Error("RPC error: Error { code: ServerError(429), message: \"The requests per second (RPS) of your requests are higher than your plan allows.\", data: None }".to_string()), fingerprint_4)
                ],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
        TestLogHandler::new().exists_log_containing("DEBUG: BlockchainBridge: Aborting scanning; 1 transactions succeed and 3 transactions failed");
    }

    #[test]
    fn handle_request_transaction_receipts_short_circuits_if_submit_batch_fails() {
        init_test_logging();
        let (accountant, _, accountant_recording) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.clone().recipient();
        let report_transaction_recipient: Recipient<ReportTransactionReceipts> =
            accountant_addr.recipient();
        let hash_1 = make_tx_hash(0x1b2e6);
        let fingerprint_1 = PendingPayableFingerprint {
            rowid: 454,
            timestamp: SystemTime::now(),
            hash: hash_1,
            attempt: 3,
            amount: 3333,
            process_error: None,
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: make_tx_hash(222444),
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            false,
        );
        subject
            .pending_payable_confirmation
            .report_transaction_receipts_sub_opt = Some(report_transaction_recipient);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![fingerprint_1, fingerprint_2],
            response_skeleton_opt: None,
        };
        let system = System::new("test");

        let _ = subject.handle_scan_future(
            BlockchainBridge::handle_request_transaction_receipts,
            ScanType::PendingPayables,
            msg,
        );

        system.run();
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(
            recording.get_record::<ScanError>(0),
            &ScanError {
                scan_type: ScanType::PendingPayables,
                response_skeleton_opt: None,
                msg: "Blockchain error: Query failed: Transport error: Error(IncompleteMessage)"
                    .to_string()
            }
        );
        assert_eq!(recording.len(), 1);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Blockchain error: Query failed: Transport error: Error(IncompleteMessage)");
    }

    #[test]
    fn handle_retrieve_transactions_uses_latest_block_number_upon_get_block_number_error() {
        init_test_logging();
        let system = System::new(
            "handle_retrieve_transactions_uses_latest_block_number_upon_get_block_number_error",
        );
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xC8".to_string(), 0)
            .raw_response(r#"{
              "jsonrpc": "2.0",
              "id": 1,
              "result": [
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000000000002a",
                  "logIndex": "0x1d",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80",
                    "0x000000000000000000000000000000000000000066697273745f77616c6c6574"
                  ],
                  "transactionHash": "0x3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50",
                  "transactionIndex": "0x1d"
                },
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fc",
                  "data": "0x00000000000000000000000000000037",
                  "logIndex": "0x57",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80",
                    "0x000000000000000000000000000000000000007365636f6e645f77616c6c6574"
                  ],
                  "transactionHash": "0x788b1442414cb9c9a36dba2abe250763161a6f6395788a2e808f1b34e92beec1",
                  "transactionIndex": "0x54"
                }
              ]
            }"#.to_string())
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let earning_wallet = make_wallet("somewallet");
        let persistent_config = PersistentConfigurationMock::new()
            .max_block_count_result(Ok(Some(10000u64)))
            .start_block_result(Ok(100));
        let mut subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(port)),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        subject.received_payments_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let before = SystemTime::now();

        subject
            .handle_retrieve_transactions(retrieve_transactions)
            .wait()
            .unwrap();

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let expected_transactions = RetrievedBlockchainTransactions {
            new_start_block: 6040060u64,
            transactions: vec![
                BlockchainTransaction {
                    block_number: 6040059,
                    from: make_wallet("first_wallet"), // Points to topics of 1
                    wei_amount: 42,                    // Its points to the field data
                },
                BlockchainTransaction {
                    block_number: 6040060,
                    from: make_wallet("second_wallet"), // Points to topics of 1
                    wei_amount: 55,                     // Its points to the field data
                },
            ],
        };
        let mut payments_and_start_block = make_empty_payments_and_start_block();
        payments_and_start_block.payments = expected_transactions.transactions;
        payments_and_start_block.new_start_block = expected_transactions.new_start_block;
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_received_payment.len(), 1);
        let received_payments = accountant_received_payment.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments.timestamp, after);
        assert_eq!(
            received_payments,
            &ReceivedPayments {
                timestamp: received_payments.timestamp,
                payments_and_start_block,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn handle_retrieve_transactions_sends_received_payments_back_to_accountant() {
        let system =
            System::new("handle_retrieve_transactions_sends_received_payments_back_to_accountant");
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .response(
                vec![LogObject {
                    removed: false,
                    log_index: Some("0x20".to_string()),
                    transaction_index: Some("0x30".to_string()),
                    transaction_hash: Some(
                        "0x2222222222222222222222222222222222222222222222222222222222222222"
                            .to_string(),
                    ),
                    block_hash: Some(
                        "0x1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    ),
                    block_number: Some("0x7D0".to_string()), // 2000 decimal
                    address: "0x3333333333333333333333333333333333333334".to_string(),
                    data: "0x000000000000000000000000000000000000000000000000000000003b5dc100"
                        .to_string(),
                    topics: vec![
                        "0xddf252ad1be2c89b69c2b0680000000000006561726e696e675f77616c6c6574"
                            .to_string(),
                        "0xddf252ad1be2c89b69c2b0690000000000006561726e696e675f77616c6c6574"
                            .to_string(),
                    ],
                }],
                1,
            )
            .start();

        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr =
            accountant.system_stop_conditions(match_every_type_id!(ReceivedPayments));
        let earning_wallet = make_wallet("earning_wallet");
        let amount = 996000000;
        let expected_transactions = RetrievedBlockchainTransactions {
            new_start_block: 1000000000,
            transactions: vec![BlockchainTransaction {
                block_number: 2000,
                from: earning_wallet.clone(),
                wei_amount: amount,
            }],
        };
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(6))
            .max_block_count_result(Err(PersistentConfigError::NotPresent));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant_addr).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let before = SystemTime::now();

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
        let after = SystemTime::now();

        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let received_payments_message = accountant_recording.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments_message.timestamp, after);
        assert_eq!(
            received_payments_message,
            &ReceivedPayments {
                timestamp: received_payments_message.timestamp,
                payments_and_start_block: PaymentsAndStartBlock {
                    payments: expected_transactions.transactions,
                    new_start_block: expected_transactions.new_start_block,
                },
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn handle_retrieve_transactions_receives_invalid_topics() {
        init_test_logging();
        let test_name = "handle_retrieve_transactions_receives_invalid_topics";
        let system = System::new(test_name);
        let logger = Logger::new(test_name);
        let port = find_free_port();
        let expected_response_logs = vec![LogObject {
            removed: false,
            log_index: Some("0x20".to_string()),
            transaction_index: Some("0x30".to_string()),
            transaction_hash: Some(
                "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            ),
            block_hash: Some(
                "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            ),
            block_number: Some("0x7D0".to_string()), // 2000 decimal
            address: "0x3333333333333333333333333333333333333334".to_string(),
            data: "0x000000000000000000000000000000000000000000000000000000003b5dc100".to_string(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b0680000000000006561726e696e675f77616c6c6574".to_string(),
            ],
        }];
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .response(expected_response_logs, 1)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant.system_stop_conditions(match_every_type_id!(ScanError));
        let earning_wallet = make_wallet("earning_wallet");
        let mut blockchain_interface = make_blockchain_interface_web3(port);
        blockchain_interface.logger = logger;
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(6))
            .max_block_count_result(Err(PersistentConfigError::DatabaseError(
                "my tummy hurts".to_string(),
            )));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant_addr).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let scan_error_msg = accountant_recording.get_record::<ScanError>(0);
        assert_eq!(
            scan_error_msg,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: "Error while retrieving transactions: InvalidResponse".to_string(),
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Invalid response from blockchain server:"
        ));
    }

    #[test]
    fn handle_retrieve_transactions_receives_query_failed_and_updates_max_block() {
        init_test_logging();
        let test_name = "handle_retrieve_transactions_receives_query_failed_and_updates_max_block";
        let system = System::new(test_name);
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .err_response(-32005, "Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000", 0)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant = accountant.system_stop_conditions(match_every_type_id!(ScanError));
        let earning_wallet = make_wallet("earning_wallet");
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(6))
            .max_block_count_result(Err(PersistentConfigError::DatabaseError(
                "my tummy hurts".to_string(),
            )))
            .set_max_block_count_result(Ok(()));
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        subject.logger = Logger::new(test_name);
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let scan_error_msg = accountant_recording.get_record::<ScanError>(0);
        assert_eq!(
            scan_error_msg,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: "Error while retrieving transactions: QueryFailed(\"RPC error: Error { code: ServerError(-32005), message: \\\"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000\\\", data: None }\")".to_string(),
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Updated max_block_count to 1000 in database"
        ));
    }

    #[test]
    #[should_panic(
        expected = "Attempt to set new max block to 1000 failed due to: DatabaseError(\"my brain hurst\")"
    )]
    fn handle_retrieve_transactions_receives_query_failed_and_failed_update_max_block() {
        let system = System::new("test");
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .err_response(-32005, "Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000", 0)
            .start();
        let (accountant, _, _) = make_recorder();
        let earning_wallet = make_wallet("earning_wallet");
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(6))
            .max_block_count_result(Err(PersistentConfigError::DatabaseError(
                "my tummy hurts".to_string(),
            )))
            .set_max_block_count_result(Err(PersistentConfigError::DatabaseError(
                "my brain hurst".to_string(),
            )));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
    }

    #[test]
    #[should_panic(
        expected = "Cannot retrieve start block from database; payments to you may not be processed: TransactionError"
    )]
    fn handle_retrieve_transactions_panics_if_start_block_cannot_be_read() {
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Err(PersistentConfigError::TransactionError));
        let mut subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(find_free_port())),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        };

        let _ = subject.handle_retrieve_transactions(retrieve_transactions);
    }

    // TODO: GH-555: Remove system_stop_conditions while also confirming the ScanError msg wasn't sent.
    #[test]
    fn handle_scan_future_handles_success() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xC8".to_string(), 0)
            .raw_response(r#"{
              "jsonrpc": "2.0",
              "id": 1,
              "result": [
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000000000002a",
                  "logIndex": "0x1d",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80",
                    "0x000000000000000000000000000000000000000066697273745f77616c6c6574"
                  ],
                  "transactionHash": "0x3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50",
                  "transactionIndex": "0x1d"
                },
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fc",
                  "data": "0x00000000000000000000000000000037",
                  "logIndex": "0x57",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80",
                    "0x000000000000000000000000000000000000007365636f6e645f77616c6c6574"
                  ],
                  "transactionHash": "0x788b1442414cb9c9a36dba2abe250763161a6f6395788a2e808f1b34e92beec1",
                  "transactionIndex": "0x54"
                }
              ]
            }"#.to_string())
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let start_block = 2000;
        let wallet = make_wallet("somewallet");
        let persistent_config = PersistentConfigurationMock::default()
            .start_block_result(Ok(start_block))
            .max_block_count_result(Ok(None));
        let retrieve_transactions = RetrieveTransactions {
            recipient: wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let mut subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(port)),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let system = System::new("test");
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start();
        subject.received_payments_subs_opt = Some(accountant_addr.clone().recipient());
        subject.scan_error_subs_opt = Some(accountant_addr.recipient());
        subject.handle_scan_future(
            BlockchainBridge::handle_retrieve_transactions,
            ScanType::Receivables,
            retrieve_transactions,
        );

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let msg_opt = accountant_recording.get_record_opt::<ScanError>(0);
        assert_eq!(msg_opt, None, "We didnt expect a scan error: {:?}", msg_opt);
    }

    #[test]
    fn handle_scan_future_handles_failure() {
        assert_handle_scan_future_handles_failure(RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        });

        assert_handle_scan_future_handles_failure(RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        });
    }

    fn assert_handle_scan_future_handles_failure(msg: RetrieveTransactions) {
        init_test_logging();
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xC8".to_string(), 0)
            .err_response(-32005, "My tummy hurts", 0)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let start_block = 2000;
        let persistent_config = PersistentConfigurationMock::default()
            .start_block_result(Ok(start_block))
            .max_block_count_result(Ok(None));
        let mut subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(port)),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let system = System::new("test");
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start();
        subject.received_payments_subs_opt = Some(accountant_addr.clone().recipient());
        subject.scan_error_subs_opt = Some(accountant_addr.recipient());

        subject.handle_scan_future(
            BlockchainBridge::handle_retrieve_transactions,
            ScanType::Receivables,
            msg.clone(),
        );

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<ScanError>(0);
        assert_eq!(
            message,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: msg.response_skeleton_opt,
                msg: "Error while retrieving transactions: QueryFailed(\"RPC error: Error { code: ServerError(-32005), message: \\\"My tummy hurts\\\", data: None }\")"
                    .to_string()
            }
        );
        assert_eq!(accountant_recording.len(), 1);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Error while retrieving transactions: QueryFailed(\"RPC error: Error { code: ServerError(-32005), message: \\\"My tummy hurts\\\", data: None }\")");
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn blockchain_bridge_can_be_crashed_properly_but_not_improperly() {
        let crashable = true;
        let subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(find_free_port())),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            crashable,
        );

        prove_that_crash_request_handler_is_hooked_up(subject, CRASH_KEY);
    }

    #[test]
    fn extract_max_block_range_from_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"eth_getLogs block range too large, range: 33636, max: 3500\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(3500u64), max_block_count);
    }

    #[test]
    fn extract_max_block_range_from_pokt_error_response() {
        let result = BlockchainError::QueryFailed("Rpc(Error { code: ServerError(-32001), message: \"Relay request failed validation: invalid relay request: eth_getLogs block range limit (100000 blocks) exceeded\", data: None })".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(100000u64), max_block_count);
    }
    /*
        POKT (Polygon mainnet and amoy)
        {"jsonrpc":"2.0","id":7,"error":{"message":"You cannot query logs for more than 100000 blocks at once.","code":-32064}}
    */
    /*
        Ankr
        {"jsonrpc":"2.0","error":{"code":-32600,"message":"block range is too wide"},"id":null}%
    */
    #[test]
    fn extract_max_block_range_for_ankr_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32600), message: \"block range is too wide\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(None, max_block_count);
    }

    /*
    MaticVigil
    [{"error":{"message":"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000","code":-32005},"jsonrpc":"2.0","id":7},{"error":{"message":"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000","code":-32005},"jsonrpc":"2.0","id":8}]%
    */
    #[test]
    fn extract_max_block_range_for_matic_vigil_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1000), max_block_count);
    }

    /*
    Blockpi
    [{"jsonrpc":"2.0","id":7,"result":"0x21db466"},{"jsonrpc":"2.0","id":8,"error":{"code":-32602,"message":"eth_getLogs is limited to 1024 block range. Please check the parameter requirements at  https://docs.blockpi.io/documentations/api-reference"}}]
    */
    #[test]
    fn extract_max_block_range_for_blockpi_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"eth_getLogs is limited to 1024 block range. Please check the parameter requirements at  https://docs.blockpi.io/documentations/api-reference\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1024), max_block_count);
    }

    /*
    blastapi - completely rejected call on Public endpoint as won't handle eth_getLogs method on public API
    [{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found","data":{"method":""}}},{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request","data":{"message":"Cancelled due to validation errors in batch request"}}}] (edited)
    [8:50 AM]
    */

    #[test]
    fn extract_max_block_range_for_blastapi_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32601), message: \"Method not found\", data: \"'eth_getLogs' is not available on our public API. Head over to https://docs.blastapi.io/blast-documentation/tutorials-and-guides/using-blast-to-get-a-blockchain-endpoint for more information\" }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(None, max_block_count);
    }

    #[test]
    fn extract_max_block_range_for_expected_batch_got_single_error_response() {
        let result = BlockchainError::QueryFailed(
            "Got invalid response: Expected batch, got single.".to_string(),
        );

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1000), max_block_count);
    }

    #[test]
    fn make_connections_implements_panic_on_migration() {
        let data_dir = ensure_node_home_directory_exists(
            "blockchain_bridge",
            "make_connections_with_panic_on_migration",
        );

        let act = |data_dir: &Path| {
            BlockchainBridge::initialize_persistent_configuration(data_dir);
        };

        assert_on_initialization_with_panic_on_migration(&data_dir, &act);
    }

    #[test]
    fn calculate_fallback_start_block_number_works() {
        assert_eq!(
            BlockchainBridge::calculate_fallback_start_block_number(10_000, u64::MAX),
            10_000 + 1
        );
        assert_eq!(
            BlockchainBridge::calculate_fallback_start_block_number(5_000, 10_000),
            5_000 + 10_000
        );
    }
}

#[cfg(test)]
pub mod exportable_test_parts {
    use super::*;
    use crate::test_utils::recorder::make_blockchain_bridge_subs_from_recorder;
    use crate::test_utils::unshared_test_utils::SubsFactoryTestAddrLeaker;

    impl SubsFactory<BlockchainBridge, BlockchainBridgeSubs>
        for SubsFactoryTestAddrLeaker<BlockchainBridge>
    {
        fn make(&self, addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
            self.send_leaker_msg_and_return_meaningless_subs(
                addr,
                make_blockchain_bridge_subs_from_recorder,
            )
        }
    }
}
