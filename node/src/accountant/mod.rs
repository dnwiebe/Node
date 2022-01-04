// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_dao;
pub mod pending_payments_dao;
pub mod receivable_dao;
pub mod tools;

#[cfg(test)]
pub mod test_utils;

use crate::accountant::payable_dao::{PayableAccount, PayableDaoFactory, Payment};
use crate::accountant::pending_payments_dao::{PendingPaymentsDao, PendingPaymentsDaoFactory};
use crate::accountant::receivable_dao::{ReceivableAccount, ReceivableDaoFactory};
use crate::accountant::tools::accountant_tools::{Scanners, TransactionConfirmationTools};
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::{PaymentBackupRecord, RetrieveTransactions};
use crate::blockchain::blockchain_interface::{BlockchainError, Transaction};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::dao_utils::DaoFactoryReal;
use crate::database::db_migrations::MigratorConfig;
use crate::db_config::config_dao::ConfigDaoFactory;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::accountant::AccountantSubs;
use crate::sub_lib::accountant::ReportExitServiceConsumedMessage;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::utils::{handle_ui_crash_request, NODE_MAILBOX_CAPACITY};
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Addr;
use actix::AsyncContext;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Recipient;
use futures::future::Future;
use itertools::Itertools;
use lazy_static::lazy_static;
use masq_lib::crash_point::CrashPoint;
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiFinancialsRequest};
use masq_lib::messages::{UiFinancialsResponse, UiPayableAccount, UiReceivableAccount};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use payable_dao::PayableDao;
use receivable_dao::ReceivableDao;
use std::default::Default;
use std::ops::Add;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime};
use web3::types::{TransactionReceipt, H256};

pub const CRASH_KEY: &str = "ACCOUNTANT";
//TODO evaluate if these should be configurable by user in UI and/or CLI
pub const DEFAULT_PAYABLES_SCAN_INTERVAL: u64 = 300; // 5 minutes
pub const DEFAULT_RECEIVABLES_SCAN_INTERVAL: u64 = 300; // 5 minutes

const SECONDS_PER_DAY: i64 = 86_400;

lazy_static! {
    pub static ref PAYMENT_CURVES: PaymentCurves = PaymentCurves {
        payment_suggested_after_sec: SECONDS_PER_DAY,
        payment_grace_before_ban_sec: SECONDS_PER_DAY,
        permanent_debt_allowed_gwub: 10_000_000,
        balance_to_decrease_from_gwub: 1_000_000_000,
        balance_decreases_for_sec: 30 * SECONDS_PER_DAY,
        unban_when_balance_below_gwub: 10_000_000,
    };
}

//TODO this might become chain specific later on
pub const DEFAULT_PENDING_TRANSACTION_CHECKOUT_INTERVAL_MS: u64 = 5_000;
pub const DEFAULT_PENDING_TOO_LONG_SEC: u64 = 21_600; //6 hours

#[derive(Debug, PartialEq)]
pub enum DebtRecordingError {
    SignConversion(u64),
    RusqliteError(String),
}

#[derive(PartialEq, Debug, Clone)]
pub struct PaymentError(PaymentErrorKind, TransactionId);

#[derive(PartialEq, Debug, Clone)]
pub enum PaymentErrorKind {
    SignConversion(u64),
    RusqliteError(String),
    BlockchainError(String),
}

#[derive(PartialEq, Debug, Clone)]
pub struct PaymentCurves {
    pub payment_suggested_after_sec: i64,
    pub payment_grace_before_ban_sec: i64,
    pub permanent_debt_allowed_gwub: i64,
    pub balance_to_decrease_from_gwub: i64,
    pub balance_decreases_for_sec: i64,
    pub unban_when_balance_below_gwub: i64,
}

impl PaymentCurves {
    pub fn sugg_and_grace(&self, now: i64) -> i64 {
        now - self.payment_suggested_after_sec - self.payment_grace_before_ban_sec
    }

    pub fn sugg_thru_decreasing(&self, now: i64) -> i64 {
        self.sugg_and_grace(now) - self.balance_decreases_for_sec
    }
}

pub struct Accountant {
    config: AccountantConfig,
    consuming_wallet: Option<Wallet>,
    earning_wallet: Wallet,
    payable_dao: Box<dyn PayableDao>,
    receivable_dao: Box<dyn ReceivableDao>,
    pending_payments_dao: Box<dyn PendingPaymentsDao>,
    banned_dao: Box<dyn BannedDao>,
    crashable: bool,
    scanners: Scanners,
    transaction_confirmation: TransactionConfirmationTools,
    persistent_configuration: Box<dyn PersistentConfiguration>,
    report_accounts_payable_sub: Option<Recipient<ReportAccountsPayable>>,
    retrieve_transactions_sub: Option<Recipient<RetrieveTransactions>>,
    report_new_payments_sub: Option<Recipient<ReceivedPayments>>,
    report_sent_payments_sub: Option<Recipient<SentPayments>>,
    ui_message_sub: Option<Recipient<NodeToUiMessage>>,
    logger: Logger,
}

impl Actor for Accountant {
    type Context = Context<Self>;
}

#[derive(Debug, Eq, Message, PartialEq)]
pub struct ReceivedPayments {
    payments: Vec<Transaction>,
}

#[derive(Debug, Message, PartialEq)]
pub struct SentPayments {
    pub payments: Vec<Result<Payment, BlockchainError>>,
}

#[derive(Debug, Eq, Message, PartialEq)]
pub struct ScanForPayables {}

#[derive(Debug, Eq, Message, PartialEq)]
pub struct ScanForReceivables {}

#[derive(Debug, Eq, Message, PartialEq, Clone)]
pub struct ScanForPendingPayments {}

impl Handler<BindMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        self.handle_bind_message(msg);
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
    }
}

impl Handler<StartMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, _msg: StartMessage, ctx: &mut Self::Context) -> Self::Result {
        self.handle_start_message();

        let closure = Box::new(|msg: ScanForPendingPayments, interval: Duration| {
            ctx.notify_later(msg, interval)
        });
        self.transaction_confirmation
            .notify_later_handle_scan_for_pending_payments
            .notify_later(
                ScanForPendingPayments {},
                self.config.pending_payments_scan_interval,
                closure,
            );

        ctx.notify_later(ScanForPayables {}, self.config.payables_scan_interval);

        ctx.run_interval(self.config.receivables_scan_interval, |accountant, _ctx| {
            accountant.handle_scan_for_receivables()
        });
    }
}

impl Handler<ScanForPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForPayables, ctx: &mut Self::Context) -> Self::Result {
        self.scan_for_payables();
        let _ = ctx.notify_later(msg, self.config.payables_scan_interval);
    }
}

impl Handler<ScanForPendingPayments> for Accountant {
    type Result = ();

    fn handle(&mut self, _msg: ScanForPendingPayments, ctx: &mut Self::Context) -> Self::Result {
        self.scan_for_pending_payments();
        let closure = Box::new(|msg: ScanForPendingPayments, interval: Duration| {
            ctx.notify_later(msg, interval)
        });
        self.transaction_confirmation
            .notify_later_handle_scan_for_pending_payments
            .notify_later(
                ScanForPendingPayments {},
                self.config.pending_payments_scan_interval,
                closure,
            );
    }
}

impl Handler<ReceivedPayments> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReceivedPayments, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_received_payments(msg);
    }
}

impl Handler<SentPayments> for Accountant {
    type Result = ();

    fn handle(&mut self, sent_payments: SentPayments, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_sent_payments(sent_payments)
    }
}

impl Handler<ReportRoutingServiceProvidedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportRoutingServiceProvidedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_routing_service_provided_message(msg);
    }
}

impl Handler<ReportExitServiceProvidedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportExitServiceProvidedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_exit_service_provided_message(msg);
    }
}

impl Handler<ReportRoutingServiceConsumedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportRoutingServiceConsumedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_routing_service_consumed_message(msg);
    }
}

impl Handler<ReportExitServiceConsumedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportExitServiceConsumedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_exit_service_consumed_message(msg);
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct RequestTransactionReceipts {
    pub pending_payments: Vec<PaymentBackupRecord>,
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct ReportTransactionReceipts {
    pub payment_backups_with_receipts: Vec<(Option<TransactionReceipt>, PaymentBackupRecord)>,
}

impl Handler<ReportTransactionReceipts> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReportTransactionReceipts, ctx: &mut Self::Context) -> Self::Result {
        debug!(
            self.logger,
            "processing receipts for {} transactions",
            msg.payment_backups_with_receipts.len()
        );
        let statuses = self.handle_pending_transaction_check(msg);
        let (pending_transactions, cancellations) =
            Self::separate_transactions_if_still_pending(statuses);
        if !pending_transactions.is_empty() {
            self.update_backup_of_pending_transaction(pending_transactions);
        }
        if !cancellations.is_empty() {
            debug!(self.logger, "{} cancellations", cancellations.len());
            self.handle_transaction_cancellation(cancellations, ctx);
        }
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct CancelFailedPendingTransaction {
    pub id: TransactionId,
}

impl Handler<CancelFailedPendingTransaction> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: CancelFailedPendingTransaction,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_cancel_pending_transaction(msg)
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct ConfirmPendingTransaction {
    pub payment_backup: PaymentBackupRecord,
}

impl Handler<ConfirmPendingTransaction> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ConfirmPendingTransaction, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_confirm_pending_transaction(msg)
    }
}

impl Handler<PaymentBackupRecord> for Accountant {
    type Result = ();
    fn handle(&mut self, msg: PaymentBackupRecord, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_payment_backup(msg)
    }
}

impl Handler<NodeFromUiMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        let client_id = msg.client_id;
        if let Ok((body, context_id)) = UiFinancialsRequest::fmb(msg.clone().body) {
            self.handle_financials(client_id, context_id, body);
        } else {
            handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
        }
    }
}

impl Accountant {
    pub fn new(
        config: &BootstrapperConfig,
        payable_dao_factory: Box<dyn PayableDaoFactory>,
        receivable_dao_factory: Box<dyn ReceivableDaoFactory>,
        pending_payments_dao_factory: Box<dyn PendingPaymentsDaoFactory>,
        banned_dao_factory: Box<dyn BannedDaoFactory>,
        config_dao_factory: Box<dyn ConfigDaoFactory>,
    ) -> Accountant {
        Accountant {
            config: config.accountant_config.clone(),
            consuming_wallet: config.consuming_wallet.clone(),
            earning_wallet: config.earning_wallet.clone(),
            payable_dao: payable_dao_factory.make(),
            receivable_dao: receivable_dao_factory.make(),
            pending_payments_dao: pending_payments_dao_factory.make(),
            banned_dao: banned_dao_factory.make(),
            crashable: config.crash_point == CrashPoint::Message,
            scanners: Scanners::default(),
            transaction_confirmation: TransactionConfirmationTools::default(),
            persistent_configuration: Box::new(PersistentConfigurationReal::new(
                config_dao_factory.make(),
            )),
            report_accounts_payable_sub: None,
            retrieve_transactions_sub: None,
            report_new_payments_sub: None,
            report_sent_payments_sub: None,
            ui_message_sub: None,
            logger: Logger::new("Accountant"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Accountant>) -> AccountantSubs {
        AccountantSubs {
            bind: recipient!(addr, BindMessage),
            start: recipient!(addr, StartMessage),
            report_routing_service_provided: recipient!(addr, ReportRoutingServiceProvidedMessage),
            report_exit_service_provided: recipient!(addr, ReportExitServiceProvidedMessage),
            report_routing_service_consumed: recipient!(addr, ReportRoutingServiceConsumedMessage),
            report_exit_service_consumed: recipient!(addr, ReportExitServiceConsumedMessage),
            report_new_payments: recipient!(addr, ReceivedPayments),
            payment_backup: recipient!(addr, PaymentBackupRecord),
            report_transaction_receipts: recipient!(addr, ReportTransactionReceipts),
            report_sent_payments: recipient!(addr, SentPayments),
            ui_message_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    pub fn dao_factory(data_directory: &Path) -> DaoFactoryReal {
        DaoFactoryReal::new(data_directory, false, MigratorConfig::panic_on_migration())
    }

    fn scan_for_payables(&self) {
        debug!(self.logger, "Scanning for payables");

        let all_non_pending_payables = self.payable_dao.non_pending_payables();
        debug!(
            self.logger,
            "{}",
            Self::investigate_debt_extremes(&all_non_pending_payables)
        );
        let qualified_payables = all_non_pending_payables
            .into_iter()
            .filter(Accountant::should_pay)
            .collect::<Vec<PayableAccount>>();
        info!(
            self.logger,
            "Chose {} qualified debts to pay",
            qualified_payables.len()
        );
        debug!(
            self.logger,
            "{}",
            Self::payments_debug_summary(&qualified_payables)
        );
        if !qualified_payables.is_empty() {
            self.report_accounts_payable_sub
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(ReportAccountsPayable {
                    accounts: qualified_payables,
                })
                .expect("BlockchainBridge is dead")
        }
    }

    fn scan_for_delinquencies(&self) {
        debug!(self.logger, "Scanning for delinquencies");

        let now = SystemTime::now();
        self.receivable_dao
            .new_delinquencies(now, &PAYMENT_CURVES)
            .into_iter()
            .for_each(|account| {
                self.banned_dao.ban(&account.wallet);
                let (balance, age) = Self::balance_and_age(&account);
                info!(
                    self.logger,
                    "Wallet {} (balance: {} MASQ, age: {} sec) banned for delinquency",
                    account.wallet,
                    balance,
                    age.as_secs()
                )
            });

        self.receivable_dao
            .paid_delinquencies(&PAYMENT_CURVES)
            .into_iter()
            .for_each(|account| {
                self.banned_dao.unban(&account.wallet);
                let (balance, age) = Self::balance_and_age(&account);
                info!(
                    self.logger,
                    "Wallet {} (balance: {} MASQ, age: {} sec) is no longer delinquent: unbanned",
                    account.wallet,
                    balance,
                    age.as_secs()
                )
            });
    }

    fn scan_for_received_payments(&self) {
        let future_logger = self.logger.clone();
        debug!(
            self.logger,
            "Scanning for payments to {}", self.earning_wallet
        );
        let future_report_new_payments_sub = self.report_new_payments_sub.clone();
        let start_block = match self.persistent_configuration.start_block() {
            Ok(start_block) => start_block,
            Err(pce) => {
                error!(
                    self.logger,
                    "Could not retrieve start block: {:?} - aborting received-payment scan", pce
                );
                return;
            }
        };
        let future = self
            .retrieve_transactions_sub
            .as_ref()
            .expect("BlockchainBridge is unbound")
            .send(RetrieveTransactions {
                start_block,
                recipient: self.earning_wallet.clone(),
            })
            .then(move |transactions_possibly| match transactions_possibly {
                Ok(Ok(ref vec)) if vec.is_empty() => {
                    debug!(future_logger, "No payments detected");
                    Ok(())
                }
                Ok(Ok(transactions)) => {
                    future_report_new_payments_sub
                        .expect("Accountant is unbound")
                        .try_send(ReceivedPayments {
                            payments: transactions,
                        })
                        .expect("Accountant is dead.");
                    Ok(())
                }
                Ok(Err(e)) => {
                    warning!(
                        future_logger,
                        "Unable to retrieve transactions from Blockchain Bridge: {:?}",
                        e
                    );
                    Err(())
                }
                Err(e) => {
                    error!(
                        future_logger,
                        "Unable to send to Blockchain Bridge: {:?}", e
                    );
                    thread::sleep(Duration::from_secs(1));
                    panic!("Unable to send to Blockchain Bridge: {:?}", e);
                }
            });
        actix::spawn(future);
    }

    fn scan_for_pending_payments(&self) {
        debug!(self.logger, "Scanning for pending payments");
        let filtered_pending_payments = self.pending_payments_dao.return_all_payment_backups();
        if !filtered_pending_payments.is_empty() {
            debug!(
                self.logger,
                "Found {} pending payments to process",
                filtered_pending_payments.len()
            );
            self.transaction_confirmation
                .request_transaction_receipts_subs_opt
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(RequestTransactionReceipts {
                    pending_payments: filtered_pending_payments,
                })
                .expect("BlockchainBridge is dead");
        } else {
            debug!(self.logger, "No pending payment found during last scan")
        }
    }

    fn balance_and_age(account: &ReceivableAccount) -> (String, Duration) {
        let balance = format!("{}", (account.balance as f64) / 1_000_000_000.0);
        let age = account
            .last_received_timestamp
            .elapsed()
            .unwrap_or_else(|_| Duration::new(0, 0));
        (balance, age)
    }

    fn should_pay(payable: &PayableAccount) -> bool {
        Self::payable_exceeded_threshold(payable).is_some()
    }

    fn payable_exceeded_threshold(payable: &PayableAccount) -> Option<u64> {
        // TODO: This calculation should be done in the database, if possible
        let time_since_last_paid = SystemTime::now()
            .duration_since(payable.last_paid_timestamp)
            .expect("Internal error")
            .as_secs();

        if time_since_last_paid <= PAYMENT_CURVES.payment_suggested_after_sec as u64 {
            return None;
        }

        if payable.balance <= PAYMENT_CURVES.permanent_debt_allowed_gwub {
            return None;
        }

        let threshold = Accountant::calculate_payout_threshold(time_since_last_paid);
        if payable.balance as f64 > threshold {
            Some(threshold as u64)
        } else {
            None
        }
    }

    fn calculate_payout_threshold(x: u64) -> f64 {
        let m = -((PAYMENT_CURVES.balance_to_decrease_from_gwub as f64
            - PAYMENT_CURVES.permanent_debt_allowed_gwub as f64)
            / (PAYMENT_CURVES.balance_decreases_for_sec as f64
                - PAYMENT_CURVES.payment_suggested_after_sec as f64));
        let b = PAYMENT_CURVES.balance_to_decrease_from_gwub as f64
            - m * PAYMENT_CURVES.payment_suggested_after_sec as f64;
        m * x as f64 + b
    }

    fn record_service_provided(
        &self,
        service_rate: u64,
        byte_rate: u64,
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate * (payload_size as u64);
        let total_charge = service_rate + byte_charge;
        if !self.our_wallet(wallet) {
            match self.receivable_dao
                .as_ref()
                .more_money_receivable(wallet, total_charge) {
                Ok(_) => (),
                Err(DebtRecordingError::SignConversion(_)) => error! (
                    self.logger,
                    "Overflow error recording service provided for {}: service rate {}, byte rate {}, payload size {}. Skipping",
                    wallet,
                    service_rate,
                    byte_rate,
                    payload_size
                ),
                Err(e)=> panic!("Recording services provided for {} but has hit fatal database error: {:?}", wallet, e)
            };
        } else {
            info!(
                self.logger,
                "Not recording service provided for our wallet {}", wallet
            );
        }
    }

    fn record_service_consumed(
        &self,
        service_rate: u64,
        byte_rate: u64,
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate * (payload_size as u64);
        let total_charge = service_rate + byte_charge;
        if !self.our_wallet(wallet) {
            match self.payable_dao
                .as_ref()
                .more_money_payable(wallet, total_charge) {
                Ok(_) => (),
                Err(DebtRecordingError::SignConversion(_)) => error! (
                    self.logger,
                    "Overflow error recording consumed services from {}: service rate {}, byte rate {}, payload size {}. Skipping",
                    wallet,
                    service_rate,
                    byte_rate,
                    payload_size
                ),
                Err(e) => panic!("Recording services consumed from {} but has hit fatal database error: {:?}", wallet, e)
            };
        } else {
            info!(
                self.logger,
                "Not recording service consumed to our wallet {}", wallet
            );
        }
    }

    fn our_wallet(&self, wallet: &Wallet) -> bool {
        match &self.consuming_wallet {
            Some(ref consuming) if consuming.address() == wallet.address() => true,
            _ => wallet.address() == self.earning_wallet.address(),
        }
    }

    //for debugging only
    fn investigate_debt_extremes(all_non_pending_payables: &[PayableAccount]) -> String {
        if all_non_pending_payables.is_empty() {
            "Payable scan found no debts".to_string()
        } else {
            struct PayableInfo {
                balance: i64,
                age: Duration,
            }
            let now = SystemTime::now();
            let init = (
                PayableInfo {
                    balance: 0,
                    age: Duration::ZERO,
                },
                PayableInfo {
                    balance: 0,
                    age: Duration::ZERO,
                },
            );
            let (biggest, oldest) = all_non_pending_payables.iter().fold(init, |sofar, p| {
                let (mut biggest, mut oldest) = sofar;
                let p_age = now
                    .duration_since(p.last_paid_timestamp)
                    .expect("Payable time is corrupt");
                {
                    //seek for a test for this if you don't understand the purpose
                    let check_age_significance_across =
                        || -> bool { p.balance == biggest.balance && p_age > biggest.age };
                    if p.balance > biggest.balance || check_age_significance_across() {
                        biggest = PayableInfo {
                            balance: p.balance,
                            age: p_age,
                        }
                    }
                    let check_balance_significance_across =
                        || -> bool { p_age == oldest.age && p.balance > oldest.balance };
                    if p_age > oldest.age || check_balance_significance_across() {
                        oldest = PayableInfo {
                            balance: p.balance,
                            age: p_age,
                        }
                    }
                }
                (biggest, oldest)
            });
            format!("Payable scan found {} debts; the biggest is {} owed for {}sec, the oldest is {} owed for {}sec",
                    all_non_pending_payables.len(), biggest.balance, biggest.age.as_secs(),
                    oldest.balance, oldest.age.as_secs())
        }
    }

    fn payments_debug_summary(qualified_payables: &[PayableAccount]) -> String {
        let now = SystemTime::now();
        let list = qualified_payables
            .iter()
            .map(|payable| {
                let p_age = now
                    .duration_since(payable.last_paid_timestamp)
                    .expect("Payable time is corrupt");
                let threshold =
                    Self::payable_exceeded_threshold(payable).expect("Threshold suddenly changed!");
                format!(
                    "{} owed for {}sec exceeds threshold: {}; creditor: {}",
                    payable.balance,
                    p_age.as_secs(),
                    threshold,
                    payable.wallet
                )
            })
            .join("\n");
        String::from("Paying qualified debts:\n").add(&list)
    }

    fn handle_bind_message(&mut self, msg: BindMessage) {
        self.report_accounts_payable_sub =
            Some(msg.peer_actors.blockchain_bridge.report_accounts_payable);
        self.retrieve_transactions_sub =
            Some(msg.peer_actors.blockchain_bridge.retrieve_transactions);
        self.report_new_payments_sub = Some(msg.peer_actors.accountant.report_new_payments);
        self.report_sent_payments_sub = Some(msg.peer_actors.accountant.report_sent_payments);
        self.ui_message_sub = Some(msg.peer_actors.ui_gateway.node_to_ui_message_sub);
        self.transaction_confirmation
            .request_transaction_receipts_subs_opt = Some(
            msg.peer_actors
                .blockchain_bridge
                .request_transaction_receipts,
        );
        info!(self.logger, "Accountant bound");
    }

    fn handle_start_message(&self) {
        self.scanners.pending_payments.scan(self);
        self.scanners.payables.scan(self);
        self.scanners.receivables.scan(self);
    }

    fn handle_scan_for_receivables(&self) {
        self.scan_for_received_payments();
        self.scan_for_delinquencies();
    }

    fn handle_received_payments(&mut self, received_payments: ReceivedPayments) {
        self.receivable_dao
            .as_mut()
            .more_money_received(received_payments.payments);
    }

    fn handle_sent_payments(&self, sent_payments: SentPayments) {
        debug!(
            self.logger,
            "Total number of attempts to send a payment transaction: {}",
            sent_payments.payments.len()
        );
        let (ok, err) = Self::separate_early_errors(sent_payments, &self.logger);
        self.mark_pending_payments(ok);
        debug!(self.logger, "Found this portion of errors: {}", err.len());
        if !err.is_empty() {
            err.into_iter().for_each(|err|
            if let Some(hash) = err.carries_transaction_hash(){
                self.discard_incomplete_transaction_with_a_failure(hash)
            } else {debug!(self.logger,"Forgetting a transaction attempt that even did not reach the signing stage")})
        }
    }

    fn discard_incomplete_transaction_with_a_failure(&self, hash: H256) {
        if let Some(rowid) = self.pending_payments_dao.payment_backup_exists(hash) {
            debug!(
                self.logger,
                "Deleting an existing backup for a failed transaction {}", hash
            );
            if let Err(e) = self.pending_payments_dao.delete_payment_backup(rowid) {
                panic!("Database unmaintainable; payment backup deletion has stayed undone due to {:?}",e)
            }
        };

        warning!(
            self.logger,
            "Failed transaction with a hash '{}' but without the backup - thrown out",
            hash
        )
    }

    fn handle_report_routing_service_provided_message(
        &mut self,
        msg: ReportRoutingServiceProvidedMessage,
    ) {
        debug!(
            self.logger,
            "Charging routing of {} bytes to wallet {}", msg.payload_size, msg.paying_wallet
        );
        self.record_service_provided(
            msg.service_rate,
            msg.byte_rate,
            msg.payload_size,
            &msg.paying_wallet,
        );
    }

    fn handle_report_exit_service_provided_message(
        &mut self,
        msg: ReportExitServiceProvidedMessage,
    ) {
        debug!(
            self.logger,
            "Charging exit service for {} bytes to wallet {} at {} per service and {} per byte",
            msg.payload_size,
            msg.paying_wallet,
            msg.service_rate,
            msg.byte_rate
        );
        self.record_service_provided(
            msg.service_rate,
            msg.byte_rate,
            msg.payload_size,
            &msg.paying_wallet,
        );
    }

    fn handle_report_routing_service_consumed_message(
        &mut self,
        msg: ReportRoutingServiceConsumedMessage,
    ) {
        debug!(
            self.logger,
            "Accruing debt to wallet {} for consuming routing service {} bytes",
            msg.earning_wallet,
            msg.payload_size
        );
        self.record_service_consumed(
            msg.service_rate,
            msg.byte_rate,
            msg.payload_size,
            &msg.earning_wallet,
        );
    }

    fn handle_report_exit_service_consumed_message(
        &mut self,
        msg: ReportExitServiceConsumedMessage,
    ) {
        debug!(
            self.logger,
            "Accruing debt to wallet {} for consuming exit service {} bytes",
            msg.earning_wallet,
            msg.payload_size
        );
        self.record_service_consumed(
            msg.service_rate,
            msg.byte_rate,
            msg.payload_size,
            &msg.earning_wallet,
        );
    }

    fn handle_financials(&mut self, client_id: u64, context_id: u64, request: UiFinancialsRequest) {
        let payables = self
            .payable_dao
            .top_records(request.payable_minimum_amount, request.payable_maximum_age)
            .iter()
            .map(|account| UiPayableAccount {
                wallet: account.wallet.to_string(),
                age: SystemTime::now()
                    .duration_since(account.last_paid_timestamp)
                    .expect("Bad interval")
                    .as_secs(),
                amount: account.balance as u64,
                pending_transaction_rowid: account.pending_payment_rowid_opt,
            })
            .collect_vec();
        let total_payable = self.payable_dao.total();
        let receivables = self
            .receivable_dao
            .top_records(
                request.receivable_minimum_amount,
                request.receivable_maximum_age,
            )
            .iter()
            .map(|account| UiReceivableAccount {
                wallet: account.wallet.to_string(),
                age: SystemTime::now()
                    .duration_since(account.last_received_timestamp)
                    .expect("Bad interval")
                    .as_secs(),
                amount: account.balance as u64,
            })
            .collect_vec();
        let total_receivable = self.receivable_dao.total();
        let body = UiFinancialsResponse {
            payables,
            total_payable,
            receivables,
            total_receivable,
        }
        .tmb(context_id);
        self.ui_message_sub
            .as_ref()
            .expect("UiGateway not bound")
            .try_send(NodeToUiMessage {
                target: ClientId(client_id),
                body,
            })
            .expect("UiGateway is dead");
    }

    fn handle_cancel_pending_transaction(&self, msg: CancelFailedPendingTransaction) {
        match self
            .pending_payments_dao
            .mark_failure(msg.id.rowid)
        {
            Ok(_) => warning!(
                self.logger,
                "Broken transaction {} left with an error mark; you should take over the care of this transaction to make sure your debts will be paid because there is no automated process that can fix this without you", msg.id.hash),
            Err(e) => panic!("Unsuccessful attempt for transaction {} to mark fatal error at pending payment backup for transaction due to {:?}; database unreliable", msg.id.hash,e),
        }
    }

    fn handle_confirm_pending_transaction(&self, msg: ConfirmPendingTransaction) {
        if let Err(e) = self.payable_dao.transaction_confirmed(&msg.payment_backup) {
            panic!(
                "Was unable to uncheck pending payment '{}' after confirmation due to '{:?}'",
                msg.payment_backup.hash, e.0
            )
        } else {
            debug!(
                self.logger,
                "Confirmation of transaction {}; record for payable table took change",
                msg.payment_backup.hash
            );
            if let Err(e) = self
                .pending_payments_dao
                .delete_payment_backup(msg.payment_backup.rowid)
            {
                panic!("Was unable to delete payment backup '{}' after successful transaction due to '{:?}'",msg.payment_backup.hash,e)
            } else {
                info!(
                    self.logger,
                    "Transaction {:#x} has gone through the whole confirmation process succeeding",
                    msg.payment_backup.hash
                )
            }
        }
    }

    fn separate_early_errors(
        sent_payments: SentPayments,
        logger: &Logger,
    ) -> (Vec<Payment>, Vec<BlockchainError>) {
        type SentPaymentType = Vec<Result<Payment, BlockchainError>>;
        let (ok, err): (SentPaymentType, SentPaymentType) = sent_payments
            .payments
            .into_iter()
            .partition(|payment| payment.is_ok());
        (
            ok.into_iter().flatten().collect(),
            err.into_iter().map(|item|{
                let error = item.expect_err("partition failed");
                logger.warning(||
                        match &error {
                            BlockchainError::TransactionFailed { msg: _, hash_opt: _ } => format!("Encountered transaction error that occurred close to the actual sending due to '{:?}'", error),
                            x => format!("Payment failure due to '{:?}'. Please check your blockchain service URL configuration.", x)
                        }
                    );
                error
            }).collect()
        )
    }

    fn mark_pending_payments(&self, sent_payments: Vec<Payment>) {
        sent_payments
            .into_iter()
            .for_each(|payment| {
                let rowid = match self.pending_payments_dao.payment_backup_exists(payment.transaction) {
                    Some(rowid) => rowid,
                    None => panic!("Payment backup for {} doesn't exist but should by now; system unreliable", payment.transaction)
                };
                match self.payable_dao.as_ref().mark_pending_payment_rowid(&payment.to, TransactionId { hash: payment.transaction, rowid }) {
                    Ok(()) => (),
                    Err(e) => panic!("Was unable to create a mark in payables for a new pending payment '{}' due to '{:?}'", payment.transaction, e.0)
                }
                debug!(self.logger, "Payment '{}' has been marked as pending in the payable table",payment.transaction)
            })
    }

    fn handle_pending_transaction_check(
        &self,
        msg: ReportTransactionReceipts,
    ) -> Vec<PendingTransactionStatus> {
        msg.payment_backups_with_receipts
            .into_iter()
            .map(|(receipt_opt, payment)|
                match receipt_opt {
                    Some(receipt) =>
                                    self.check_out_transaction_receipt(
                                        receipt,
                                        payment,
                                        &self.logger,
                                    ),
                    None => {
                        debug!(self.logger,"DEBUG: Accountant: Interpreting a receipt for transaction '{}' but none was given; attempt {}, {}ms since sending", payment.hash, payment.attempt,elapsed_in_ms(payment.timestamp));
                        PendingTransactionStatus::StillPending(TransactionId{ hash: payment.hash, rowid: payment.rowid })
                    }
                }
            )
            .collect()
    }

    fn check_out_transaction_receipt(
        &self,
        receipt: TransactionReceipt,
        payment: PaymentBackupRecord,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        fn handle_none_receipt(
            payment: PaymentBackupRecord,
            pending_interval: u64,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            info!(logger,"Pending transaction '{}' couldn't be confirmed at attempt {} at {}ms after its sending",payment.hash, payment.attempt, elapsed_in_ms(payment.timestamp));
            let elapsed = payment.timestamp.elapsed().expect("we should be older now");
            let transaction_id = TransactionId {
                hash: payment.hash,
                rowid: payment.rowid,
            };
            if pending_interval <= elapsed.as_secs() {
                warning!(logger,"Pending transaction '{}' has exceeded the maximum time allowed ({}sec) \
         for being pending and the confirmation process is going to be aborted now at the finished attempt {}; manual resolving is required from the \
          user to make the transaction paid",payment.hash,pending_interval,payment.attempt);
                PendingTransactionStatus::Failure(transaction_id)
            } else {
                PendingTransactionStatus::StillPending(transaction_id)
            }
        }
        fn handle_status_with_success(
            payment: PaymentBackupRecord,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            info!(
                logger,
                "Transaction '{}' has been added to the blockchain; detected locally at attempt {} at {}ms after its sending",
                payment.hash,
                payment.attempt,
                elapsed_in_ms(payment.timestamp)
            );
            PendingTransactionStatus::Confirmed(payment)
        }
        fn handle_status_with_failure(
            payment: &PaymentBackupRecord,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            warning!(logger,"Pending transaction '{}' announced as a failure, checking out attempt {} after {}ms from its sending",payment.hash,payment.attempt,elapsed_in_ms(payment.timestamp));
            PendingTransactionStatus::Failure(payment.into())
        }
        match receipt.status{
                None => handle_none_receipt(payment, self.config.when_pending_too_long_sec, logger),
                Some(status_code) =>
                    match status_code.as_u64(){
                    0 => handle_status_with_failure(&payment,logger),
                    1 => handle_status_with_success(payment,logger),
                    other => unreachable!("tx receipt for pending '{}' - tx status: code other than 0 or 1 shouldn't be possible, but was {}",payment.hash,other)
                }
            }
    }

    fn separate_transactions_if_still_pending(
        statuses: Vec<PendingTransactionStatus>,
    ) -> (Vec<PendingTransactionStatus>, Vec<PendingTransactionStatus>) {
        statuses
            .into_iter()
            .partition(|status| !status.is_non_pending())
    }

    fn update_backup_of_pending_transaction(
        &self,
        pending_payments: Vec<PendingTransactionStatus>,
    ) {
        pending_payments
            .into_iter()
            .for_each(|pending_payment| match pending_payment {
                PendingTransactionStatus::StillPending(id) => match self
                    .pending_payments_dao
                    .update_backup_after_scan_cycle(id.rowid)
                {
                    Ok(_) => trace!(self.logger, "Updated backup for rowid: {} ", id.rowid),
                    Err(e) => panic!("Failure on updating payment backup due to {:?}", e),
                },
                _ => unreachable!("we are operating behind a filter; should not happen"),
            })
    }

    fn handle_transaction_cancellation(
        &self,
        cancellations: Vec<PendingTransactionStatus>,
        ctx: &mut Context<Self>,
    ) {
        cancellations.into_iter().for_each(|status| {
            if let PendingTransactionStatus::Failure(transaction_id) = status {
                self.cancel_failed_transaction(transaction_id, ctx)
            } else if let PendingTransactionStatus::Confirmed(payment) = status {
                self.confirm_transaction(payment, ctx)
            }
        });
    }

    fn cancel_failed_transaction(&self, transaction_id: TransactionId, ctx: &mut Context<Self>) {
        let closure = |msg: CancelFailedPendingTransaction| ctx.notify(msg);
        self.transaction_confirmation
            .notify_handle_cancel_failed_transaction
            .notify(
                CancelFailedPendingTransaction { id: transaction_id },
                Box::new(closure),
            )
    }

    fn confirm_transaction(&self, payment_backup: PaymentBackupRecord, ctx: &mut Context<Self>) {
        let closure = |msg: ConfirmPendingTransaction| ctx.notify(msg);
        self.transaction_confirmation
            .notify_handle_confirm_transaction
            .notify(
                ConfirmPendingTransaction { payment_backup },
                Box::new(closure),
            );
    }

    fn handle_payment_backup(&self, msg: PaymentBackupRecord) {
        match self
            .pending_payments_dao
            .insert_payment_backup(msg.hash, msg.amount, msg.timestamp)
        {
            Ok(_) => debug!(self.logger, "Processed a backup for payment '{}'", msg.hash),
            Err(e) => warning!(
                self.logger,
                "WARN: Accountant: Failed to make a backup for pending payment '{}' due to '{:?}'",
                msg.hash,
                e
            ),
        }
    }
}

// At the time of this writing, Rust 1.44.0 was unpredictably producing
// segfaults on the Mac when using u64::try_from (i64). This is an attempt to
// work around that.
pub fn jackass_unsigned_to_signed(unsigned: u64) -> Result<i64, u64> {
    if unsigned <= (i64::MAX as u64) {
        Ok(unsigned as i64)
    } else {
        Err(unsigned)
    }
}

fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
    timestamp
        .elapsed()
        .expect("time calculation for elapsed failed")
        .as_millis()
}

#[derive(Debug, PartialEq, Clone)]
enum PendingTransactionStatus {
    StillPending(TransactionId), //will go back, update slightly the record, wait in an interval, and start a new round
    Failure(TransactionId),      //official tx failure
    Confirmed(PaymentBackupRecord), //tx was fully processed and successful
}

impl PendingTransactionStatus {
    fn is_non_pending(&self) -> bool {
        !matches!(self, Self::StillPending { .. })
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct TransactionId {
    pub hash: H256,
    pub rowid: u64,
}

impl From<&PaymentBackupRecord> for TransactionId {
    fn from(payment_backup: &PaymentBackupRecord) -> Self {
        Self {
            hash: payment_backup.hash,
            rowid: payment_backup.rowid,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::accountant::pending_payments_dao::PendingPaymentDaoError;
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::test_utils::{
        bc_from_ac_plus_earning_wallet, bc_from_ac_plus_wallets, make_accountant,
        make_payment_backup, make_receivable_account, BannedDaoFactoryMock, ConfigDaoFactoryMock,
        PayableDaoFactoryMock, PendingPaymentsDaoFactoryMock, PendingPaymentsDaoMock,
        ReceivableDaoFactoryMock,
    };
    use crate::accountant::test_utils::{AccountantBuilder, BannedDaoMock};
    use crate::accountant::tools::accountant_tools::NullScanner;
    use crate::blockchain::blockchain_bridge::BlockchainBridge;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::blockchain::blockchain_interface::Transaction;
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::blockchain::tool_wrappers::SendTransactionToolWrapperNull;
    use crate::database::dao_utils::from_time_t;
    use crate::database::dao_utils::to_time_t;
    use crate::db_config::mocks::ConfigDaoMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils::{
        prove_that_crash_request_handler_is_hooked_up, CleanUpMessage, DummyActor,
        NotifyHandleMock, NotifyLaterHandleMock,
    };
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::{Arbiter, System};
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_gateway::{MessageBody, MessageTarget, NodeFromUiMessage, NodeToUiMessage};
    use std::cell::RefCell;
    use std::ops::Sub;
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::sync::{Arc, MutexGuard};
    use std::thread;
    use std::time::Duration;
    use std::time::SystemTime;
    use web3::types::U256;
    use web3::types::{TransactionReceipt, H256};

    #[derive(Debug, Default)]
    pub struct PayableDaoMock {
        account_status_parameters: Arc<Mutex<Vec<Wallet>>>,
        account_status_results: RefCell<Vec<Option<PayableAccount>>>,
        more_money_payable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        more_money_payable_results: RefCell<Vec<Result<(), DebtRecordingError>>>,
        non_pending_payables_params: Arc<Mutex<Vec<()>>>,
        non_pending_payables_results: RefCell<Vec<Vec<PayableAccount>>>,
        mark_pending_payment_rowid_parameters: Arc<Mutex<Vec<(Wallet, TransactionId)>>>,
        mark_pending_payment_rowid_results: RefCell<Vec<Result<(), PaymentError>>>,
        transaction_confirmed_params: Arc<Mutex<Vec<PaymentBackupRecord>>>,
        transaction_confirmed_results: RefCell<Vec<Result<(), PaymentError>>>,
        transaction_canceled_params: Arc<Mutex<Vec<TransactionId>>>,
        transaction_canceled_results: RefCell<Vec<Result<(), PaymentError>>>,
        top_records_parameters: Arc<Mutex<Vec<(u64, u64)>>>,
        top_records_results: RefCell<Vec<Vec<PayableAccount>>>,
        total_results: RefCell<Vec<u64>>,
        have_non_pending_payables_shut_down_the_system: bool,
    }

    impl PayableDao for PayableDaoMock {
        fn more_money_payable(
            &self,
            wallet: &Wallet,
            amount: u64,
        ) -> Result<(), DebtRecordingError> {
            self.more_money_payable_parameters
                .lock()
                .unwrap()
                .push((wallet.clone(), amount));
            self.more_money_payable_results.borrow_mut().remove(0)
        }

        fn mark_pending_payment_rowid(
            &self,
            wallet: &Wallet,
            transaction_id: TransactionId,
        ) -> Result<(), PaymentError> {
            self.mark_pending_payment_rowid_parameters
                .lock()
                .unwrap()
                .push((wallet.clone(), transaction_id));
            self.mark_pending_payment_rowid_results
                .borrow_mut()
                .remove(0)
        }

        fn transaction_confirmed(&self, payment: &PaymentBackupRecord) -> Result<(), PaymentError> {
            self.transaction_confirmed_params
                .lock()
                .unwrap()
                .push(payment.clone());
            self.transaction_confirmed_results.borrow_mut().remove(0)
        }

        fn transaction_canceled(&self, transaction_id: TransactionId) -> Result<(), PaymentError> {
            self.transaction_canceled_params
                .lock()
                .unwrap()
                .push(transaction_id);
            self.transaction_canceled_results.borrow_mut().remove(0)
        }

        fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount> {
            self.account_status_parameters
                .lock()
                .unwrap()
                .push(wallet.clone());
            self.account_status_results.borrow_mut().remove(0)
        }

        fn non_pending_payables(&self) -> Vec<PayableAccount> {
            self.non_pending_payables_params.lock().unwrap().push(());
            if self.have_non_pending_payables_shut_down_the_system
                && self.non_pending_payables_results.borrow().is_empty()
            {
                System::current().stop();
                return vec![];
            }
            self.non_pending_payables_results.borrow_mut().remove(0)
        }

        fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount> {
            self.top_records_parameters
                .lock()
                .unwrap()
                .push((minimum_amount, maximum_age));
            self.top_records_results.borrow_mut().remove(0)
        }

        fn total(&self) -> u64 {
            self.total_results.borrow_mut().remove(0)
        }
    }

    impl PayableDaoMock {
        pub fn new() -> PayableDaoMock {
            PayableDaoMock::default()
        }

        fn more_money_payable_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        ) -> Self {
            self.more_money_payable_parameters = parameters;
            self
        }

        fn more_money_payable_result(self, result: Result<(), DebtRecordingError>) -> Self {
            self.more_money_payable_results.borrow_mut().push(result);
            self
        }

        fn non_pending_payables_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
            self.non_pending_payables_params = params.clone();
            self
        }

        fn non_pending_payables_result(self, result: Vec<PayableAccount>) -> Self {
            self.non_pending_payables_results.borrow_mut().push(result);
            self
        }

        pub fn mark_pending_payment_params(
            mut self,
            parameters: &Arc<Mutex<Vec<(Wallet, TransactionId)>>>,
        ) -> Self {
            self.mark_pending_payment_rowid_parameters = parameters.clone();
            self
        }

        pub fn mark_pending_payment_result(self, result: Result<(), PaymentError>) -> Self {
            self.mark_pending_payment_rowid_results
                .borrow_mut()
                .push(result);
            self
        }

        pub fn transaction_confirmed_params(
            mut self,
            params: &Arc<Mutex<Vec<PaymentBackupRecord>>>,
        ) -> Self {
            self.transaction_confirmed_params = params.clone();
            self
        }

        pub fn transaction_confirmed_result(self, result: Result<(), PaymentError>) -> Self {
            self.transaction_confirmed_results.borrow_mut().push(result);
            self
        }

        pub fn transaction_canceled_params(
            mut self,
            params: &Arc<Mutex<Vec<TransactionId>>>,
        ) -> Self {
            self.transaction_canceled_params = params.clone();
            self
        }

        pub fn transaction_canceled_result(self, result: Result<(), PaymentError>) -> Self {
            self.transaction_canceled_results.borrow_mut().push(result);
            self
        }

        fn top_records_parameters(mut self, parameters: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
            self.top_records_parameters = parameters.clone();
            self
        }

        fn top_records_result(self, result: Vec<PayableAccount>) -> Self {
            self.top_records_results.borrow_mut().push(result);
            self
        }

        fn total_result(self, result: u64) -> Self {
            self.total_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Debug, Default)]
    pub struct ReceivableDaoMock {
        account_status_parameters: Arc<Mutex<Vec<Wallet>>>,
        account_status_results: RefCell<Vec<Option<ReceivableAccount>>>,
        more_money_receivable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        more_money_receivable_results: RefCell<Vec<Result<(), DebtRecordingError>>>,
        more_money_received_parameters: Arc<Mutex<Vec<Vec<Transaction>>>>,
        more_money_received_results: RefCell<Vec<Result<(), PaymentError>>>,
        receivables_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        new_delinquencies_parameters: Arc<Mutex<Vec<(SystemTime, PaymentCurves)>>>,
        new_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        paid_delinquencies_parameters: Arc<Mutex<Vec<PaymentCurves>>>,
        paid_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        top_records_parameters: Arc<Mutex<Vec<(u64, u64)>>>,
        top_records_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        total_results: RefCell<Vec<u64>>,
        have_new_delinquencies_shutdown_the_system: bool,
    }

    impl ReceivableDao for ReceivableDaoMock {
        fn more_money_receivable(
            &self,
            wallet: &Wallet,
            amount: u64,
        ) -> Result<(), DebtRecordingError> {
            self.more_money_receivable_parameters
                .lock()
                .unwrap()
                .push((wallet.clone(), amount));
            self.more_money_receivable_results.borrow_mut().remove(0)
        }

        fn more_money_received(&mut self, transactions: Vec<Transaction>) {
            self.more_money_received_parameters
                .lock()
                .unwrap()
                .push(transactions);
        }

        fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount> {
            self.account_status_parameters
                .lock()
                .unwrap()
                .push(wallet.clone());

            self.account_status_results.borrow_mut().remove(0)
        }

        fn receivables(&self) -> Vec<ReceivableAccount> {
            self.receivables_results.borrow_mut().remove(0)
        }

        fn new_delinquencies(
            &self,
            now: SystemTime,
            payment_curves: &PaymentCurves,
        ) -> Vec<ReceivableAccount> {
            self.new_delinquencies_parameters
                .lock()
                .unwrap()
                .push((now, payment_curves.clone()));
            if self.have_new_delinquencies_shutdown_the_system
                && self.new_delinquencies_results.borrow().is_empty()
            {
                System::current().stop();
                return vec![];
            }
            self.new_delinquencies_results.borrow_mut().remove(0)
        }

        fn paid_delinquencies(&self, payment_curves: &PaymentCurves) -> Vec<ReceivableAccount> {
            self.paid_delinquencies_parameters
                .lock()
                .unwrap()
                .push(payment_curves.clone());
            self.paid_delinquencies_results.borrow_mut().remove(0)
        }

        fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<ReceivableAccount> {
            self.top_records_parameters
                .lock()
                .unwrap()
                .push((minimum_amount, maximum_age));
            self.top_records_results.borrow_mut().remove(0)
        }

        fn total(&self) -> u64 {
            self.total_results.borrow_mut().remove(0)
        }
    }

    impl ReceivableDaoMock {
        pub fn new() -> ReceivableDaoMock {
            Self::default()
        }

        fn more_money_receivable_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(Wallet, u64)>>>,
        ) -> Self {
            self.more_money_receivable_parameters = parameters.clone();
            self
        }

        fn more_money_receivable_result(self, result: Result<(), DebtRecordingError>) -> Self {
            self.more_money_receivable_results.borrow_mut().push(result);
            self
        }

        fn more_money_received_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<Vec<Transaction>>>>,
        ) -> Self {
            self.more_money_received_parameters = parameters.clone();
            self
        }

        fn more_money_received_result(self, result: Result<(), PaymentError>) -> Self {
            self.more_money_received_results.borrow_mut().push(result);
            self
        }

        fn new_delinquencies_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(SystemTime, PaymentCurves)>>>,
        ) -> Self {
            self.new_delinquencies_parameters = parameters.clone();
            self
        }

        fn new_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
            self.new_delinquencies_results.borrow_mut().push(result);
            self
        }

        fn paid_delinquencies_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<PaymentCurves>>>,
        ) -> Self {
            self.paid_delinquencies_parameters = parameters.clone();
            self
        }

        fn paid_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
            self.paid_delinquencies_results.borrow_mut().push(result);
            self
        }

        fn top_records_parameters(mut self, parameters: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
            self.top_records_parameters = parameters.clone();
            self
        }

        fn top_records_result(self, result: Vec<ReceivableAccount>) -> Self {
            self.top_records_results.borrow_mut().push(result);
            self
        }

        fn total_result(self, result: u64) -> Self {
            self.total_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn new_calls_factories_properly() {
        let config = BootstrapperConfig::new();
        let payable_dao_factory_called = Rc::new(RefCell::new(false));
        let payable_dao = PayableDaoMock::new();
        let payable_dao_factory =
            PayableDaoFactoryMock::new(Box::new(payable_dao)).called(&payable_dao_factory_called);
        let receivable_dao_factory_called = Rc::new(RefCell::new(false));
        let receivable_dao = ReceivableDaoMock::new();
        let receivable_dao_factory =
            ReceivableDaoFactoryMock::new(receivable_dao).called(&receivable_dao_factory_called);
        let payment_recover_dao_factory_called = Rc::new(RefCell::new(false));
        let payment_recover_dao = PendingPaymentsDaoMock::default();
        let payment_recover_dao_factory = PendingPaymentsDaoFactoryMock::new(payment_recover_dao)
            .called(&payment_recover_dao_factory_called);
        let banned_dao_factory_called = Rc::new(RefCell::new(false));
        let banned_dao = BannedDaoMock::new();
        let banned_dao_factory =
            BannedDaoFactoryMock::new(banned_dao).called(&banned_dao_factory_called);
        let config_dao_factory_called = Rc::new(RefCell::new(false));
        let config_dao = ConfigDaoMock::new();
        let config_dao_factory =
            ConfigDaoFactoryMock::new(config_dao).called(&config_dao_factory_called);

        let _ = Accountant::new(
            &config,
            Box::new(payable_dao_factory),
            Box::new(receivable_dao_factory),
            Box::new(payment_recover_dao_factory),
            Box::new(banned_dao_factory),
            Box::new(config_dao_factory),
        );

        assert_eq!(payable_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(receivable_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(
            payment_recover_dao_factory_called.as_ref(),
            &RefCell::new(true)
        );
        assert_eq!(banned_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(config_dao_factory_called.as_ref(), &RefCell::new(true));
    }

    #[test]
    fn financials_request_produces_financials_response() {
        let payable_top_records_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::new()
            .top_records_parameters(&payable_top_records_parameters_arc)
            .top_records_result(vec![
                PayableAccount {
                    wallet: make_wallet("earning 1"),
                    balance: 12345678,
                    last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(10000)),
                    pending_payment_rowid_opt: Some(789),
                },
                PayableAccount {
                    wallet: make_wallet("earning 2"),
                    balance: 12345679,
                    last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(10001)),
                    pending_payment_rowid_opt: None,
                },
            ])
            .total_result(23456789);
        let receivable_top_records_parameters_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .top_records_parameters(&receivable_top_records_parameters_arc)
            .top_records_result(vec![
                ReceivableAccount {
                    wallet: make_wallet("consuming 1"),
                    balance: 87654321,
                    last_received_timestamp: SystemTime::now().sub(Duration::from_secs(20000)),
                },
                ReceivableAccount {
                    wallet: make_wallet("consuming 2"),
                    balance: 87654322,
                    last_received_timestamp: SystemTime::now().sub(Duration::from_secs(20001)),
                },
            ])
            .total_result(98765432);
        let system = System::new("test");
        let subject = make_accountant(
            Some(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payables_scan_interval: Duration::from_millis(10_000),
                    receivables_scan_interval: Duration::from_millis(10_000),
                    pending_payments_scan_interval: Duration::from_millis(
                        DEFAULT_PENDING_TRANSACTION_CHECKOUT_INTERVAL_MS,
                    ),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
                make_wallet("some_wallet_address"),
            )),
            Some(payable_dao),
            Some(receivable_dao),
            None,
            None,
            None,
        );
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: MessageBody {
                opcode: "financials".to_string(),
                path: Conversation(2222),
                payload: Ok(r#"{"payableMinimumAmount": 50001, "payableMaximumAge": 50002, "receivableMinimumAmount": 50003, "receivableMaximumAge": 50004}"#.to_string()),
            }
        };

        subject_addr.try_send(ui_message).unwrap();

        System::current().stop();
        system.run();
        let payable_top_records_parameters = payable_top_records_parameters_arc.lock().unwrap();
        assert_eq!(*payable_top_records_parameters, vec![(50001, 50002)]);
        let receivable_top_records_parameters =
            receivable_top_records_parameters_arc.lock().unwrap();
        assert_eq!(*receivable_top_records_parameters, vec![(50003, 50004)]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(response.target, MessageTarget::ClientId(1234));
        assert_eq!(response.body.opcode, "financials".to_string());
        assert_eq!(response.body.path, Conversation(2222));
        let parsed_payload =
            serde_json::from_str::<UiFinancialsResponse>(&response.body.payload.as_ref().unwrap())
                .unwrap();
        assert_eq!(
            parsed_payload,
            UiFinancialsResponse {
                payables: vec![
                    UiPayableAccount {
                        wallet: "0x00000000000000000000006561726e696e672031".to_string(),
                        age: 10000,
                        amount: 12345678,
                        pending_transaction_rowid: Some(789)
                    },
                    UiPayableAccount {
                        wallet: "0x00000000000000000000006561726e696e672032".to_string(),
                        age: 10001,
                        amount: 12345679,
                        pending_transaction_rowid: None,
                    }
                ],
                total_payable: 23456789,
                receivables: vec![
                    UiReceivableAccount {
                        wallet: "0x000000000000000000636f6e73756d696e672031".to_string(),
                        age: 20000,
                        amount: 87654321,
                    },
                    UiReceivableAccount {
                        wallet: "0x000000000000000000636f6e73756d696e672032".to_string(),
                        age: 20001,
                        amount: 87654322,
                    }
                ],
                total_receivable: 98765432
            }
        );
    }

    #[test]
    fn accountant_calls_payable_dao_to_mark_payment_sent() {
        let backup_record_exists_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payment_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_wallet = make_wallet("paying_you");
        let expected_amount = 12;
        let expected_hash = H256::from("transaction_hash".keccak256());
        let expected_timestamp = SystemTime::now();
        let expected_rowid = 45623;
        let pending_payments_dao = PendingPaymentsDaoMock::default()
            .payment_backup_exists_params(&backup_record_exists_params_arc)
            .payment_backup_exists_result(Some(expected_rowid));
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payment_params(&mark_pending_payment_params_arc)
            .mark_pending_payment_result(Ok(()));
        let system = System::new("accountant_calls_payable_dao_payment_sent_when_sent_payments");
        let accountant = make_accountant(
            Some(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payables_scan_interval: Duration::from_millis(10_000),
                    receivables_scan_interval: Duration::from_millis(10_000),
                    pending_payments_scan_interval: Duration::from_millis(
                        DEFAULT_PENDING_TRANSACTION_CHECKOUT_INTERVAL_MS,
                    ),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
                make_wallet("some_wallet_address"),
            )),
            Some(payable_dao),
            None,
            Some(pending_payments_dao),
            None,
            None,
        );

        let expected_payment = Payment::new(
            expected_wallet.clone(),
            expected_amount,
            expected_hash.clone(),
            expected_timestamp,
        );
        let send_payments = SentPayments {
            payments: vec![Ok(expected_payment.clone())],
        };
        let subject = accountant.start();

        subject
            .try_send(send_payments)
            .expect("unexpected actix error");
        System::current().stop();
        system.run();

        let read_payment_record_params = backup_record_exists_params_arc.lock().unwrap();
        assert_eq!(*read_payment_record_params, vec![expected_hash]);
        let mark_pending_payment_params = mark_pending_payment_params_arc.lock().unwrap();
        let actual = mark_pending_payment_params.get(0).unwrap();
        assert_eq!(
            actual,
            &(
                expected_wallet,
                TransactionId {
                    hash: expected_hash,
                    rowid: expected_rowid
                }
            )
        );
    }

    #[test]
    fn accountant_logs_and_aborts_when_handle_sent_payments_finds_an_error_from_post_hash_time_and_the_payment_backup_does_not_exist(
    ) {
        init_test_logging();
        let system = System::new("sent payments failure without backup");
        let pending_payments_dao =
            PendingPaymentsDaoMock::default().payment_backup_exists_result(None);
        let accountant = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(PendingPaymentsDaoFactoryMock::new(
                pending_payments_dao,
            )))
            .build();
        let send_payments = SentPayments {
            payments: vec![Err(BlockchainError::TransactionFailed {
                msg: "SQLite migraine".to_string(),
                hash_opt: Some(H256::from_uint(&U256::from(12345))),
            })],
        };
        let subject = accountant.start();

        subject
            .try_send(send_payments)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let log_handler = TestLogHandler::new();
        log_handler.exists_no_log_containing(
            "DEBUG: Accountant: Deleting an existing backup for a failed transaction",
        );
        log_handler.exists_log_containing("WARN: Accountant: Encountered transaction error that occurred close to \
         the actual sending due to 'TransactionFailed { msg: \"SQLite migraine\", hash_opt: Some(0x0000000000000000000000000000000000000000000000000000000000003039) }'");
        log_handler.exists_log_containing(
            r#"WARN: Accountant: Failed transaction with a hash '0x0000…3039' but without the backup - thrown out"#,
        );
    }

    #[test]
    fn handle_sent_payments_discover_failed_transaction_and_payment_backup_was_really_created() {
        init_test_logging();
        let payment_backup_exists_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payment_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_payment_backup_params_arc = Arc::new(Mutex::new(vec![]));
        let good_transaction_rowid = 3;
        let failed_transaction_rowid = 5;
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payment_params(&mark_pending_payment_params_arc)
            .mark_pending_payment_result(Ok(()));
        let system = System::new("accountant_calls_payable_dao_payment_sent_when_sent_payments");
        let pending_payments_dao = PendingPaymentsDaoMock::default()
            .payment_backup_exists_params(&payment_backup_exists_params_arc)
            .payment_backup_exists_result(Some(good_transaction_rowid)) //for the correct transaction before mark_pending_payment
            .payment_backup_exists_result(Some(failed_transaction_rowid)) //err, to find out if the backup has been created or if the error occurred before that
            .delete_payment_backup_params(&delete_payment_backup_params_arc)
            .delete_payment_backup_result(Ok(()));
        let subject = AccountantBuilder::default()
            .payable_dao_factory(Box::new(PayableDaoFactoryMock::new(Box::new(payable_dao))))
            .pending_payments_dao_factory(Box::new(PendingPaymentsDaoFactoryMock::new(
                pending_payments_dao,
            )))
            .build();
        let wallet = make_wallet("blah");
        let hash_tx_1 = H256::from_uint(&U256::from(5555));
        let hash_tx_2 = H256::from_uint(&U256::from(12345));

        let send_payments = SentPayments {
            payments: vec![
                Ok(Payment {
                    to: wallet.clone(),
                    amount: 5656,
                    timestamp: SystemTime::now(),
                    transaction: hash_tx_1,
                }),
                Err(BlockchainError::TransactionFailed {
                    msg: "Payment attempt failed".to_string(),
                    hash_opt: Some(hash_tx_2),
                }),
            ],
        };
        let subject_addr = subject.start();

        subject_addr
            .try_send(send_payments)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let payment_backup_exists_params = payment_backup_exists_params_arc.lock().unwrap();
        assert_eq!(*payment_backup_exists_params, vec![hash_tx_1, hash_tx_2]);
        let mark_pending_payment_params = mark_pending_payment_params_arc.lock().unwrap();
        assert_eq!(
            *mark_pending_payment_params,
            vec![(
                wallet,
                TransactionId {
                    hash: hash_tx_1,
                    rowid: good_transaction_rowid
                }
            )]
        );
        let delete_payment_backup_params = delete_payment_backup_params_arc.lock().unwrap();
        assert_eq!(
            *delete_payment_backup_params,
            vec![failed_transaction_rowid]
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Deleting an existing backup for a failed transaction 0x0000…3039",
        );
    }

    #[test]
    fn accountant_sends_report_accounts_payable_to_blockchain_bridge_when_qualified_payments_found()
    {
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge = blockchain_bridge.retrieve_transactions_response(Ok(vec![]));
        let amount_1 = PAYMENT_CURVES.balance_to_decrease_from_gwub + 100;
        let amount_2 = PAYMENT_CURVES.balance_to_decrease_from_gwub + 101;
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("blah"),
                balance: amount_1,
                last_paid_timestamp: from_time_t(100_000_000),
                pending_payment_rowid_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("foo"),
                balance: amount_2,
                last_paid_timestamp: from_time_t(100_000_000),
                pending_payment_rowid_opt: None,
            },
        ];

        let payable_dao = PayableDaoMock::new().non_pending_payables_result(accounts.clone());
        let system = System::new("report_accounts_payable forwarded to blockchain_bridge");
        let mut subject = make_accountant(
            Some(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payables_scan_interval: Duration::from_secs(100), //scan intervals deliberately big to demonstrate that we don't do the intervals yet
                    receivables_scan_interval: Duration::from_secs(100),
                    pending_payments_scan_interval: Duration::from_secs(100),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
                make_wallet("some_wallet_address"),
            )),
            Some(payable_dao),
            None,
            None,
            None,
            None,
        );
        subject.scanners.pending_payments = Box::new(NullScanner); //skipping scanner for pending payments
        subject.scanners.receivables = Box::new(NullScanner); //turning off scanner for receivables
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();

        send_bind_message!(accountant_subs, peer_actors);
        send_start_message!(accountant_subs);

        System::current().stop();
        system.run();
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let report_accounts_payables_msgs: Vec<&ReportAccountsPayable> = (0
            ..blockchain_bridge_recorder.len())
            .flat_map(|index| {
                blockchain_bridge_recorder.get_record_opt::<ReportAccountsPayable>(index)
            })
            .collect();
        assert_eq!(
            report_accounts_payables_msgs,
            vec![&ReportAccountsPayable { accounts }]
        );
    }

    #[test]
    fn accountant_receives_new_payments_to_the_receivables_dao() {
        let wallet = make_wallet("wallet0");
        let earning_wallet = make_wallet("earner3000");
        let gwei_amount = 42u64;
        let expected_payment = Transaction {
            block_number: 7u64,
            from: wallet.clone(),
            gwei_amount,
        };
        let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_received_parameters(&more_money_received_params_arc)
            .more_money_received_result(Ok(()))
            .more_money_received_result(Ok(()));
        let accountant = make_accountant(
            Some(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payables_scan_interval: Duration::from_secs(10_000),
                    receivables_scan_interval: Duration::from_secs(10_000),
                    pending_payments_scan_interval: Duration::from_secs(100),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
                earning_wallet.clone(),
            )),
            Some(PayableDaoMock::new().non_pending_payables_result(vec![])),
            Some(receivable_dao),
            None,
            None,
            None,
        );

        let system = System::new("accountant_receives_new_payments_to_the_receivables_dao");
        let subject = accountant.start();

        subject
            .try_send(ReceivedPayments {
                payments: vec![expected_payment.clone(), expected_payment.clone()],
            })
            .expect("unexpected actix error");
        System::current().stop();
        system.run();
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(1, more_money_received_params.len());

        let more_money_received_params = more_money_received_params.get(0).unwrap();
        assert_eq!(2, more_money_received_params.len());

        let first_payment = more_money_received_params.get(0).unwrap();
        assert_eq!(expected_payment.from, first_payment.from);
        assert_eq!(gwei_amount, first_payment.gwei_amount);
        let second_payment = more_money_received_params.get(1).unwrap();
        assert_eq!(expected_payment.from, second_payment.from);
        assert_eq!(gwei_amount, second_payment.gwei_amount);
    }

    #[test]
    fn accountant_scans_after_startup() {
        init_test_logging();
        let return_unresolved_backup_records_params_arc = Arc::new(Mutex::new(vec![]));
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let new_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, _) = make_recorder();
        let blockchain_bridge = blockchain_bridge.retrieve_transactions_response(Ok(vec![]));
        let system = System::new("accountant_scans_after_startup");
        let config = bc_from_ac_plus_wallets(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100), //making sure we cannot enter the first repeated scanning
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_millis(100), //except here, where we use it to stop the system
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("buy"),
            make_wallet("hi"),
        );
        let mut pending_payments_dao = PendingPaymentsDaoMock::default()
            .return_all_payment_backups_params(&return_unresolved_backup_records_params_arc)
            .return_all_payment_backups_result(vec![]);
        pending_payments_dao.have_return_all_backup_records_shut_down_the_system = true;
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_params_arc)
            .new_delinquencies_result(vec![])
            .paid_delinquencies_parameters(&paid_delinquencies_params_arc)
            .paid_delinquencies_result(vec![]);
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![]);
        let persistent_config = PersistentConfigurationMock::default()
            .start_block_params(&start_block_params_arc)
            .start_block_result(Ok(123456));
        let subject = make_accountant(
            Some(config),
            Some(payable_dao),
            Some(receivable_dao),
            Some(pending_payments_dao),
            None,
            Some(persistent_config),
        );
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run();
        let tlh = TestLogHandler::new();
        tlh.await_log_containing("DEBUG: Accountant: Scanning for payables", 1000u64);
        tlh.exists_log_containing(&format!(
            "DEBUG: Accountant: Scanning for payments to {}",
            make_wallet("hi")
        ));
        tlh.exists_log_containing("DEBUG: Accountant: Scanning for delinquencies");
        tlh.exists_log_containing("DEBUG: Accountant: Scanning for pending payments");
        //some more week proofs but still good enough
        //proof of calling a piece of scan_for_pending_payments
        let return_unresolved_backup_records_params =
            return_unresolved_backup_records_params_arc.lock().unwrap();
        assert_eq!(*return_unresolved_backup_records_params, vec![(), ()]); //the last ends this test calling System::current.stop()
                                                                            //proof of calling a piece of scan_for_payables()
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        assert_eq!(*non_pending_payables_params, vec![()]);
        //proof of calling a piece of scan_for_receivables()
        let start_block_params = start_block_params_arc.lock().unwrap();
        assert_eq!(*start_block_params, vec![()]);
        //proof of calling pieces of scan_for_delinquencies()
        let mut new_delinquencies_params = new_delinquencies_params_arc.lock().unwrap();
        let (captured_timestamp, captured_curves) = new_delinquencies_params.remove(0);
        assert!(new_delinquencies_params.is_empty());
        assert!(
            captured_timestamp < SystemTime::now()
                && captured_timestamp >= from_time_t(to_time_t(SystemTime::now()) - 5)
        );
        assert_eq!(captured_curves, *PAYMENT_CURVES);
        let paid_delinquencies_params = paid_delinquencies_params_arc.lock().unwrap();
        assert_eq!(paid_delinquencies_params.len(), 1);
        assert_eq!(paid_delinquencies_params[0], *PAYMENT_CURVES);
    }

    #[test]
    fn accountant_payment_received_scan_timer_triggers_scanning_for_payments() {
        let new_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let paying_wallet = make_wallet("wallet0");
        let earning_wallet = make_wallet("earner3000");
        let amount = 42u64;
        let expected_transactions = vec![Transaction {
            block_number: 7u64,
            from: paying_wallet.clone(),
            gwei_amount: amount,
        }];
        let (blockchain_bridge_mock, _, blockchain_bridge_recording) = make_recorder();
        let blockchain_bridge_mock = blockchain_bridge_mock
            .retrieve_transactions_response(Ok(vec![]))
            .retrieve_transactions_response(Ok(expected_transactions.clone()))
            .retrieve_transactions_response(Ok(vec![]));
        let (accountant_mock, _, accountant_recording_arc) = make_recorder();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_millis(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            earning_wallet.clone(),
        );
        let system =
            System::new("accountant_payment_received_scan_timer_triggers_scanning_for_payments");
        let mut receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_params_arc)
            .new_delinquencies_result(vec![])
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]) //extra last, because it has some inertia
            .paid_delinquencies_result(vec![]); //TODO remove this extra supply later, not sure why needed and either if it can help
                                                //TODO: it sometimes fails for Mac, later when we have configurable scanning intervals we will be able to set these intervals some to be short and a long one for the last cycle (GH-485)
                                                // GH-492 may be also help, since it looks like it squeals because of the futures and run_interval() which still there
        receivable_dao.have_new_delinquencies_shutdown_the_system = true;
        let config_mock = PersistentConfigurationMock::new()
            .start_block_result(Ok(5))
            .start_block_result(Ok(10));
        let mut subject = make_accountant(
            Some(config),
            None,
            Some(receivable_dao),
            None,
            None,
            Some(config_mock),
        );
        subject.scanners.payables = Box::new(NullScanner); //skipping
        subject.scanners.pending_payments = Box::new(NullScanner); //skipping
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge_mock)
            .accountant(accountant_mock)
            .build();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);
        send_start_message!(subject_subs);

        system.run();

        let retrieve_transactions_recording = blockchain_bridge_recording.lock().unwrap();
        let retrieve_transactions_message_1 =
            retrieve_transactions_recording.get_record::<RetrieveTransactions>(0);
        assert_eq!(
            retrieve_transactions_message_1,
            &RetrieveTransactions {
                start_block: 5,
                recipient: earning_wallet.clone(),
            },
        );
        let retrieve_transactions_message_2 =
            retrieve_transactions_recording.get_record::<RetrieveTransactions>(1);
        assert_eq!(
            retrieve_transactions_message_2,
            &RetrieveTransactions {
                start_block: 10,
                recipient: earning_wallet,
            }
        );
        let received_payments_recording = accountant_recording_arc.lock().unwrap();
        let received_payments_message =
            received_payments_recording.get_record::<ReceivedPayments>(0);
        assert_eq!(
            &ReceivedPayments {
                payments: expected_transactions
            },
            received_payments_message
        );
        let new_delinquencies_params = new_delinquencies_params_arc.lock().unwrap();
        assert_eq!(new_delinquencies_params.len(), 3) //the third is supposed to kill the system
    }

    #[test]
    fn accountant_logs_if_no_transactions_were_detected() {
        init_test_logging();
        let earning_wallet = make_wallet("earner3000");
        let blockchain_bridge = Recorder::new().retrieve_transactions_response(Ok(vec![]));
        let blockchain_bridge_awaiter = blockchain_bridge.get_awaiter();
        let blockchain_bridge_recording = blockchain_bridge.get_recording();
        let (accountant_mock, _, accountant_recording_arc) = make_recorder();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(10_000),
                receivables_scan_interval: Duration::from_millis(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            earning_wallet.clone(),
        );

        thread::spawn(move || {
            let system = System::new("accountant_logs_if_no_transactions_were_detected");
            let pending_payments_dao =
                PendingPaymentsDaoMock::default().return_all_payment_backups_result(vec![]);
            let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
            let receivable_dao = ReceivableDaoMock::new()
                .new_delinquencies_result(vec![])
                .paid_delinquencies_result(vec![]);
            let config_mock = PersistentConfigurationMock::new().start_block_result(Ok(5));
            let subject = make_accountant(
                Some(config),
                Some(payable_dao),
                Some(receivable_dao),
                Some(pending_payments_dao),
                None,
                Some(config_mock),
            );
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .accountant(accountant_mock)
                .build();
            let subject_addr: Addr<Accountant> = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(subject_subs, peer_actors);
            send_start_message!(subject_subs);

            system.run();
        });

        blockchain_bridge_awaiter.await_message_count(1);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Scanning for payments");
        let retrieve_transactions_recording = blockchain_bridge_recording.lock().unwrap();
        let retrieve_transactions_message =
            retrieve_transactions_recording.get_record::<RetrieveTransactions>(0);
        assert_eq!(
            retrieve_transactions_message,
            &RetrieveTransactions {
                start_block: 5u64,
                recipient: earning_wallet,
            },
        );
        log_handler.exists_log_containing("DEBUG: Accountant: No payments detected");
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(0, accountant_recording.len());
        log_handler
            .exists_log_containing("DEBUG: Accountant: No pending payment found during last scan");
    }

    #[test]
    //TODO this test needs a restructure
    fn accountant_logs_error_when_blockchain_bridge_responds_with_error() {
        init_test_logging();
        let earning_wallet = make_wallet("earner3000");
        let blockchain_bridge = Recorder::new().retrieve_transactions_response(Err(
            BlockchainError::QueryFailed("really bad".to_string()),
        ));
        let blockchain_bridge_awaiter = blockchain_bridge.get_awaiter();
        let blockchain_bridge_recording = blockchain_bridge.get_recording();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(10_000),
                receivables_scan_interval: Duration::from_millis(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            earning_wallet.clone(),
        );

        thread::spawn(move || {
            let system =
                System::new("accountant_logs_error_when_blockchain_bridge_responds_with_error");
            let receivable_dao = ReceivableDaoMock::new()
                .new_delinquencies_result(vec![])
                .paid_delinquencies_result(vec![]);
            let config_mock = PersistentConfigurationMock::new().start_block_result(Ok(0));
            let mut subject = make_accountant(
                Some(config),
                None,
                Some(receivable_dao),
                None,
                None,
                Some(config_mock),
            );
            subject.scanners.payables = Box::new(NullScanner);
            subject.scanners.pending_payments = Box::new(NullScanner);
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .build();
            let subject_addr: Addr<Accountant> = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(subject_subs, peer_actors);
            send_start_message!(subject_subs);

            system.run();
        });

        blockchain_bridge_awaiter.await_message_count(1);
        let retrieve_transactions_recording = blockchain_bridge_recording.lock().unwrap();
        let retrieve_transactions_message =
            retrieve_transactions_recording.get_record::<RetrieveTransactions>(0);
        assert_eq!(earning_wallet, retrieve_transactions_message.recipient);

        TestLogHandler::new().exists_log_containing(
            r#"WARN: Accountant: Unable to retrieve transactions from Blockchain Bridge: QueryFailed("really bad")"#,
        );
    }

    #[test]
    fn accountant_pending_payments_scan_timer_triggers_periodical_scanning_for_yet_unconfirmed_transactions(
    ) {
        //in the very first round we scan without waiting but we cannot find any pending payments
        init_test_logging();
        let return_unresolved_backup_records_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let system =
            System::new("accountant_payable_scan_timer_triggers_scanning_for_pending_payments");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100), //actually irrelevant because we skip all scans but pending_payments
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_millis(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        // slightly above minimum balance, to the right of the curve (time intersection)
        let payment_backup_record = PaymentBackupRecord {
            rowid: 45454,
            timestamp: SystemTime::now(),
            hash: H256::from_uint(&U256::from(565)),
            attempt: 1,
            amount: 4589,
            process_error: None,
        };
        let mut pending_payments_dao = PendingPaymentsDaoMock::default()
            .return_all_payment_backups_params(&return_unresolved_backup_records_params_arc)
            .return_all_payment_backups_result(vec![])
            .return_all_payment_backups_result(vec![payment_backup_record.clone()]);
        pending_payments_dao.have_return_all_backup_records_shut_down_the_system = true;
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let persistent_config =
            PersistentConfigurationMock::default().start_block_result(Ok(123456));
        let mut subject = make_accountant(
            Some(config),
            None,
            None,
            Some(pending_payments_dao),
            None,
            Some(persistent_config),
        );
        subject.scanners.receivables = Box::new(NullScanner); //skipping
        subject.scanners.payables = Box::new(NullScanner); //skipping
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run(); //this doesn't block because payable.dao_pending_payments() calls System::current.stop() when its queue becomes empty
        let return_unresolved_backup_records_params =
            return_unresolved_backup_records_params_arc.lock().unwrap();
        assert_eq!(*return_unresolved_backup_records_params, vec![(), (), ()]); //the third attempt is the one where the queue is empty and System::current.stop() ends the cycle
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let request_transaction_receipt_msg =
            blockchain_bridge_recorder.get_record::<RequestTransactionReceipts>(0);
        assert_eq!(
            request_transaction_receipt_msg,
            &RequestTransactionReceipts {
                pending_payments: vec![payment_backup_record],
            }
        );
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            "DEBUG: Accountant: Scanning for pending payments",
            "DEBUG: Accountant: Scanning for pending payments",
            "DEBUG: Accountant: Scanning for pending payments",
        ]);
    }

    #[test]
    fn accountant_payable_scan_timer_triggers_periodical_scanning_for_payables() {
        //in the very first round we scan without waiting but we cannot find any payable records
        init_test_logging();
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let system = System::new("accountant_payable_scan_timer_triggers_scanning_for_payables");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_millis(100),
                receivables_scan_interval: Duration::from_secs(100), //actually irrelevant because we skip all scans but payables
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        let now = to_time_t(SystemTime::now());
        // slightly above minimum balance, to the right of the curve (time intersection)
        let account = PayableAccount {
            wallet: make_wallet("wallet"),
            balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 5,
            last_paid_timestamp: from_time_t(now - PAYMENT_CURVES.balance_decreases_for_sec - 10),
            pending_payment_rowid_opt: None,
        };
        let mut payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![])
            .non_pending_payables_result(vec![account.clone()]);
        payable_dao.have_non_pending_payables_shut_down_the_system = true;
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let persistent_config =
            PersistentConfigurationMock::default().start_block_result(Ok(123456));
        let mut subject = make_accountant(
            Some(config),
            Some(payable_dao),
            None,
            None,
            None,
            Some(persistent_config),
        );
        subject.scanners.pending_payments = Box::new(NullScanner); //skipping
        subject.scanners.receivables = Box::new(NullScanner); //skipping
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run(); //this doesn't block because payable.dao_pending_payments() calls System::current.stop() when its queue becomes empty
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        assert_eq!(*non_pending_payables_params, vec![(), (), ()]); //the third attempt is the one where the queue is empty and System::current.stop() ends the cycle
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let report_accounts_payables_msg =
            blockchain_bridge_recorder.get_record::<ReportAccountsPayable>(0);
        assert_eq!(
            report_accounts_payables_msg,
            &ReportAccountsPayable {
                accounts: vec![account]
            }
        );
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            "DEBUG: Accountant: Scanning for payables",
            "DEBUG: Accountant: Scanning for payables",
            "DEBUG: Accountant: Scanning for payables",
        ]);
    }

    #[test]
    fn scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(1000),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("mine"),
        );
        let now = to_time_t(SystemTime::now());
        let accounts = vec![
            // below minimum balance, to the right of time intersection (inside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub - 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payment_rowid_opt: None,
            },
            // above balance intersection, to the left of minimum time (inside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec + 10,
                ),
                pending_payment_rowid_opt: None,
            },
            // above minimum balance, to the right of minimum time (not in buffer zone, below the curve)
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub - 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec - 1,
                ),
                pending_payment_rowid_opt: None,
            },
        ];
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_result(accounts.clone())
            .non_pending_payables_result(vec![]);
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let system = System::new(
            "scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve",
        );
        let blockchain_bridge_addr: Addr<Recorder> = blockchain_bridge.start();
        let report_accounts_payable_sub =
            blockchain_bridge_addr.recipient::<ReportAccountsPayable>();
        let mut subject = make_accountant(Some(config), Some(payable_dao), None, None, None, None);
        subject.report_accounts_payable_sub = Some(report_accounts_payable_sub);

        subject.scan_for_payables();

        System::current().stop_with_code(0);
        system.run();
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recordings.len(), 0);
    }

    #[test]
    fn scan_for_payables_message_triggers_payment_for_balances_over_the_curve() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_millis(1_000),
                receivables_scan_interval: Duration::from_millis(1_000),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("mine"),
        );
        let now = to_time_t(SystemTime::now());
        let accounts = vec![
            // slightly above minimum balance, to the right of the curve (time intersection)
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payment_rowid_opt: None,
            },
            // slightly above the curve (balance intersection), to the right of minimum time
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec - 10,
                ),
                pending_payment_rowid_opt: None,
            },
        ];
        let payable_dao = PayableDaoMock::default()
            .non_pending_payables_result(accounts.clone())
            .non_pending_payables_result(vec![]);
        let (mut blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        blockchain_bridge = blockchain_bridge
            .retrieve_transactions_response(Ok(vec![]))
            .report_accounts_payable_response(Ok(vec![]));
        let system =
            System::new("scan_for_payables_message_triggers_payment_for_balances_over_the_curve");
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let subject = make_accountant(Some(config), Some(payable_dao), None, None, None, None);
        let subject_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(accountant_subs, peer_actors);

        let _ = subject_addr.try_send(ScanForPayables {}).unwrap();

        let dummy_actor = DummyActor::new(None);
        let dummy_address = dummy_actor.start();
        dummy_address
            .try_send(CleanUpMessage { sleep_ms: 150 })
            .unwrap();
        system.run();
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recordings.get_record::<ReportAccountsPayable>(0),
            &ReportAccountsPayable { accounts }
        );
    }

    #[test]
    fn payment_received_scan_triggers_scan_for_delinquencies() {
        //we want to make sure that the first round goes idle because that is driven by the immediate scan after the start msg arrives
        //so what is important is the second round and if we get the expected result we can say that the code for scanning in intervals works
        let ban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let ban_parameters_arc_inner = ban_parameters_arc.clone();
        let blockchain_bridge = Recorder::new().retrieve_transactions_response(Ok(vec![]));
        let system = System::new("payment_received_scan_triggers_scan_for_delinquencies");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_millis(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        let mut receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .new_delinquencies_result(vec![make_receivable_account(1234, true)])
            .paid_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]) //because the system has some inertia before it shuts down
            .paid_delinquencies_result(vec![]); //TODO this is even one more extra; remove it when GH-485 or GH-492 are done, both offers options to break the race
        receivable_dao.have_new_delinquencies_shutdown_the_system = true;
        let banned_dao = BannedDaoMock::new()
            .ban_parameters(&ban_parameters_arc_inner)
            .ban_list_result(vec![])
            .ban_list_result(vec![]);
        let persistent_config =
            PersistentConfigurationMock::default().start_block_result(Ok(123456));
        let mut subject = make_accountant(
            Some(config),
            None,
            Some(receivable_dao),
            None,
            Some(banned_dao),
            Some(persistent_config),
        );
        subject.scanners.pending_payments = Box::new(NullScanner); //skipping
        subject.scanners.payables = Box::new(NullScanner); //skipping
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);
        send_start_message!(subject_subs);

        system.run();

        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert_eq!(
            "0x00000000000000000077616c6c65743132333464",
            &format!("{:#x}", &ban_parameters[0].address())
        );
    }

    #[test]
    fn scan_for_received_payments_handles_error_retrieving_start_block() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Err(PersistentConfigError::NotPresent));
        let subject = make_accountant(None, None, None, None, None, Some(persistent_config));

        subject.scan_for_received_payments();

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("ERROR: Accountant: Could not retrieve start block: NotPresent - aborting received-payment scan");
    }

    #[test]
    fn scan_for_delinquencies_triggers_bans_and_unbans() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(1000),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("mine"),
        );
        let newly_banned_1 = make_receivable_account(1234, true);
        let newly_banned_2 = make_receivable_account(2345, true);
        let newly_unbanned_1 = make_receivable_account(3456, false);
        let newly_unbanned_2 = make_receivable_account(4567, false);
        let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let new_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_parameters_arc)
            .new_delinquencies_result(vec![newly_banned_1.clone(), newly_banned_2.clone()])
            .paid_delinquencies_parameters(&paid_delinquencies_parameters_arc)
            .paid_delinquencies_result(vec![newly_unbanned_1.clone(), newly_unbanned_2.clone()]);
        let ban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let unban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let banned_dao = BannedDaoMock::new()
            .ban_list_result(vec![])
            .ban_parameters(&ban_parameters_arc)
            .unban_parameters(&unban_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao),
            Some(receivable_dao),
            None,
            Some(banned_dao),
            None,
        );

        subject.scan_for_delinquencies();

        let new_delinquencies_parameters: MutexGuard<Vec<(SystemTime, PaymentCurves)>> =
            new_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(PAYMENT_CURVES.clone(), new_delinquencies_parameters[0].1);
        let paid_delinquencies_parameters: MutexGuard<Vec<PaymentCurves>> =
            paid_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(PAYMENT_CURVES.clone(), paid_delinquencies_parameters[0]);
        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert!(ban_parameters.contains(&newly_banned_1.wallet));
        assert!(ban_parameters.contains(&newly_banned_2.wallet));
        assert_eq!(2, ban_parameters.len());
        let unban_parameters = unban_parameters_arc.lock().unwrap();
        assert!(unban_parameters.contains(&newly_unbanned_1.wallet));
        assert!(unban_parameters.contains(&newly_unbanned_2.wallet));
        assert_eq!(2, unban_parameters.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_matching("INFO: Accountant: Wallet 0x00000000000000000077616c6c65743132333464 \\(balance: 1234 MASQ, age: \\d+ sec\\) banned for delinquency");
        tlh.exists_log_matching("INFO: Accountant: Wallet 0x00000000000000000077616c6c65743233343564 \\(balance: 2345 MASQ, age: \\d+ sec\\) banned for delinquency");
        tlh.exists_log_matching("INFO: Accountant: Wallet 0x00000000000000000077616c6c6574333435366e \\(balance: 3456 MASQ, age: \\d+ sec\\) is no longer delinquent: unbanned");
        tlh.exists_log_matching("INFO: Accountant: Wallet 0x00000000000000000077616c6c6574343536376e \\(balance: 4567 MASQ, age: \\d+ sec\\) is no longer delinquent: unbanned");
    }

    #[test]
    fn scan_for_pending_payments_found_no_pending_payments() {
        init_test_logging();
        let return_all_backup_records_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payments_dao = PendingPaymentsDaoMock::default()
            .return_all_payment_backups_params(&return_all_backup_records_params_arc)
            .return_all_payment_backups_result(vec![]);
        let pending_payments_dao_factory = PendingPaymentsDaoFactoryMock::new(pending_payments_dao);
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(pending_payments_dao_factory))
            .build();

        let _ = subject.scan_for_pending_payments();

        let return_all_backup_records_params = return_all_backup_records_params_arc.lock().unwrap();
        assert_eq!(*return_all_backup_records_params, vec![()]);
        TestLogHandler::new()
            .exists_log_containing("DEBUG: Accountant: No pending payment found during last scan");
    }

    #[test]
    fn scan_for_pending_payments_found_unresolved_pending_payments_and_urges_their_processing() {
        init_test_logging();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let pending_payment_backup_1 = PaymentBackupRecord {
            rowid: 555,
            timestamp: from_time_t(210_000_000),
            hash: H256::from_uint(&U256::from(45678)),
            attempt: 0,
            amount: 4444,
            process_error: None,
        };
        let pending_payment_backup_2 = PaymentBackupRecord {
            rowid: 550,
            timestamp: from_time_t(210_000_100),
            hash: H256::from_uint(&U256::from(112233)),
            attempt: 0,
            amount: 7999,
            process_error: None,
        };
        let pending_payments_dao = PendingPaymentsDaoMock::default()
            .return_all_payment_backups_result(vec![
                pending_payment_backup_1.clone(),
                pending_payment_backup_2.clone(),
            ]);
        let pending_payments_dao_factory = PendingPaymentsDaoFactoryMock::new(pending_payments_dao);
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("mine"),
        );
        let system = System::new("pending payments scan");
        let mut subject = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(pending_payments_dao_factory))
            .bootstrapper_config(config)
            .build();
        let blockachain_bridge_addr = blockchain_bridge.start();
        subject
            .transaction_confirmation
            .request_transaction_receipts_subs_opt = Some(blockachain_bridge_addr.recipient());
        let account_addr = subject.start();

        let _ = account_addr.try_send(ScanForPendingPayments {}).unwrap();

        let dummy_actor = DummyActor::new(None);
        let dummy_addr = dummy_actor.start();
        dummy_addr
            .try_send(CleanUpMessage { sleep_ms: 10 })
            .unwrap();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recording.len(), 1);
        let received_msg = blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0);
        assert_eq!(
            received_msg,
            &RequestTransactionReceipts {
                pending_payments: vec![pending_payment_backup_1, pending_payment_backup_2]
            }
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Found 2 pending payments to process");
    }

    #[test]
    fn report_routing_service_provided_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
        let system = System::new("report_routing_service_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        let paying_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
                paying_wallet: paying_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_receivable_parameters = more_money_receivable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_receivable_parameters[0],
            (make_wallet("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Accountant: Charging routing of 1234 bytes to wallet {}",
            paying_wallet
        ));
    }

    #[test]
    fn report_routing_service_provided_message_is_received_from_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("our consuming wallet");
        let config = bc_from_ac_plus_wallets(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            consuming_wallet.clone(),
            make_wallet("our earning wallet"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
        let system = System::new("report_routing_service_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
                paying_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_receivable_parameters_arc
            .lock()
            .unwrap()
            .is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service provided for our wallet {}",
            consuming_wallet,
        ));
    }

    #[test]
    fn report_routing_service_provided_message_is_received_from_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("our earning wallet");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            earning_wallet.clone(),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
        let system = System::new("report_routing_service_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
                paying_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_receivable_parameters_arc
            .lock()
            .unwrap()
            .is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service provided for our wallet {}",
            earning_wallet,
        ));
    }

    #[test]
    fn report_routing_service_consumed_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone())
            .more_money_payable_result(Ok(()));
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
        let system = System::new("report_routing_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        let earning_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportRoutingServiceConsumedMessage {
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_payable_parameters = more_money_payable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_payable_parameters[0],
            (make_wallet("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(
            &format!("DEBUG: Accountant: Accruing debt to wallet {} for consuming routing service 1234 bytes", earning_wallet),
        );
    }

    #[test]
    fn report_routing_service_consumed_message_is_received_for_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("the consuming wallet");
        let config = bc_from_ac_plus_wallets(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            consuming_wallet.clone(),
            make_wallet("the earning wallet"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
        let system = System::new("report_routing_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceConsumedMessage {
                earning_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_payable_parameters_arc.lock().unwrap().is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service consumed to our wallet {}",
            consuming_wallet,
        ));
    }

    #[test]
    fn report_routing_service_consumed_message_is_received_for_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("the earning wallet");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            earning_wallet.clone(),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
        let system = System::new("report_routing_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceConsumedMessage {
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_payable_parameters_arc.lock().unwrap().is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service consumed to our wallet {}",
            earning_wallet
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
        let system = System::new("report_exit_service_provided_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        let paying_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
                paying_wallet: paying_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop();
        system.run();
        let more_money_receivable_parameters = more_money_receivable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_receivable_parameters[0],
            (make_wallet("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Accountant: Charging exit service for 1234 bytes to wallet {}",
            paying_wallet
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received_from_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("my consuming wallet");
        let config = bc_from_ac_plus_wallets(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            consuming_wallet.clone(),
            make_wallet("my earning wallet"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
        let system = System::new("report_exit_service_provided_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
                paying_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop();
        system.run();
        assert!(more_money_receivable_parameters_arc
            .lock()
            .unwrap()
            .is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service provided for our wallet {}",
            consuming_wallet
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received_from_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("my earning wallet");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            earning_wallet.clone(),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
        let system = System::new("report_exit_service_provided_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
                paying_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop();
        system.run();
        assert!(more_money_receivable_parameters_arc
            .lock()
            .unwrap()
            .is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service provided for our wallet {}",
            earning_wallet,
        ));
    }

    #[test]
    fn report_exit_service_consumed_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone())
            .more_money_payable_result(Ok(()));
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
        let system = System::new("report_exit_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        let earning_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportExitServiceConsumedMessage {
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_payable_parameters = more_money_payable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_payable_parameters[0],
            (make_wallet("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Accountant: Accruing debt to wallet {} for consuming exit service 1234 bytes",
            earning_wallet
        ));
    }

    #[test]
    fn report_exit_service_consumed_message_is_received_for_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("own consuming wallet");
        let config = bc_from_ac_plus_wallets(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            consuming_wallet.clone(),
            make_wallet("own earning wallet"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
        let system = System::new("report_exit_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceConsumedMessage {
                earning_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_payable_parameters_arc.lock().unwrap().is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service consumed to our wallet {}",
            consuming_wallet
        ));
    }

    #[test]
    fn report_exit_service_consumed_message_is_received_for_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("own earning wallet");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payments_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            earning_wallet.clone(),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
        let system = System::new("report_exit_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceConsumedMessage {
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_payable_parameters_arc.lock().unwrap().is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service consumed to our wallet {}",
            earning_wallet
        ));
    }

    #[test]
    #[should_panic(
        expected = "Recording services provided for 0x000000000000000000000000000000626f6f6761 \
    but has hit fatal database error: RusqliteError(\"we cannot help ourself; this is baaad\")"
    )]
    fn record_service_provided_panics_on_fatal_errors() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let subject = make_accountant(
            None,
            None,
            Some(ReceivableDaoMock::new().more_money_receivable_result(Err(
                DebtRecordingError::RusqliteError(
                    "we cannot help ourself; this is baaad".to_string(),
                ),
            ))),
            None,
            None,
            None,
        );

        let _ = subject.record_service_provided(i64::MAX as u64, 1, 2, &wallet);
    }

    #[test]
    fn record_service_provided_handles_overflow() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let subject = make_accountant(
            None,
            None,
            Some(
                ReceivableDaoMock::new()
                    .more_money_receivable_result(Err(DebtRecordingError::SignConversion(1234))),
            ),
            None,
            None,
            None,
        );

        subject.record_service_provided(i64::MAX as u64, 1, 2, &wallet);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Accountant: Overflow error recording service provided for {}: service rate {}, byte rate 1, payload size 2. Skipping",
            wallet,
            i64::MAX as u64
        ));
    }

    #[test]
    fn record_service_consumed_handles_overflow() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let subject = make_accountant(
            None,
            Some(
                PayableDaoMock::new()
                    .more_money_payable_result(Err(DebtRecordingError::SignConversion(1234))),
            ),
            None,
            None,
            None,
            None,
        );

        subject.record_service_consumed(i64::MAX as u64, 1, 2, &wallet);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Accountant: Overflow error recording consumed services from {}: service rate {}, byte rate 1, payload size 2. Skipping",
            wallet,
            i64::MAX as u64
        ));
    }

    #[test]
    #[should_panic(
        expected = "Recording services consumed from 0x000000000000000000000000000000626f6f6761 but \
     has hit fatal database error: RusqliteError(\"we cannot help ourself; this is baaad\")"
    )]
    fn record_service_consumed_panics_on_fatal_errors() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let subject = make_accountant(
            None,
            Some(PayableDaoMock::new().more_money_payable_result(Err(
                DebtRecordingError::RusqliteError(
                    "we cannot help ourself; this is baaad".to_string(),
                ),
            ))),
            None,
            None,
            None,
            None,
        );

        let _ = subject.record_service_consumed(i64::MAX as u64, 1, 2, &wallet);
    }

    #[test]
    #[should_panic(
        expected = "Was unable to create a mark in payables for a new pending payment '0x0000…007b' due to 'SignConversion(9999999999999)'"
    )]
    fn handle_sent_payments_fails_to_make_a_mark_in_payables_and_so_panics() {
        let payment = Payment::new(
            make_wallet("blah"),
            6789,
            H256::from_uint(&U256::from(123)),
            SystemTime::now(),
        );
        let subject = make_accountant(
            None,
            Some(
                PayableDaoMock::new().mark_pending_payment_result(Err(PaymentError(
                    PaymentErrorKind::SignConversion(9999999999999),
                    TransactionId {
                        hash: H256::from_uint(&U256::from(123)),
                        rowid: 7879,
                    },
                ))),
            ),
            None,
            Some(PendingPaymentsDaoMock::default().payment_backup_exists_result(Some(7879))),
            None,
            None,
        );

        let _ = subject.mark_pending_payments(vec![payment]);
    }

    #[test]
    #[should_panic(
        expected = "Database unmaintainable; payment backup deletion has stayed undone due to RecordDeletion(\"we slept over, sorry\")"
    )]
    fn handle_sent_payments_dealing_with_failed_payment_fails_to_delete_the_existing_payment_backup_and_panics(
    ) {
        let rowid = 4;
        let hash = H256::from_uint(&U256::from(123));
        let payments = SentPayments {
            payments: vec![Err(BlockchainError::TransactionFailed {
                msg: "blah".to_string(),
                hash_opt: Some(hash),
            })],
        };
        let pending_payment_dao = PendingPaymentsDaoMock::default()
            .payment_backup_exists_result(Some(rowid))
            .delete_payment_backup_result(Err(PendingPaymentDaoError::RecordDeletion(
                "we slept over, sorry".to_string(),
            )));
        let subject = make_accountant(None, None, None, Some(pending_payment_dao), None, None);

        let _ = subject.handle_sent_payments(payments);
    }

    #[test]
    fn handle_sent_payments_receives_two_payments_being_incorrect_and_one_correct() {
        //the two failures differ in the logged messages
        init_test_logging();
        let payment_backup_exists_params_arc = Arc::new(Mutex::new(vec![]));
        let now_system = SystemTime::now();
        let payment_1 = Err(BlockchainError::InvalidResponse);
        let payment_2_rowid = 126;
        let payment_hash_2 = H256::from_uint(&U256::from(166));
        let payment_2 = Payment::new(make_wallet("booga"), 6789, payment_hash_2, now_system);
        let payment_3 = Err(BlockchainError::TransactionFailed {
            msg: "closing hours, sorry".to_string(),
            hash_opt: None,
        });
        let payments = SentPayments {
            payments: vec![payment_1, Ok(payment_2.clone()), payment_3],
        };
        let pending_payments_dao = PendingPaymentsDaoMock::default()
            //one seems to be missing, not really, the execution short-circuited at the outer error
            .payment_backup_exists_params(&payment_backup_exists_params_arc)
            .payment_backup_exists_result(Some(payment_2_rowid));
        let subject = make_accountant(
            None,
            Some(PayableDaoMock::new().mark_pending_payment_result(Ok(()))),
            None,
            Some(pending_payments_dao),
            None,
            None,
        );

        subject.handle_sent_payments(payments);

        let payment_backup_exists_params = payment_backup_exists_params_arc.lock().unwrap();
        assert_eq!(*payment_backup_exists_params, vec![payment_hash_2]); //we know the other two errors are associated with an initiated transaction having a backup
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("WARN: Accountant: Payment failure due to 'InvalidResponse'. Please check your blockchain service URL configuration.");
        log_handler.exists_log_containing("DEBUG: Accountant: Payment '0x0000…00a6' has been marked as pending in the payable table");
        log_handler.exists_log_containing("WARN: Accountant: Encountered transaction error that occurred close to the actual sending due to 'TransactionFailed { msg: \"closing hours, sorry\", hash_opt: None }'");
        log_handler.exists_log_containing("DEBUG: Accountant: Forgetting a transaction attempt that even did not reach the signing stage");
    }

    #[test]
    #[should_panic(
        expected = "Payment backup for 0x0000…0315 doesn't exist but should by now; system unreliable"
    )]
    fn handle_sent_payments_receives_proper_payment_but_payment_backup_not_found_so_it_panics() {
        init_test_logging();
        let now_system = SystemTime::now();
        let payment_hash = H256::from_uint(&U256::from(789));
        let payment = Payment::new(make_wallet("booga"), 6789, payment_hash, now_system);
        let pending_payments_dao =
            PendingPaymentsDaoMock::default().payment_backup_exists_result(None);
        let subject = make_accountant(
            None,
            Some(PayableDaoMock::new().mark_pending_payment_result(Ok(()))),
            None,
            Some(pending_payments_dao),
            None,
            None,
        );

        let _ = subject.mark_pending_payments(vec![payment]);
    }

    #[test]
    fn handle_confirm_transaction_works() {
        init_test_logging();
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_payment_backup_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_factory = PayableDaoFactoryMock::new(Box::new(
            PayableDaoMock::default()
                .transaction_confirmed_params(&transaction_confirmed_params_arc)
                .transaction_confirmed_result(Ok(())),
        ));
        let pending_payments_dao_factory = PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default()
                .delete_payment_backup_params(&delete_payment_backup_params_arc)
                .delete_payment_backup_result(Ok(())),
        );
        let subject = AccountantBuilder::default()
            .payable_dao_factory(Box::new(payable_dao_factory))
            .pending_payments_dao_factory(Box::new(pending_payments_dao_factory))
            .build();
        let tx_hash = H256::from("sometransactionhash".keccak256());
        let amount = 4567;
        let timestamp_from_time_of_payment = from_time_t(200_000_000);
        let rowid = 2;
        let payment_backup = PaymentBackupRecord {
            rowid,
            timestamp: timestamp_from_time_of_payment,
            hash: tx_hash,
            attempt: 1,
            amount,
            process_error: None,
        };

        let _ = subject.handle_confirm_pending_transaction(ConfirmPendingTransaction {
            payment_backup: payment_backup.clone(),
        });

        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(*transaction_confirmed_params, vec![payment_backup]);
        let delete_payment_backup_params = delete_payment_backup_params_arc.lock().unwrap();
        assert_eq!(*delete_payment_backup_params, vec![rowid]);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Confirmation of transaction 0x051a…8c19; record for payable table took change");
        log_handler.exists_log_containing("INFO: Accountant: Transaction 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 has gone through the whole confirmation process succeeding");
    }

    #[test]
    #[should_panic(
        expected = "Was unable to uncheck pending payment '0x0000…0315' after confirmation due to 'RusqliteError(\"record change not successful\")"
    )]
    fn handle_confirm_pending_transaction_panics_on_unchecking_payable_table() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Err(PaymentError(
            PaymentErrorKind::RusqliteError("record change not successful".to_string()),
            TransactionId { hash, rowid },
        )));
        let subject = AccountantBuilder::default()
            .payable_dao_factory(Box::new(PayableDaoFactoryMock::new(Box::new(payable_dao))))
            .build();
        let mut payment = make_payment_backup();
        payment.rowid = rowid;
        payment.hash = hash;
        let msg = ConfirmPendingTransaction {
            payment_backup: payment.clone(),
        };

        let _ = subject.handle_confirm_pending_transaction(msg);
    }

    #[test]
    #[should_panic(
        expected = "Was unable to delete payment backup '0x0000…0315' after successful transaction due to 'RecordDeletion(\"the database is fooling around with us\")'"
    )]
    fn handle_confirm_pending_transaction_panics_on_deleting_payment_backup() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Ok(()));
        let pending_payments_dao = PendingPaymentsDaoMock::default().delete_payment_backup_result(
            Err(PendingPaymentDaoError::RecordDeletion(
                "the database is fooling around with us".to_string(),
            )),
        );
        let subject = AccountantBuilder::default()
            .payable_dao_factory(Box::new(PayableDaoFactoryMock::new(Box::new(payable_dao))))
            .pending_payments_dao_factory(Box::new(PendingPaymentsDaoFactoryMock::new(
                pending_payments_dao,
            )))
            .build();
        let mut payment_backup = make_payment_backup();
        payment_backup.rowid = rowid;
        payment_backup.hash = hash;
        let msg = ConfirmPendingTransaction {
            payment_backup: payment_backup.clone(),
        };

        let _ = subject.handle_confirm_pending_transaction(msg);
    }

    #[test]
    fn handle_cancel_pending_transaction_works() {
        init_test_logging();
        let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payments_dao_factory = PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default()
                .mark_failure_params(&mark_failure_params_arc)
                .mark_failure_result(Ok(())),
        );
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(pending_payments_dao_factory))
            .build();
        let tx_hash = H256::from("sometransactionhash".keccak256());
        let rowid = 2;
        let transaction_id = TransactionId {
            hash: tx_hash,
            rowid,
        };

        let _ = subject.handle_cancel_pending_transaction(CancelFailedPendingTransaction {
            id: transaction_id,
        });

        let mark_failure_params = mark_failure_params_arc.lock().unwrap();
        assert_eq!(*mark_failure_params, vec![rowid]);
        TestLogHandler::new().exists_log_containing(
            "WARN: Accountant: Broken transaction 0x051a…8c19 left with an error mark; you should take over \
             the care of this transaction to make sure your debts will be paid because there is no automated process that can fix this without you",
        );
    }

    #[test]
    #[should_panic(
        expected = "Unsuccessful attempt for transaction 0x051a…8c19 to mark fatal error at pending payment backup for transaction due to UpdateFailed(\"no no no\")"
    )]
    fn handle_cancel_pending_transaction_panics_on_its_inability_to_mark_failure() {
        let payable_dao_factory = PayableDaoFactoryMock::new(Box::new(
            PayableDaoMock::default().transaction_canceled_result(Ok(())),
        ));
        let pending_payments_dao_factory = PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default().mark_failure_result(Err(
                PendingPaymentDaoError::UpdateFailed("no no no".to_string()),
            )),
        );
        let subject = AccountantBuilder::default()
            .payable_dao_factory(Box::new(payable_dao_factory))
            .pending_payments_dao_factory(Box::new(pending_payments_dao_factory))
            .build();
        let rowid = 2;
        let hash = H256::from("sometransactionhash".keccak256());

        let _ = subject.handle_cancel_pending_transaction(CancelFailedPendingTransaction {
            id: TransactionId { hash, rowid },
        });
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn accountant_can_be_crashed_properly_but_not_improperly() {
        let mut config = BootstrapperConfig::default();
        config.crash_point = CrashPoint::Message;
        let accountant = make_accountant(Some(config), None, None, None, None, None);

        prove_that_crash_request_handler_is_hooked_up(accountant, CRASH_KEY);
    }

    #[test]
    fn investigate_debt_extremes_picks_the_most_relevant_records() {
        let now = to_time_t(SystemTime::now());
        let same_amount_significance = 2_000_000;
        let same_age_significance = from_time_t(now - 30000);
        let payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: same_amount_significance,
                last_paid_timestamp: from_time_t(now - 5000),
                pending_payment_rowid_opt: None,
            },
            //this debt is more significant because beside being high in amount it's also older, so should be prioritized and picked
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: same_amount_significance,
                last_paid_timestamp: from_time_t(now - 10000),
                pending_payment_rowid_opt: None,
            },
            //similarly these two wallets have debts equally old but the second has a bigger balance and should be chosen
            PayableAccount {
                wallet: make_wallet("wallet3"),
                balance: 100,
                last_paid_timestamp: same_age_significance,
                pending_payment_rowid_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: 330,
                last_paid_timestamp: same_age_significance,
                pending_payment_rowid_opt: None,
            },
        ];

        let result = Accountant::investigate_debt_extremes(payables);

        assert_eq!(result,"Payable scan found 4 debts; the biggest is 2000000 owed for 10000sec, the oldest is 330 owed for 30000sec")
    }

    #[test]
    fn payment_debug_summary_prints_pretty_summary() {
        let now = to_time_t(SystemTime::now());
        let qualified_payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 1234,
                ),
                pending_payment_rowid_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 1,
                ),
                pending_payment_rowid_opt: None,
            },
        ];

        let result = Accountant::payments_debug_summary(qualified_payables);

        assert_eq!(result,
                   "Paying qualified debts:\n\
                   10001000 owed for 2593234sec exceeds threshold: 9512428; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   10000001 owed for 2592001sec exceeds threshold: 9999604; creditor: 0x0000000000000000000000000077616c6c657431"
        )
    }

    #[test]
    fn pending_transaction_is_registered_and_monitored_until_it_gets_confirmed_or_canceled() {
        //TODO change the description
        //We send a list of creditor accounts with mature debts to BlockchainBridge,
        //he acts like he's sending transactions for paying them (the transacting part is mocked),
        //next BlockchainBridge relies payments to Accountant with PaymentSent message. There we take care of an update
        //of the payable table, marking a pending tx, after which we register a delayed self-notification
        //to send a message requesting fetching tx receipts, when we get the receipts we process
        //them and make and either registr another self-notification to repeat the cycle (that is for a still
        //pending transaction) or we can demand a cancellation for the reason of either getting a confirmation for
        //the transaction or for having a failure on that transaction.
        //One transaction is canceled after failure detected and the other is successfully confirmed.
        //When a transaction is being clean out, we remove marks from both payable and pending_payments tables.
        //It's a very similar procedure as for a confirmation or remotely happened failure (not a procedural
        //error within our code)
        //Extending beyond the scope of this test: If it were a failure occurred after the moment of sending
        //a theoretically correct transaction what we also call a post-transaction time and if it stands that
        //we can reach a solid backup of the payment we will do just a partial clean-up, leaving the confirmation
        //for another periodical scan for listed but still unconfirmed transactions (but this part is not a part
        //of this test)
        init_test_logging();
        let mark_pending_payment_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let return_all_payment_backups_params_arc = Arc::new(Mutex::new(vec![]));
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let insert_record_params_arc = Arc::new(Mutex::new(vec![]));
        let update_backup_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_record_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_scan_for_pending_payments_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_scan_for_pending_payments_arc_cloned =
            notify_later_scan_for_pending_payments_params_arc.clone(); //because it moves into a closure
        let notify_cancel_failed_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_cancel_failed_transaction_params_arc_cloned =
            notify_cancel_failed_transaction_params_arc.clone(); //because it moves into a closure
        let notify_confirm_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_confirm_transaction_params_arc_cloned =
            notify_confirm_transaction_params_arc.clone(); //because it moves into a closure
                                                           //these belongs to 'pending_payment' table
        let pending_tx_hash_1 = H256::from_uint(&U256::from(123));
        let pending_tx_hash_2 = H256::from_uint(&U256::from(567));
        let rowid_for_account_1 = 3;
        let rowid_for_account_2 = 5;
        let payment_timestamp_1 = SystemTime::now().sub(Duration::from_secs(
            (PAYMENT_CURVES.payment_suggested_after_sec + 555) as u64,
        ));
        let payment_timestamp_2 = SystemTime::now().sub(Duration::from_secs(
            (PAYMENT_CURVES.payment_suggested_after_sec + 50) as u64,
        ));
        let payable_account_balance_1 = PAYMENT_CURVES.balance_to_decrease_from_gwub + 10;
        let payable_account_balance_2 = PAYMENT_CURVES.balance_to_decrease_from_gwub + 666;
        let transaction_receipt_tx_2_first_round = TransactionReceipt::default();
        let transaction_receipt_tx_1_second_round = TransactionReceipt::default();
        let transaction_receipt_tx_2_second_round = TransactionReceipt::default();
        let mut transaction_receipt_tx_1_third_round = TransactionReceipt::default();
        transaction_receipt_tx_1_third_round.status = Some(U64::from(0)); //failure
        let transaction_receipt_tx_2_third_round = TransactionReceipt::default();
        let mut transaction_receipt_tx_2_fourth_round = TransactionReceipt::default();
        transaction_receipt_tx_2_fourth_round.status = Some(U64::from(1)); // confirmed
        let blockchain_interface = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .get_transaction_count_result(Ok(web3::types::U256::from(2)))
            //because we cannot have both, resolution on the higher level and also regarding what's inside blockchain interface,
            //there is (only) one component that is missing in this wholesome test - the part where we send a request to create
            //a backup for the payment's parameters in the DB - this happens inside send_raw_transaction()
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
            .send_transaction_result(Ok((pending_tx_hash_1, payment_timestamp_1)))
            .send_transaction_result(Ok((pending_tx_hash_2, payment_timestamp_2)))
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(None))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_2_first_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_1_second_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_2_second_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_1_third_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_2_third_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_2_fourth_round)));
        let consuming_wallet = make_paying_wallet(b"wallet");
        let system = System::new("pending_transaction");
        let persistent_config = PersistentConfigurationMock::default().gas_price_result(Ok(130));
        let blockchain_bridge = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            Some(consuming_wallet),
        );
        let wallet_account_1 = make_wallet("creditor1");
        let account_1 = PayableAccount {
            wallet: wallet_account_1.clone(),
            balance: payable_account_balance_1,
            last_paid_timestamp: payment_timestamp_1,
            pending_payment_rowid_opt: None,
        };
        let wallet_account_2 = make_wallet("creditor2");
        let account_2 = PayableAccount {
            wallet: wallet_account_2.clone(),
            balance: payable_account_balance_2,
            last_paid_timestamp: payment_timestamp_2,
            pending_payment_rowid_opt: None,
        };
        let pending_payments_scan_interval = 300;
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![account_1, account_2])
            .mark_pending_payment_params(&mark_pending_payment_params_arc)
            .mark_pending_payment_result(Ok(()))
            .mark_pending_payment_result(Ok(()))
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()));
        let bootstrapper_config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(1_000_000), //we don't care about this scan
                receivables_scan_interval: Duration::from_secs(1_000_000), //we don't care about this scan
                pending_payments_scan_interval: Duration::from_millis(
                    pending_payments_scan_interval,
                ),
                when_pending_too_long_sec: (PAYMENT_CURVES.payment_suggested_after_sec + 1000)
                    as u64,
            },
            make_wallet("some_wallet_address"),
        );
        let payment_1_backup_first_round = PaymentBackupRecord {
            rowid: rowid_for_account_1,
            timestamp: payment_timestamp_1,
            hash: pending_tx_hash_1,
            attempt: 1,
            amount: payable_account_balance_1 as u64,
            process_error: None,
        };
        let payment_2_backup_first_round = PaymentBackupRecord {
            rowid: rowid_for_account_2,
            timestamp: payment_timestamp_2,
            hash: pending_tx_hash_2,
            attempt: 1,
            amount: payable_account_balance_2 as u64,
            process_error: None,
        };
        let mut payment_1_backup_second_round = payment_1_backup_first_round.clone();
        payment_1_backup_second_round.attempt = 2;
        let mut payment_2_backup_second_round = payment_2_backup_first_round.clone();
        payment_2_backup_second_round.attempt = 2;
        let mut payment_1_backup_third_round = payment_1_backup_first_round.clone();
        payment_1_backup_third_round.attempt = 3;
        let mut payment_2_backup_third_round = payment_2_backup_first_round.clone();
        payment_2_backup_third_round.attempt = 3;
        let mut payment_2_backup_fourth_round = payment_2_backup_first_round.clone();
        payment_2_backup_fourth_round.attempt = 4;
        let pending_payments_dao = PendingPaymentsDaoMock::default()
            .return_all_payment_backups_params(&return_all_payment_backups_params_arc)
            .return_all_payment_backups_result(vec![])
            .return_all_payment_backups_result(vec![
                payment_1_backup_first_round,
                payment_2_backup_first_round,
            ])
            .return_all_payment_backups_result(vec![
                payment_1_backup_second_round,
                payment_2_backup_second_round,
            ])
            .return_all_payment_backups_result(vec![
                payment_1_backup_third_round,
                payment_2_backup_third_round,
            ])
            .return_all_payment_backups_result(vec![payment_2_backup_fourth_round.clone()])
            .insert_payment_backup_params(&insert_record_params_arc)
            .insert_payment_backup_result(Ok(()))
            .insert_payment_backup_result(Ok(()))
            .payment_backup_exists_result(Some(rowid_for_account_1))
            .payment_backup_exists_result(Some(rowid_for_account_2))
            .update_backup_after_scan_cycle_params(&update_backup_after_cycle_params_arc)
            .update_backup_after_scan_cycle_results(Ok(()))
            .update_backup_after_scan_cycle_results(Ok(()))
            .update_backup_after_scan_cycle_results(Ok(()))
            .update_backup_after_scan_cycle_results(Ok(()))
            .update_backup_after_scan_cycle_results(Ok(()))
            .mark_failure_params(&mark_failure_params_arc)
            //we don't have a better solution yet, so we mark this down
            .mark_failure_result(Ok(()))
            .delete_payment_backup_params(&delete_record_params_arc)
            //this is used during confirmation of the successful one
            .delete_payment_backup_result(Ok(()));
        let accountant_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| {
                let mut subject = make_accountant(
                    Some(bootstrapper_config),
                    Some(payable_dao),
                    None,
                    Some(pending_payments_dao),
                    None,
                    None,
                );
                subject.scanners.receivables = Box::new(NullScanner);
                let notify_later_half_mock = NotifyLaterHandleMock::default()
                    .notify_later_params(&notify_later_scan_for_pending_payments_arc_cloned);
                subject
                    .transaction_confirmation
                    .notify_later_handle_scan_for_pending_payments =
                    Box::new(notify_later_half_mock);
                let mut notify_half_mock = NotifyHandleMock::default()
                    .notify_params(&notify_cancel_failed_transaction_params_arc_cloned);
                notify_half_mock.do_you_want_to_proceed_after = true;
                subject
                    .transaction_confirmation
                    .notify_handle_cancel_failed_transaction = Box::new(notify_half_mock);
                let mut notify_half_mock = NotifyHandleMock::default()
                    .notify_params(&notify_confirm_transaction_params_arc_cloned);
                notify_half_mock.do_you_want_to_proceed_after = true;
                subject
                    .transaction_confirmation
                    .notify_handle_confirm_transaction = Box::new(notify_half_mock);
                subject
            });
        let mut peer_actors = peer_actors_builder().build();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        peer_actors.accountant = accountant_subs.clone();
        let blockchain_bridge_addr = blockchain_bridge.start();
        let blockchain_bridge_subs = BlockchainBridge::make_subs_from(&blockchain_bridge_addr);
        peer_actors.blockchain_bridge = blockchain_bridge_subs.clone();
        let dummy_actor = DummyActor::new(None);
        let dummy_actor_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| dummy_actor);
        send_bind_message!(accountant_subs, peer_actors);
        send_bind_message!(blockchain_bridge_subs, peer_actors);

        send_start_message!(accountant_subs);

        //I need one more actor on an Arbiter's thread (able to invoke a panic if something's wrong);
        //the main subject - BlockchainBridge - is clumsy regarding combining its creation and an Arbiter, so I used this solution
        dummy_actor_addr
            .try_send(CleanUpMessage { sleep_ms: 3000 })
            .unwrap();
        assert_eq!(system.run(), 0);
        let mut mark_pending_payment_parameters = mark_pending_payment_params_arc.lock().unwrap();
        let first_payment = mark_pending_payment_parameters.remove(0);
        assert_eq!(first_payment.0, wallet_account_1);
        assert_eq!(
            first_payment.1,
            TransactionId {
                hash: pending_tx_hash_1,
                rowid: rowid_for_account_1
            }
        );
        let second_payment = mark_pending_payment_parameters.remove(0);
        assert!(
            mark_pending_payment_parameters.is_empty(),
            "{:?}",
            mark_pending_payment_parameters
        );
        assert_eq!(second_payment.0, wallet_account_2);
        assert_eq!(
            second_payment.1,
            TransactionId {
                hash: pending_tx_hash_2,
                rowid: rowid_for_account_2
            }
        );
        let return_all_payment_backups_params =
            return_all_payment_backups_params_arc.lock().unwrap();
        assert_eq!(*return_all_payment_backups_params, vec![(), (), (), (), ()]);
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        assert_eq!(*non_pending_payables_params, vec![()]); //because we disabled further scanning for payables
        let get_transaction_receipt_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(
            *get_transaction_receipt_params,
            vec![
                pending_tx_hash_1,
                pending_tx_hash_2,
                pending_tx_hash_1,
                pending_tx_hash_2,
                pending_tx_hash_1,
                pending_tx_hash_2,
                pending_tx_hash_2
            ]
        );
        let update_backup_after_cycle_params = update_backup_after_cycle_params_arc.lock().unwrap();
        assert_eq!(
            *update_backup_after_cycle_params,
            vec![
                rowid_for_account_1,
                rowid_for_account_2,
                rowid_for_account_1,
                rowid_for_account_2,
                rowid_for_account_2
            ]
        );
        let mark_failure_params = mark_failure_params_arc.lock().unwrap();
        assert_eq!(*mark_failure_params, vec![rowid_for_account_1]);
        let delete_record_params = delete_record_params_arc.lock().unwrap();
        assert_eq!(*delete_record_params, vec![rowid_for_account_2]);
        let expected_params_for_payment_2 = Payment {
            to: wallet_account_2,
            amount: payable_account_balance_2 as u64,
            timestamp: from_time_t(0), //deliberately wrong; I cannot compare the right ones
            transaction: pending_tx_hash_2,
        };
        let mut transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        let payment_confirmed = transaction_confirmed_params.remove(0);
        assert!(transaction_confirmed_params.is_empty());
        assert_eq!(payment_confirmed.process_error, None);
        assert_eq!(
            payment_confirmed.amount,
            expected_params_for_payment_2.amount
        );
        assert_eq!(
            payment_confirmed.hash,
            expected_params_for_payment_2.transaction
        );
        assert_eq!(payment_confirmed.rowid, rowid_for_account_2);
        let expected_scan_pending_payments_msg_and_interval = (
            ScanForPendingPayments {},
            Duration::from_millis(pending_payments_scan_interval),
        );

        let notify_later_check_for_confirmation = notify_later_scan_for_pending_payments_params_arc
            .lock()
            .unwrap();
        assert_eq!(
            *notify_later_check_for_confirmation,
            vec![
                expected_scan_pending_payments_msg_and_interval.clone(),
                expected_scan_pending_payments_msg_and_interval.clone(),
                expected_scan_pending_payments_msg_and_interval.clone(),
                expected_scan_pending_payments_msg_and_interval.clone(),
                expected_scan_pending_payments_msg_and_interval
            ]
        );
        let mut notify_confirm_transaction_params =
            notify_confirm_transaction_params_arc.lock().unwrap();
        let actual_confirmed_payment: ConfirmPendingTransaction =
            notify_confirm_transaction_params.remove(0);
        assert!(notify_confirm_transaction_params.is_empty());
        let expected_confirmation_message = ConfirmPendingTransaction {
            payment_backup: payment_2_backup_fourth_round,
        };
        assert_eq!(actual_confirmed_payment, expected_confirmation_message);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(
            "WARN: Accountant: Broken transaction 0x0000…007b left with an error mark; you should take over the care of this transaction to make sure your debts will be paid because there \
             is no automated process that can fix this without you");
        log_handler.exists_log_matching("INFO: Accountant: Transaction '0x0000…0237' has been added to the blockchain; detected locally at attempt 4 at \\d{2,}ms after its sending");
        log_handler.exists_log_containing("INFO: Accountant: Transaction 0x0000000000000000000000000000000000000000000000000000000000000237 has gone through the whole confirmation process succeeding");
    }

    #[test]
    fn handle_pending_tx_checkout_handles_none_returned_for_transaction_receipt() {
        init_test_logging();
        let subject = AccountantBuilder::default().build();
        let tx_receipt_opt = None;
        let rowid = 455;
        let hash = H256::from_uint(&U256::from(2323));
        let payment_backup_record = PaymentBackupRecord {
            rowid,
            timestamp: SystemTime::now().sub(Duration::from_millis(10000)),
            hash,
            attempt: 3,
            amount: 111,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            payment_backups_with_receipts: vec![(tx_receipt_opt, payment_backup_record.clone())],
        };

        let result = subject.handle_pending_transaction_check(msg.clone());

        assert_eq!(
            result,
            vec![PendingTransactionStatus::StillPending(TransactionId {
                hash,
                rowid
            })]
        );
        TestLogHandler::new().exists_log_matching("DEBUG: Accountant: Interpreting a receipt for transaction '0x0000…0913' but none was given; attempt 3, 100\\d\\dms since sending");
    }

    #[test]
    fn accountant_receives_reported_transaction_receipts_and_processes_them_all() {
        let notify_handle_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default().build();
        subject
            .transaction_confirmation
            .notify_handle_confirm_transaction =
            Box::new(NotifyHandleMock::default().notify_params(&notify_handle_params_arc));
        let subject_addr = subject.start();
        let transaction_hash_1 = H256::from_uint(&U256::from(4545));
        let mut transaction_receipt_1 = TransactionReceipt::default();
        transaction_receipt_1.transaction_hash = transaction_hash_1;
        transaction_receipt_1.status = Some(U64::from(1)); //success
        let payment_backup_1 = PaymentBackupRecord {
            rowid: 5,
            timestamp: from_time_t(200_000_000),
            hash: transaction_hash_1,
            attempt: 2,
            amount: 444,
            process_error: None,
        };
        let transaction_hash_2 = H256::from_uint(&U256::from(3333333));
        let mut transaction_receipt_2 = TransactionReceipt::default();
        transaction_receipt_2.transaction_hash = transaction_hash_2;
        transaction_receipt_2.status = Some(U64::from(1)); //success
        let payment_backup_2 = PaymentBackupRecord {
            rowid: 10,
            timestamp: from_time_t(199_780_000),
            hash: Default::default(),
            attempt: 15,
            amount: 1212,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            payment_backups_with_receipts: vec![
                (Some(transaction_receipt_1), payment_backup_1.clone()),
                (Some(transaction_receipt_2), payment_backup_2.clone()),
            ],
        };

        let _ = subject_addr.try_send(msg).unwrap();

        let system = System::new("processing reported receipts");
        System::current().stop();
        system.run();
        let notify_handle_params = notify_handle_params_arc.lock().unwrap();
        assert_eq!(
            *notify_handle_params,
            vec![
                ConfirmPendingTransaction {
                    payment_backup: payment_backup_1
                },
                ConfirmPendingTransaction {
                    payment_backup: payment_backup_2
                }
            ]
        );
    }

    #[test]
    fn check_out_transaction_receipt_when_transaction_status_is_a_failure() {
        init_test_logging();
        let subject = AccountantBuilder::default().build();
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(0)); //failure
        let hash = H256::from_uint(&U256::from(4567));
        let pending_payment_backup = PaymentBackupRecord {
            rowid: 777777,
            timestamp: SystemTime::now().sub(Duration::from_millis(150000)),
            hash,
            attempt: 5,
            amount: 2222,
            process_error: None,
        };

        let result = subject.check_out_transaction_receipt(
            tx_receipt,
            pending_payment_backup,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(TransactionId {
                hash,
                rowid: 777777
            })
        );
        TestLogHandler::new().exists_log_matching("WARN: receipt_check_logger: Pending \
         transaction '0x0000…11d7' announced as a failure, checking out attempt 5 after 1500\\d\\dms from its sending");
    }

    #[test]
    fn check_out_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(567));
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent = SystemTime::now().sub(Duration::from_millis(100));
        let subject = AccountantBuilder::default().build();
        let payment_backup = PaymentBackupRecord {
            rowid,
            timestamp: when_sent,
            hash,
            attempt: 1,
            amount: 123,
            process_error: None,
        };

        let result = subject.check_out_transaction_receipt(
            tx_receipt,
            payment_backup.clone(),
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::StillPending(TransactionId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(
            "INFO: receipt_check_logger: Pending \
         transaction '0x0000…0237' couldn't be confirmed at attempt 1 at 100ms after its sending",
        );
    }

    #[test]
    fn check_out_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval()
    {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(567));
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent =
            SystemTime::now().sub(Duration::from_secs(DEFAULT_PENDING_TOO_LONG_SEC + 5)); //old transaction
        let subject = AccountantBuilder::default().build();
        let payment_backup = PaymentBackupRecord {
            rowid,
            timestamp: when_sent,
            hash,
            attempt: 10,
            amount: 123,
            process_error: None,
        };

        let result = subject.check_out_transaction_receipt(
            tx_receipt,
            payment_backup.clone(),
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(TransactionId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(
            "WARN: receipt_check_logger: Pending transaction '0x0000…0237' has exceeded the \
             maximum time allowed (21600sec) for being pending and the confirmation process is going to \
              be aborted now at the finished attempt 10; manual resolving is required from the user to \
               make the transaction paid",
        );
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending '0x0000…007b' - tx status: code other than 0 or 1 shouldn't be possible, but was 456"
    )]
    fn check_out_transaction_receipt_panics_at_undefined_status_code() {
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        let mut payment_backup = make_payment_backup();
        payment_backup.hash = H256::from_uint(&U256::from(123));
        let subject = AccountantBuilder::default().build();

        let _ = subject.check_out_transaction_receipt(
            tx_receipt,
            payment_backup,
            &Logger::new("receipt_check_logger"),
        );
    }

    #[test]
    fn is_non_pending_is_properly_set() {
        assert_eq!(
            PendingTransactionStatus::Failure(make_transaction_id()).is_non_pending(),
            true
        );
        assert_eq!(
            PendingTransactionStatus::Confirmed(make_payment_backup()).is_non_pending(),
            true
        );
        assert_eq!(
            PendingTransactionStatus::StillPending(make_transaction_id()).is_non_pending(),
            false
        )
    }

    #[test]
    fn accountant_handles_payment_backup() {
        init_test_logging();
        let insert_payment_backup_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payment_dao_factory = PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default()
                .insert_payment_backup_params(&insert_payment_backup_params_arc)
                .insert_payment_backup_result(Ok(())),
        );
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(pending_payment_dao_factory))
            .build();
        let accountant_addr = subject.start();
        let tx_hash = H256::from_uint(&U256::from(55));
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let amount = 4055;
        let timestamp = SystemTime::now();
        let backup_message = PaymentBackupRecord {
            rowid: 0,
            timestamp,
            hash: tx_hash,
            attempt: 0,
            amount,
            process_error: None,
        };

        let _ = accountant_subs
            .payment_backup
            .try_send(backup_message.clone())
            .unwrap();

        let system = System::new("ordering payment backup test");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let insert_payment_backup_params = insert_payment_backup_params_arc.lock().unwrap();
        assert_eq!(
            *insert_payment_backup_params,
            vec![(tx_hash, amount, timestamp)]
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Processed a backup for payment '0x0000…0037'",
        );
    }

    #[test]
    fn payment_backup_insertion_clearly_failed_and_we_log_it_at_least() {
        //despite it doesn't happen here this event would cause a panic later
        init_test_logging();
        let insert_payment_backup_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payment_dao_factory = PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default()
                .insert_payment_backup_params(&insert_payment_backup_params_arc)
                .insert_payment_backup_result(Err(PendingPaymentDaoError::InsertionFailed(
                    "Crashed".to_string(),
                ))),
        );
        let amount = 2345;
        let transaction_hash = H256::from_uint(&U256::from(456));
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(pending_payment_dao_factory))
            .build();
        let timestamp_secs = 150_000_000;
        let backup_message = PaymentBackupRecord {
            rowid: 0,
            timestamp: from_time_t(timestamp_secs),
            hash: transaction_hash,
            attempt: 0,
            amount,
            process_error: None,
        };

        let _ = subject.handle_payment_backup(backup_message);

        let initiate_backup_params = insert_payment_backup_params_arc.lock().unwrap();
        assert_eq!(
            *initiate_backup_params,
            vec![(transaction_hash, amount, from_time_t(timestamp_secs))]
        );
        TestLogHandler::new().exists_log_containing("WARN: Accountant: Failed to make a backup for pending payment '0x0000…01c8' due to 'InsertionFailed(\"Crashed\")'");
    }

    #[test]
    fn separate_early_errors_works() {
        let payment_ok = Payment {
            to: make_wallet("blah"),
            amount: 5555,
            timestamp: SystemTime::now(),
            transaction: Default::default(),
        };
        let error = BlockchainError::SignedValueConversion(666);
        let sent_payments = SentPayments {
            payments: vec![Ok(payment_ok.clone()), Err(error.clone())],
        };

        let (ok, err) = Accountant::separate_early_errors(sent_payments, &Logger::new("test"));

        assert_eq!(ok, vec![payment_ok]);
        assert_eq!(err, vec![error])
    }

    #[test]
    fn separate_transactions_if_still_pending_works() {
        let statuses = vec![
            PendingTransactionStatus::Confirmed(make_payment_backup()),
            PendingTransactionStatus::StillPending(make_transaction_id()),
            PendingTransactionStatus::Failure(make_transaction_id()),
        ];

        let (pending, non_pending) = Accountant::separate_transactions_if_still_pending(statuses);

        assert_eq!(
            pending,
            vec![PendingTransactionStatus::StillPending(make_transaction_id())]
        );
        assert_eq!(
            non_pending,
            vec![
                PendingTransactionStatus::Confirmed(make_payment_backup()),
                PendingTransactionStatus::Failure(make_transaction_id())
            ]
        )
    }

    #[test]
    fn update_backup_of_pending_transaction_happy_path() {
        let update_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = H256::from_uint(&U256::from(444888));
        let rowid_1 = 3456;
        let hash_2 = H256::from_uint(&U256::from(111000));
        let rowid_2 = 3450;
        let pending_payment_dao_factory = Box::new(PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default()
                .update_backup_after_scan_cycle_params(&update_after_cycle_params_arc)
                .update_backup_after_scan_cycle_results(Ok(()))
                .update_backup_after_scan_cycle_results(Ok(())),
        ));
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(pending_payment_dao_factory)
            .build();
        let pending_payments = vec![
            PendingTransactionStatus::StillPending(TransactionId {
                hash: hash_1,
                rowid: rowid_1,
            }),
            PendingTransactionStatus::StillPending(TransactionId {
                hash: hash_2,
                rowid: rowid_2,
            }),
        ];

        let _ = subject.update_backup_of_pending_transaction(pending_payments);

        let update_after_cycle_params = update_after_cycle_params_arc.lock().unwrap();
        assert_eq!(*update_after_cycle_params, vec![rowid_1, rowid_2])
    }

    #[test]
    #[should_panic(
        expected = "Failure on updating payment backup due to UpdateFailed(\"yeah, bad\")"
    )]
    fn update_backup_of_pending_transaction_sad_path() {
        let hash = H256::from_uint(&U256::from(444888));
        let rowid = 3456;
        let pending_payment_dao_factory = Box::new(PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default().update_backup_after_scan_cycle_results(Err(
                PendingPaymentDaoError::UpdateFailed("yeah, bad".to_string()),
            )),
        ));
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(pending_payment_dao_factory)
            .build();
        let pending_payments = vec![PendingTransactionStatus::StillPending(TransactionId {
            hash,
            rowid,
        })];

        let _ = subject.update_backup_of_pending_transaction(pending_payments);
    }

    #[test]
    fn jackass_unsigned_to_signed_handles_zero() {
        let result = jackass_unsigned_to_signed(0u64);

        assert_eq!(result, Ok(0i64));
    }

    #[test]
    fn jackass_unsigned_to_signed_handles_max_allowable() {
        let result = jackass_unsigned_to_signed(i64::MAX as u64);

        assert_eq!(result, Ok(i64::MAX));
    }

    #[test]
    fn jackass_unsigned_to_signed_handles_max_plus_one() {
        let attempt = (i64::MAX as u64) + 1;
        let result = jackass_unsigned_to_signed((i64::MAX as u64) + 1);

        assert_eq!(result, Err(attempt));
    }

    fn make_transaction_id() -> TransactionId {
        TransactionId {
            hash: H256::from_uint(&U256::from(789)),
            rowid: 1,
        }
    }
}
