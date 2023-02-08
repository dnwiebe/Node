// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_scanner_utils {
    use crate::accountant::dao_utils::ThresholdUtils;
    use crate::accountant::payable_dao::{PayableAccount, PendingPayable};
    use crate::accountant::scanners_utils::payable_scanner_utils::PayableTransactingErrorEnum::{
        LocallyCausedError, RemotelyCausedErrors,
    };
    use crate::accountant::SentPayables;
    use crate::blockchain::blockchain_interface::BlockchainError::PayableTransactionFailed;
    use crate::blockchain::blockchain_interface::ProcessedPayableFallible::{Correct, Failure};
    use crate::blockchain::blockchain_interface::{
        BlockchainError, ProcessedPayableFallible, RpcPayableFailure,
    };
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::sub_lib::wallet::Wallet;
    use itertools::Itertools;
    use masq_lib::logger::Logger;
    use masq_lib::utils::plus;
    #[cfg(test)]
    use std::any::Any;
    use std::cmp::Ordering;
    use std::time::SystemTime;
    use thousands::Separable;
    use web3::types::H256;

    pub type RefWalletAndRowidOptCoupledWithHash<'a> = ((&'a Wallet, Option<u64>), H256);

    pub type VecOfRowidOptAndHash = Vec<(Option<u64>, H256)>;

    #[derive(Debug, PartialEq)]
    pub enum PayableTransactingErrorEnum {
        LocallyCausedError(BlockchainError),
        RemotelyCausedErrors(Vec<H256>),
    }

    //debugging purposes only
    pub fn investigate_debt_extremes(
        timestamp: SystemTime,
        all_non_pending_payables: &[PayableAccount],
    ) -> String {
        #[derive(Clone, Copy, Default)]
        struct PayableInfo {
            balance_wei: u128,
            age: u64,
        }
        fn bigger(payable_1: PayableInfo, payable_2: PayableInfo) -> PayableInfo {
            match payable_1.balance_wei.cmp(&payable_2.balance_wei) {
                Ordering::Greater => payable_1,
                Ordering::Less => payable_2,
                Ordering::Equal => {
                    if payable_1.age == payable_2.age {
                        payable_1
                    } else {
                        older(payable_1, payable_2)
                    }
                }
            }
        }
        fn older(payable_1: PayableInfo, payable_2: PayableInfo) -> PayableInfo {
            match payable_1.age.cmp(&payable_2.age) {
                Ordering::Greater => payable_1,
                Ordering::Less => payable_2,
                Ordering::Equal => {
                    if payable_1.balance_wei == payable_2.balance_wei {
                        payable_1
                    } else {
                        bigger(payable_1, payable_2)
                    }
                }
            }
        }

        if all_non_pending_payables.is_empty() {
            return "Payable scan found no debts".to_string();
        }
        let (biggest, oldest) = all_non_pending_payables
            .iter()
            .map(|payable| PayableInfo {
                balance_wei: payable.balance_wei,
                age: timestamp
                    .duration_since(payable.last_paid_timestamp)
                    .expect("Payable time is corrupt")
                    .as_secs(),
            })
            .fold(
                Default::default(),
                |(so_far_biggest, so_far_oldest): (PayableInfo, PayableInfo), payable| {
                    (
                        bigger(so_far_biggest, payable),
                        older(so_far_oldest, payable),
                    )
                },
            );
        format!("Payable scan found {} debts; the biggest is {} owed for {}sec, the oldest is {} owed for {}sec",
                all_non_pending_payables.len(), biggest.balance_wei, biggest.age,
                oldest.balance_wei, oldest.age)
    }

    pub fn separate_errors<'a, 'b>(
        sent_payables: &'a SentPayables,
        logger: &'b Logger,
    ) -> (Vec<&'a PendingPayable>, Option<PayableTransactingErrorEnum>) {
        match &sent_payables.payment_result {
            Ok(individual_batch_responses) => {
                if individual_batch_responses.is_empty() {
                    panic!("Broken code: An empty vector of processed payments claiming to be an Ok value")
                }
                let (oks, err_hashes_opt) =
                    separate_rpc_results(individual_batch_responses, logger);

                let errs_opt = err_hashes_opt.map(RemotelyCausedErrors);
                (oks, errs_opt)
            }
            Err(e) => {
                warning!(
                    logger,
                    "Failed process to be screened for persisted data. Cause by: {}",
                    e
                );

                (vec![], Some(LocallyCausedError(e.clone())))
            }
        }
    }

    fn separate_rpc_results<'a, 'b>(
        individual_responses_in_the_batch: &'a [ProcessedPayableFallible],
        logger: &'b Logger,
    ) -> (Vec<&'a PendingPayable>, Option<Vec<H256>>) {
        fn add_another_correct_transaction<'a>(
            acc: (Vec<&'a PendingPayable>, Vec<H256>),
            pending_payable: &'a PendingPayable,
        ) -> (Vec<&'a PendingPayable>, Vec<H256>) {
            (plus(acc.0, pending_payable), acc.1)
        }
        fn add_another_rpc_failure(
            acc: (Vec<&PendingPayable>, Vec<H256>),
            hash: H256,
        ) -> (Vec<&PendingPayable>, Vec<H256>) {
            (acc.0, plus(acc.1, hash))
        }

        let init = (vec![], vec![]);
        let (oks, errs) = individual_responses_in_the_batch
            .iter()
            .fold(init,|acc, rpc_result| match rpc_result {
                Correct(pending_payable) => add_another_correct_transaction(acc, pending_payable),
                Failure(RpcPayableFailure{rpc_error,recipient_wallet,hash }) => {
                    warning!(logger,
                        "Remote transaction failure: '{}' for payment to {} and transaction hash {:?}. \
                      Please check your blockchain service URL configuration.", rpc_error, recipient_wallet, hash);
                    add_another_rpc_failure(acc, *hash)
                }
            });

        let errs_opt = if !errs.is_empty() { Some(errs) } else { None };

        (oks, errs_opt)
    }

    pub fn payables_debug_summary(qualified_accounts: &[(PayableAccount, u128)], logger: &Logger) {
        if qualified_accounts.is_empty() {
            return;
        }
        debug!(logger, "Paying qualified debts:\n{}", {
            let now = SystemTime::now();
            qualified_accounts
                .iter()
                .map(|(payable, threshold_point)| {
                    let p_age = now
                        .duration_since(payable.last_paid_timestamp)
                        .expect("Payable time is corrupt");
                    format!(
                        "{} wei owed for {} sec exceeds threshold: {} wei; creditor: {}",
                        payable.balance_wei.separate_with_commas(),
                        p_age.as_secs(),
                        threshold_point.separate_with_commas(),
                        payable.wallet
                    )
                })
                .join("\n")
        })
    }

    pub fn debugging_summary_after_error_separation(
        oks: &[&PendingPayable],
        errs_opt: &Option<PayableTransactingErrorEnum>,
    ) -> String {
        format!(
            "Got {} properly sent payables of {} attempts",
            oks.len(),
            count_total_errors(errs_opt)
                .map(|err_count| (err_count + oks.len()).to_string())
                .unwrap_or_else(|| "not determinable number of".to_string())
        )
    }

    pub(super) fn count_total_errors(
        full_set_of_errors: &Option<PayableTransactingErrorEnum>,
    ) -> Option<usize> {
        match full_set_of_errors {
            Some(errors) => match errors {
                LocallyCausedError(blockchain_error) => match blockchain_error {
                    PayableTransactionFailed {
                        signed_and_saved_txs_opt,
                        ..
                    } => signed_and_saved_txs_opt.as_ref().map(|hashes| hashes.len()),
                    _ => None,
                },
                RemotelyCausedErrors(b_e) => Some(b_e.len()),
            },
            None => Some(0),
        }
    }

    pub trait PayableThresholdsGauge {
        fn is_innocent_age(&self, age: u64, limit: u64) -> bool;
        fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool;
        fn calculate_payout_threshold_in_gwei(
            &self,
            payment_thresholds: &PaymentThresholds,
            x: u64,
        ) -> u128;
        as_any_dcl!();
    }

    #[derive(Default)]
    pub struct PayableThresholdsGaugeReal {}

    impl PayableThresholdsGauge for PayableThresholdsGaugeReal {
        fn is_innocent_age(&self, age: u64, limit: u64) -> bool {
            age <= limit
        }

        fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool {
            balance <= limit
        }

        fn calculate_payout_threshold_in_gwei(
            &self,
            payment_thresholds: &PaymentThresholds,
            debt_age: u64,
        ) -> u128 {
            ThresholdUtils::calculate_finite_debt_limit_by_age(payment_thresholds, debt_age)
        }
        as_any_impl!();
    }
}

pub mod pending_payable_scanner_utils {
    use crate::accountant::PendingPayableId;
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use masq_lib::logger::Logger;
    use std::time::SystemTime;

    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    pub struct PendingPayableScanSummary {
        pub still_pending: Vec<PendingPayableId>,
        pub failures: Vec<PendingPayableId>,
        pub confirmed: Vec<PendingPayableFingerprint>,
    }

    pub fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
        timestamp
            .elapsed()
            .expect("time calculation for elapsed failed")
            .as_millis()
    }

    pub fn handle_none_status(
        mut scan_summary: PendingPayableScanSummary,
        fingerprint: PendingPayableFingerprint,
        max_pending_interval: u64,
        logger: &Logger,
    ) -> PendingPayableScanSummary {
        info!(
            logger,
            "Pending transaction {:?} couldn't be confirmed at attempt \
            {} at {}ms after its sending",
            fingerprint.hash,
            fingerprint.attempt,
            elapsed_in_ms(fingerprint.timestamp)
        );
        let elapsed = fingerprint
            .timestamp
            .elapsed()
            .expect("we should be older now");
        if max_pending_interval <= elapsed.as_secs() {
            error!(
                logger,
                "Pending transaction {:?} has exceeded the maximum pending time \
                ({}sec) and the confirmation process is going to be aborted now \
                at the final attempt {}; manual resolution is required from the \
                user to complete the transaction.",
                fingerprint.hash,
                max_pending_interval,
                fingerprint.attempt
            );
            scan_summary.failures.push(fingerprint.into())
        } else {
            scan_summary.still_pending.push(fingerprint.into())
        }
        scan_summary
    }

    pub fn handle_status_with_success(
        mut scan_summary: PendingPayableScanSummary,
        fingerprint: PendingPayableFingerprint,
        logger: &Logger,
    ) -> PendingPayableScanSummary {
        info!(
            logger,
            "Transaction {:?} has been added to the blockchain; detected locally at attempt \
            {} at {}ms after its sending",
            fingerprint.hash,
            fingerprint.attempt,
            elapsed_in_ms(fingerprint.timestamp)
        );
        scan_summary.confirmed.push(fingerprint.clone());
        scan_summary
    }

    pub fn handle_status_with_failure(
        mut scan_summary: PendingPayableScanSummary,
        fingerprint: PendingPayableFingerprint,
        logger: &Logger,
    ) -> PendingPayableScanSummary {
        error!(
            logger,
            "Pending transaction {:?} announced as a failure, interpreting attempt \
            {} after {}ms from the sending",
            fingerprint.hash,
            fingerprint.attempt,
            elapsed_in_ms(fingerprint.timestamp)
        );
        scan_summary.failures.push(fingerprint.into());
        scan_summary
    }
}

pub mod receivable_scanner_utils {
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::wei_to_gwei;
    use std::time::{Duration, SystemTime};
    use thousands::Separable;

    pub fn balance_and_age(time: SystemTime, account: &ReceivableAccount) -> (String, Duration) {
        let balance = wei_to_gwei::<i64, i128>(account.balance_wei).separate_with_commas();
        let age = time
            .duration_since(account.last_received_timestamp)
            .unwrap_or_else(|_| Duration::new(0, 0));
        (balance, age)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::dao_utils::{from_time_t, to_time_t};
    use crate::accountant::payable_dao::{PayableAccount, PendingPayable};
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::scanners_utils::payable_scanner_utils::PayableTransactingErrorEnum::{
        LocallyCausedError, RemotelyCausedErrors,
    };
    use crate::accountant::scanners_utils::payable_scanner_utils::{
        count_total_errors, debugging_summary_after_error_separation, investigate_debt_extremes,
        payables_debug_summary, separate_errors, PayableThresholdsGauge,
        PayableThresholdsGaugeReal,
    };
    use crate::accountant::scanners_utils::receivable_scanner_utils::balance_and_age;
    use crate::accountant::{checked_conversion, gwei_to_wei, SentPayables};
    use crate::blockchain::blockchain_interface::BlockchainError::PayableTransactionFailed;
    use crate::blockchain::blockchain_interface::ProcessedPayableFallible::{Correct, Failure};
    use crate::blockchain::blockchain_interface::{BlockchainError, RpcPayableFailure};
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use masq_lib::constants::WEIS_OF_GWEI;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::SystemTime;

    #[test]
    fn investigate_debt_extremes_picks_the_most_relevant_records() {
        let now = SystemTime::now();
        let now_t = to_time_t(now);
        let same_amount_significance = 2_000_000;
        let same_age_significance = from_time_t(now_t - 30000);
        let payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance_wei: same_amount_significance,
                last_paid_timestamp: from_time_t(now_t - 5000),
                pending_payable_opt: None,
            },
            //this debt is more significant because beside being high in amount it's also older, so should be prioritized and picked
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: same_amount_significance,
                last_paid_timestamp: from_time_t(now_t - 10000),
                pending_payable_opt: None,
            },
            //similarly these two wallets have debts equally old but the second has a bigger balance and should be chosen
            PayableAccount {
                wallet: make_wallet("wallet3"),
                balance_wei: 100,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance_wei: 330,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
        ];

        let result = investigate_debt_extremes(now, payables);

        assert_eq!(result, "Payable scan found 4 debts; the biggest is 2000000 owed for 10000sec, the oldest is 330 owed for 30000sec")
    }

    #[test]
    fn balance_and_age_is_calculated_as_expected() {
        let now = SystemTime::now();
        let offset = 1000;
        let receivable_account = ReceivableAccount {
            wallet: make_wallet("wallet0"),
            balance_wei: 10_000_000_000,
            last_received_timestamp: from_time_t(to_time_t(now) - offset),
        };

        let (balance, age) = balance_and_age(now, &receivable_account);

        assert_eq!(balance, "10");
        assert_eq!(age.as_secs(), offset as u64);
    }

    #[test]
    fn separate_errors_works_for_no_errs_just_oks() {
        let correct_payment = PendingPayable {
            recipient_wallet: make_wallet("blah"),
            hash: make_tx_hash(123),
        };
        let sent_payable = SentPayables {
            payment_result: Ok(vec![Correct(correct_payment.clone())]),
            response_skeleton_opt: None,
        };

        let (oks, errs) = separate_errors(&sent_payable, &Logger::new("test"));

        assert_eq!(oks, vec![&correct_payment]);
        assert_eq!(errs, None)
    }

    #[test]
    fn separate_errors_works_for_our_errors() {
        init_test_logging();
        let error = PayableTransactionFailed {
            msg: "bad timing".to_string(),
            signed_and_saved_txs_opt: None,
        };
        let sent_payable = SentPayables {
            payment_result: Err(error.clone()),
            response_skeleton_opt: None,
        };

        let (oks, errs) = separate_errors(&sent_payable, &Logger::new("test_logger"));

        assert!(oks.is_empty());
        assert_eq!(errs, Some(LocallyCausedError(error)));
        TestLogHandler::new().exists_log_containing("WARN: test_logger: Failed process to be screened for persisted data. Cause by: \
         Blockchain error: Batch processing: \"bad timing\". Without prepared transactions, no hashes to report");
    }

    #[test]
    fn separate_errors_works_for_their_errors() {
        init_test_logging();
        let payable_ok = PendingPayable {
            recipient_wallet: make_wallet("blah"),
            hash: make_tx_hash(123),
        };
        let bad_rpc_call = RpcPayableFailure {
            rpc_error: web3::Error::InvalidResponse("that donkey screwed it up".to_string()),
            recipient_wallet: make_wallet("whooa"),
            hash: make_tx_hash(789),
        };
        let sent_payable = SentPayables {
            payment_result: Ok(vec![
                Correct(payable_ok.clone()),
                Failure(bad_rpc_call.clone()),
            ]),
            response_skeleton_opt: None,
        };

        let (oks, errs) = separate_errors(&sent_payable, &Logger::new("test_logger"));

        assert_eq!(oks, vec![&payable_ok]);
        assert_eq!(errs, Some(RemotelyCausedErrors(vec![make_tx_hash(789)])));
        TestLogHandler::new().exists_log_containing("WARN: test_logger: Remote transaction failure: 'Got invalid response: \
         that donkey screwed it up' for payment to 0x00000000000000000000000000000077686f6f61 and transaction hash \
          0x0000000000000000000000000000000000000000000000000000000000000315. Please check your blockchain service URL configuration.");
    }

    #[test]
    fn payables_debug_summary_stays_inert_if_no_qualified_payments() {
        init_test_logging();
        let logger = Logger::new("payables_debug_summary_stays_inert_if_no_qualified_payments");

        payables_debug_summary(&vec![], &logger);

        TestLogHandler::new().exists_no_log_containing(
            "DEBUG: payables_debug_summary_stays_\
        inert_if_no_qualified_payments: Paying qualified debts:",
        );
    }

    #[test]
    fn payables_debug_summary_prints_pretty_summary() {
        init_test_logging();
        let now = to_time_t(SystemTime::now());
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 2_592_000,
            debt_threshold_gwei: 1_000_000_000,
            payment_grace_period_sec: 86_400,
            maturity_threshold_sec: 86_400,
            permanent_debt_allowed_gwei: 10_000_000,
            unban_below_gwei: 10_000_000,
        };
        let qualified_payables_and_threshold_points = vec![
            (
                PayableAccount {
                    wallet: make_wallet("wallet0"),
                    balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 2000),
                    last_paid_timestamp: from_time_t(
                        now - checked_conversion::<u64, i64>(
                            payment_thresholds.maturity_threshold_sec
                                + payment_thresholds.threshold_interval_sec,
                        ),
                    ),
                    pending_payable_opt: None,
                },
                10_000_000_001_152_000_u128,
            ),
            (
                PayableAccount {
                    wallet: make_wallet("wallet1"),
                    balance_wei: gwei_to_wei(payment_thresholds.debt_threshold_gwei - 1),
                    last_paid_timestamp: from_time_t(
                        now - checked_conversion::<u64, i64>(
                            payment_thresholds.maturity_threshold_sec + 55,
                        ),
                    ),
                    pending_payable_opt: None,
                },
                999_978_993_055_555_580,
            ),
        ];
        let logger = Logger::new("test");

        payables_debug_summary(&qualified_payables_and_threshold_points, &logger);

        TestLogHandler::new().exists_log_containing("Paying qualified debts:\n\
                   10,002,000,000,000,000 wei owed for 2678400 sec exceeds threshold: \
                   10,000,000,001,152,000 wei; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   999,999,999,000,000,000 wei owed for 86455 sec exceeds threshold: \
                   999,978,993,055,555,580 wei; creditor: 0x0000000000000000000000000077616c6c657431");
    }

    #[test]
    fn payout_sloped_segment_in_payment_thresholds_goes_along_proper_line() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 333,
            payment_grace_period_sec: 444,
            permanent_debt_allowed_gwei: 4444,
            debt_threshold_gwei: 8888,
            threshold_interval_sec: 1111111,
            unban_below_gwei: 0,
        };
        let higher_corner_timestamp = payment_thresholds.maturity_threshold_sec;
        let middle_point_timestamp = payment_thresholds.maturity_threshold_sec
            + payment_thresholds.threshold_interval_sec / 2;
        let lower_corner_timestamp =
            payment_thresholds.maturity_threshold_sec + payment_thresholds.threshold_interval_sec;
        let tested_fn = |payment_thresholds: &PaymentThresholds, time| {
            PayableThresholdsGaugeReal {}
                .calculate_payout_threshold_in_gwei(payment_thresholds, time) as i128
        };

        let higher_corner_point = tested_fn(&payment_thresholds, higher_corner_timestamp);
        let middle_point = tested_fn(&payment_thresholds, middle_point_timestamp);
        let lower_corner_point = tested_fn(&payment_thresholds, lower_corner_timestamp);

        let allowed_imprecision = WEIS_OF_GWEI;
        let ideal_template_higher: i128 = gwei_to_wei(payment_thresholds.debt_threshold_gwei);
        let ideal_template_middle: i128 = gwei_to_wei(
            (payment_thresholds.debt_threshold_gwei
                - payment_thresholds.permanent_debt_allowed_gwei)
                / 2
                + payment_thresholds.permanent_debt_allowed_gwei,
        );
        let ideal_template_lower: i128 =
            gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei);
        assert!(
            higher_corner_point <= ideal_template_higher + allowed_imprecision
                && ideal_template_higher - allowed_imprecision <= higher_corner_point,
            "ideal: {}, real: {}",
            ideal_template_higher,
            higher_corner_point
        );
        assert!(
            middle_point <= ideal_template_middle + allowed_imprecision
                && ideal_template_middle - allowed_imprecision <= middle_point,
            "ideal: {}, real: {}",
            ideal_template_middle,
            middle_point
        );
        assert!(
            lower_corner_point <= ideal_template_lower + allowed_imprecision
                && ideal_template_lower - allowed_imprecision <= lower_corner_point,
            "ideal: {}, real: {}",
            ideal_template_lower,
            lower_corner_point
        )
    }

    #[test]
    fn is_innocent_age_works_for_age_smaller_than_innocent_age() {
        let payable_age = 999;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_age_works_for_age_equal_to_innocent_age() {
        let payable_age = 1000;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_age_works_for_excessive_age() {
        let payable_age = 1001;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, false)
    }

    #[test]
    fn is_innocent_balance_works_for_balance_smaller_than_innocent_balance() {
        let payable_balance = 999;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_balance_works_for_balance_equal_to_innocent_balance() {
        let payable_balance = 1000;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_balance_works_for_excessive_balance() {
        let payable_balance = 1001;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, false)
    }

    #[test]
    fn count_total_errors_says_unidentifiable_for_very_early_local_error() {
        let sent_payable = Some(LocallyCausedError(BlockchainError::InvalidUrl));

        let result = count_total_errors(&sent_payable);

        assert_eq!(result, None)
    }

    #[test]
    fn count_total_errors_says_unidentifiable_for_local_error_before_signing() {
        let error = PayableTransactionFailed {
            msg: "Ouuuups".to_string(),
            signed_and_saved_txs_opt: None,
        };
        let sent_payable = Some(LocallyCausedError(error));

        let result = count_total_errors(&sent_payable);

        assert_eq!(result, None)
    }

    #[test]
    fn count_total_errors_works_correctly_for_local_error_after_signing() {
        let error = PayableTransactionFailed {
            msg: "Ouuuups".to_string(),
            signed_and_saved_txs_opt: Some(vec![make_tx_hash(333), make_tx_hash(666)]),
        };
        let sent_payable = Some(LocallyCausedError(error));

        let result = count_total_errors(&sent_payable);

        assert_eq!(result, Some(2))
    }

    #[test]
    fn count_total_errors_works_correctly_for_remote_errors() {
        let sent_payable = Some(RemotelyCausedErrors(vec![
            make_tx_hash(123),
            make_tx_hash(456),
        ]));

        let result = count_total_errors(&sent_payable);

        assert_eq!(result, Some(2))
    }

    #[test]
    fn count_total_errors_works_correctly_if_no_errors_found_at_all() {
        let sent_payable = None;

        let result = count_total_errors(&sent_payable);

        assert_eq!(result, Some(0))
    }

    #[test]
    fn debug_summary_after_error_separation_says_the_count_is_unidentifiable() {
        let oks = vec![];
        let error = BlockchainError::InvalidAddress;
        let errs = Some(LocallyCausedError(error));

        let result = debugging_summary_after_error_separation(&oks, &errs);

        assert_eq!(
            result,
            "Got 0 properly sent payables of not determinable number of attempts"
        )
    }
}
