// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

// If possible, let these modules be private
mod adjustment_runners;
mod criterion_calculators;
mod diagnostics;
mod disqualification_arbiter;
mod inner;
#[cfg(test)]
mod loading_test;
mod log_fns;
mod miscellaneous;
mod preparatory_analyser;
#[cfg(test)]
mod test_utils;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::adjustment_runners::{
    AdjustmentRunner, TransactionAndServiceFeeAdjustmentRunner, ServiceFeeOnlyAdjustmentRunner,
};
use crate::accountant::payment_adjuster::diagnostics::{diagnostics, collection_diagnostics};
use crate::accountant::payment_adjuster::inner::{
    PaymentAdjusterInner, PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
};
use crate::accountant::payment_adjuster::log_fns::{
    accounts_before_and_after_debug,
    log_transaction_fee_adjustment_ok_but_by_service_fee_undoable,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::RequiredSpecialTreatment::{
    TreatInsignificantAccount, TreatOutweighedAccounts,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{AdjustedAccountBeforeFinalization, AdjustmentIterationResult, RecursionResults, UnconfirmedAdjustment, WeightedPayable};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{weights_total, exhaust_cw_till_the_last_drop, adjust_account_balance_if_outweighed, drop_no_longer_needed_weights_away_from_accounts, dump_unaffordable_accounts_by_txn_fee, sum_as, compute_mul_coefficient_preventing_fractional_numbers, sort_in_descendant_order_by_weights, zero_affordable_accounts_found, find_largest_weight};
use crate::accountant::payment_adjuster::preparatory_analyser::{PreparatoryAnalyzer};
use crate::diagnostics;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;
use masq_lib::utils::convert_collection;
use crate::accountant::payment_adjuster::criterion_calculators::balance_and_age_calculator::BalanceAndAgeCriterionCalculator;
use crate::accountant::payment_adjuster::criterion_calculators::{CriterionCalculator};
use crate::accountant::payment_adjuster::diagnostics::ordinary_diagnostic_functions::{calculated_criterion_and_weight_diagnostics, proposed_adjusted_balance_diagnostics};
use crate::accountant::payment_adjuster::disqualification_arbiter::{DisqualificationArbiter, DisqualificationGauge, DisqualificationGaugeReal};
use crate::accountant::QualifiedPayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        qualified_payables: &[QualifiedPayableAccount],
        agent: &dyn BlockchainAgent,
    ) -> Result<Option<Adjustment>, PaymentAdjusterError>;

    fn adjust_payments(
        &mut self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutboundPaymentsInstructions, PaymentAdjusterError>;

    as_any_in_trait!();
}

pub struct PaymentAdjusterReal {
    analyzer: PreparatoryAnalyzer,
    disqualification_arbiter: DisqualificationArbiter,
    inner: Box<dyn PaymentAdjusterInner>,
    calculators: Vec<Box<dyn CriterionCalculator>>,
    logger: Logger,
}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn search_for_indispensable_adjustment(
        &self,
        qualified_payables: &[QualifiedPayableAccount],
        agent: &dyn BlockchainAgent,
    ) -> Result<Option<Adjustment>, PaymentAdjusterError> {
        let number_of_counts = qualified_payables.len();

        match self
            .analyzer
            .determine_transaction_count_limit_by_transaction_fee(
                agent,
                number_of_counts,
                &self.logger,
            ) {
            Ok(None) => (),
            Ok(Some(affordable_transaction_count)) => {
                return Ok(Some(Adjustment::TransactionFeeInPriority {
                    affordable_transaction_count,
                }))
            }
            Err(e) => return Err(e),
        };

        let service_fee_balance_minor = agent.service_fee_balance_minor();
        match self.analyzer.check_need_of_adjustment_by_service_fee(
            &self.disqualification_arbiter,
            Either::Left(qualified_payables),
            service_fee_balance_minor,
            &self.logger,
        ) {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(Adjustment::ByServiceFee)),
            Err(e) => Err(e),
        }
    }

    fn adjust_payments(
        &mut self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutboundPaymentsInstructions, PaymentAdjusterError> {
        let qualified_payables = setup.qualified_payables;
        let response_skeleton_opt = setup.response_skeleton_opt;
        let agent = setup.agent;
        let initial_service_fee_balance_minor = agent.service_fee_balance_minor();
        let required_adjustment = setup.adjustment;

        self.initialize_inner(initial_service_fee_balance_minor, required_adjustment, now);

        let sketched_debug_info_opt = self.sketch_debug_info_opt(&qualified_payables);

        let affordable_accounts = self.run_adjustment(qualified_payables)?;

        self.complete_debug_info_if_enabled(sketched_debug_info_opt, &affordable_accounts);

        Ok(OutboundPaymentsInstructions::new(
            Either::Right(affordable_accounts),
            agent,
            response_skeleton_opt,
        ))
    }

    as_any_in_trait_impl!();
}

impl Default for PaymentAdjusterReal {
    fn default() -> Self {
        Self::new()
    }
}

impl PaymentAdjusterReal {
    pub fn new() -> Self {
        Self {
            analyzer: PreparatoryAnalyzer::new(),
            disqualification_arbiter: DisqualificationArbiter::default(),
            inner: Box::new(PaymentAdjusterInnerNull {}),
            calculators: vec![Box::new(BalanceAndAgeCriterionCalculator::default())],
            logger: Logger::new("PaymentAdjuster"),
        }
    }

    fn initialize_inner(
        &mut self,
        cw_service_fee_balance: u128,
        required_adjustment: Adjustment,
        now: SystemTime,
    ) {
        let transaction_fee_limitation_opt = match required_adjustment {
            Adjustment::TransactionFeeInPriority {
                affordable_transaction_count,
            } => Some(affordable_transaction_count),
            Adjustment::ByServiceFee => None,
        };

        let inner = PaymentAdjusterInnerReal::new(
            now,
            transaction_fee_limitation_opt,
            cw_service_fee_balance,
        );

        self.inner = Box::new(inner);
    }

    fn run_adjustment(
        &mut self,
        qualified_accounts: Vec<QualifiedPayableAccount>,
    ) -> Result<Vec<PayableAccount>, PaymentAdjusterError> {
        let processed_accounts = self.calculate_criteria_and_propose_adjustments_recursively(
            qualified_accounts,
            TransactionAndServiceFeeAdjustmentRunner {},
        )?;

        if zero_affordable_accounts_found(&processed_accounts) {
            return Err(PaymentAdjusterError::AllAccountsEliminated);
        }

        match processed_accounts {
            Either::Left(non_exhausted_accounts) => {
                let original_cw_service_fee_balance_minor =
                    self.inner.original_cw_service_fee_balance_minor();
                let exhaustive_affordable_accounts = exhaust_cw_till_the_last_drop(
                    non_exhausted_accounts,
                    original_cw_service_fee_balance_minor,
                );
                Ok(exhaustive_affordable_accounts)
            }
            Either::Right(finalized_accounts) => Ok(finalized_accounts),
        }
    }
    fn calculate_criteria_and_propose_adjustments_recursively<AR, RT>(
        &mut self,
        unresolved_qualified_accounts: Vec<QualifiedPayableAccount>,
        adjustment_runner: AR,
    ) -> RT
    where
        AR: AdjustmentRunner<ReturnType = RT>,
    {
        diagnostics!(
            "\nUNRESOLVED QUALIFIED ACCOUNTS IN CURRENT ITERATION:",
            &unresolved_qualified_accounts
        );

        //TODO remove me
        // if unresolved_qualified_accounts.len() == 1 {
        //     let last_one = unresolved_qualified_accounts
        //         .into_iter()
        //         .next()
        //         .expect("previous if stmt must be wrong");
        //     return adjustment_runner.adjust_last_one(self, last_one);
        // }

        let weights_and_accounts_sorted =
            self.calculate_weights_for_accounts(unresolved_qualified_accounts);

        adjustment_runner.adjust_accounts(self, weights_and_accounts_sorted)
    }

    fn begin_with_adjustment_by_transaction_fee(
        &mut self,
        weighted_accounts_in_descending_order: Vec<WeightedPayable>,
        already_known_affordable_transaction_count: u16,
    ) -> Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    > {
        let weighted_accounts_affordable_by_transaction_fee = dump_unaffordable_accounts_by_txn_fee(
            weighted_accounts_in_descending_order,
            already_known_affordable_transaction_count,
        );

        let cw_service_fee_balance = self.inner.original_cw_service_fee_balance_minor();

        let is_service_fee_adjustment_needed =
            match self.analyzer.check_need_of_adjustment_by_service_fee(
                &self.disqualification_arbiter,
                Either::Right(&weighted_accounts_affordable_by_transaction_fee),
                cw_service_fee_balance,
                &self.logger,
            ) {
                Ok(answer) => answer,
                Err(e) => {
                    log_transaction_fee_adjustment_ok_but_by_service_fee_undoable(&self.logger);
                    return Err(e);
                }
            };

        match is_service_fee_adjustment_needed {
            true => {
                diagnostics!("STILL NECESSARY TO CONTINUE BY ADJUSTMENT IN BALANCES");

                let adjustment_result_before_verification = self
                    .propose_possible_adjustment_recursively(
                        weighted_accounts_affordable_by_transaction_fee,
                    );
                Ok(Either::Left(adjustment_result_before_verification))
            }
            false => {
                let accounts_not_needing_adjustment =
                    drop_no_longer_needed_weights_away_from_accounts(
                        weighted_accounts_affordable_by_transaction_fee,
                    );
                Ok(Either::Right(accounts_not_needing_adjustment))
            }
        }
    }

    fn propose_possible_adjustment_recursively(
        &mut self,
        weighed_accounts: Vec<WeightedPayable>,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        let current_iteration_result = self.perform_adjustment_by_service_fee(weighed_accounts);

        let recursion_results = self.resolve_current_iteration_result(current_iteration_result);

        let merged = recursion_results.merge_results_from_recursion();

        diagnostics!(
            "\nFINAL SET OF ADJUSTED ACCOUNTS IN CURRENT ITERATION:",
            &merged
        );

        merged
    }

    fn resolve_current_iteration_result(
        &mut self,
        adjustment_iteration_result: AdjustmentIterationResult,
    ) -> RecursionResults {
        match adjustment_iteration_result {
            AdjustmentIterationResult::AllAccountsProcessed(decided_accounts) => {
                RecursionResults::new(decided_accounts, vec![])
            }
            AdjustmentIterationResult::SpecialTreatmentRequired {
                case: special_case,
                remaining_undecided_accounts,
            } => {
                let here_decided_accounts = match special_case {
                    TreatInsignificantAccount => {
                        if remaining_undecided_accounts.is_empty() {
                            todo!("you should allow this... -> All accounts eliminated");

                            // a) only one account can be eliminated in a single iteration,
                            // b) if there is one last undecided account, it goes on through a shortcut, not reaching
                            // out down here
                            unreachable!("Not possible by original design")
                        }

                        vec![]
                    }
                    TreatOutweighedAccounts(outweighed) => {
                        if remaining_undecided_accounts.is_empty() {
                            todo!("this should be made impossible, in turn... by a short circuit within the adjustment runner");

                            debug!(self.logger, "Every account outweighed (Probably excessive funds after preceding \
                            disqualification). Returning from recursion");

                            return RecursionResults::new(outweighed, vec![]);
                        }

                        self.adjust_remaining_unallocated_cw_balance_down(&outweighed);
                        outweighed
                    }
                };

                let down_stream_decided_accounts = self
                    .calculate_criteria_and_propose_adjustments_recursively(
                        remaining_undecided_accounts,
                        ServiceFeeOnlyAdjustmentRunner {},
                    );

                RecursionResults::new(here_decided_accounts, down_stream_decided_accounts)
            }
        }
    }

    fn calculate_weights_for_accounts(
        &self,
        accounts: Vec<QualifiedPayableAccount>,
    ) -> Vec<WeightedPayable> {
        self.apply_criteria(self.calculators.as_slice(), accounts)
    }

    fn apply_criteria(
        &self,
        criteria_calculators: &[Box<dyn CriterionCalculator>],
        qualified_accounts: Vec<QualifiedPayableAccount>,
    ) -> Vec<WeightedPayable> {
        let weighted_accounts = qualified_accounts.into_iter().map(|payable| {
            let weight =
                criteria_calculators
                    .iter()
                    .fold(0_u128, |weight, criterion_calculator| {
                        let new_criterion =
                            criterion_calculator.calculate(&payable, self.inner.as_ref());

                        let summed_up = weight + new_criterion;

                        calculated_criterion_and_weight_diagnostics(
                            &payable.qualified_as.wallet,
                            criterion_calculator.as_ref(),
                            new_criterion,
                            summed_up,
                        );

                        summed_up
                    });

            WeightedPayable::new(payable, weight)
        });

        sort_in_descendant_order_by_weights(weighted_accounts)
    }

    fn perform_adjustment_by_service_fee(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
    ) -> AdjustmentIterationResult {
        let non_finalized_adjusted_accounts =
            self.compute_unconfirmed_adjustments(weighted_accounts);

        let still_unchecked_for_disqualified =
            match self.handle_possibly_outweighed_accounts(non_finalized_adjusted_accounts) {
                Either::Left(first_check_passing_accounts) => first_check_passing_accounts,
                Either::Right(with_some_outweighed) => return with_some_outweighed,
            };

        let verified_accounts = match self
            .consider_account_disqualification(still_unchecked_for_disqualified, &self.logger)
        {
            Either::Left(verified_accounts) => verified_accounts,
            Either::Right(with_some_disqualified) => return with_some_disqualified,
        };

        AdjustmentIterationResult::AllAccountsProcessed(verified_accounts)
    }

    fn compute_unconfirmed_adjustments(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
    ) -> Vec<UnconfirmedAdjustment> {
        let weights_total = weights_total(&weighted_accounts);
        let largest_weight = find_largest_weight(&weighted_accounts);
        let cw_service_fee_balance = self.inner.unallocated_cw_service_fee_balance_minor();

        let multiplication_coefficient = compute_mul_coefficient_preventing_fractional_numbers(
            cw_service_fee_balance,
            largest_weight,
        );

        let proportional_cw_balance_fragment = Self::compute_proportional_cw_fragment(
            cw_service_fee_balance,
            weights_total,
            multiplication_coefficient,
        );

        let compute_proposed_adjusted_balance =
            |weight: u128| weight * proportional_cw_balance_fragment / multiplication_coefficient;

        weighted_accounts
            .into_iter()
            .map(|weighted_account| {
                let proposed_adjusted_balance =
                    compute_proposed_adjusted_balance(weighted_account.weight);

                proposed_adjusted_balance_diagnostics(
                    &weighted_account.qualified_account,
                    proposed_adjusted_balance,
                );

                UnconfirmedAdjustment::new(weighted_account, proposed_adjusted_balance)
            })
            .collect()
    }

    fn compute_proportional_cw_fragment(
        cw_service_fee_balance: u128,
        weights_total: u128,
        multiplication_coefficient: u128,
    ) -> u128 {
        cw_service_fee_balance
            // Considered safe due to the process of getting this coefficient
            .checked_mul(multiplication_coefficient)
            .unwrap_or_else(|| {
                panic!(
                    "mul overflow from {} * {}",
                    weights_total, multiplication_coefficient
                )
            })
            .checked_div(weights_total)
            .expect("div overflow")
    }

    fn consider_account_disqualification(
        &self,
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
        logger: &Logger,
    ) -> Either<Vec<AdjustedAccountBeforeFinalization>, AdjustmentIterationResult> {
        if let Some(disqualified_account_wallet) = self
            .disqualification_arbiter
            .try_finding_an_account_to_disqualify_in_this_iteration(
                &unconfirmed_adjustments,
                logger,
            )
        {
            let remaining = unconfirmed_adjustments.into_iter().filter(|account_info| {
                account_info
                    .non_finalized_account
                    .qualified_payable
                    .qualified_as
                    .wallet
                    != disqualified_account_wallet
            });

            let remaining_reverted = remaining
                .map(|account_info| {
                    //TODO maybe implement from like before
                    account_info.non_finalized_account.qualified_payable
                    // PayableAccount::from(NonFinalizedAdjustmentWithResolution::new(
                    //     account_info.non_finalized_account,
                    //     AdjustmentResolution::Revert,
                    // ))
                })
                .collect();

            Either::Right(AdjustmentIterationResult::SpecialTreatmentRequired {
                case: TreatInsignificantAccount,
                remaining_undecided_accounts: remaining_reverted,
            })
        } else {
            Either::Left(convert_collection(unconfirmed_adjustments))
        }
    }

    // The term "outweighed account" comes from a phenomenon with account weight increasing
    // significantly based on a different parameter than the debt size. Untreated, we would which
    // grant the account (much) more money than what the accountancy has recorded for it.
    fn handle_possibly_outweighed_accounts(
        &self,
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> Either<Vec<UnconfirmedAdjustment>, AdjustmentIterationResult> {
        let init = (vec![], vec![]);

        let (outweighed, properly_adjusted_accounts) = unconfirmed_adjustments
            .into_iter()
            .fold(init, adjust_account_balance_if_outweighed);

        if outweighed.is_empty() {
            Either::Left(properly_adjusted_accounts)
        } else {
            let remaining_undecided_accounts: Vec<QualifiedPayableAccount> =
                convert_collection(properly_adjusted_accounts);
            let pre_processed_outweighed: Vec<AdjustedAccountBeforeFinalization> =
                convert_collection(outweighed);
            Either::Right(AdjustmentIterationResult::SpecialTreatmentRequired {
                case: TreatOutweighedAccounts(pre_processed_outweighed),
                remaining_undecided_accounts,
            })
        }
    }

    fn adjust_remaining_unallocated_cw_balance_down(
        &mut self,
        processed_outweighed: &[AdjustedAccountBeforeFinalization],
    ) {
        let subtrahend_total: u128 = sum_as(processed_outweighed, |account| {
            account.proposed_adjusted_balance_minor
        });
        self.inner
            .subtract_from_unallocated_cw_service_fee_balance_minor(subtrahend_total);

        diagnostics!(
            "LOWERED CW BALANCE",
            "Unallocated balance lowered by {} to {}",
            subtrahend_total,
            self.inner.unallocated_cw_service_fee_balance_minor()
        )
    }

    fn sketch_debug_info_opt(
        &self,
        qualified_payables: &[QualifiedPayableAccount],
    ) -> Option<HashMap<Wallet, u128>> {
        self.logger.debug_enabled().then(|| {
            qualified_payables
                .iter()
                .map(|payable| {
                    (
                        payable.qualified_as.wallet.clone(),
                        payable.qualified_as.balance_wei,
                    )
                })
                .collect::<HashMap<Wallet, u128>>()
        })
    }

    fn complete_debug_info_if_enabled(
        &self,
        sketched_debug_info_opt: Option<HashMap<Wallet, u128>>,
        affordable_accounts: &[PayableAccount],
    ) {
        self.logger.debug(|| {
            let sketched_debug_info =
                sketched_debug_info_opt.expect("debug is enabled, so info should exist");
            accounts_before_and_after_debug(sketched_debug_info, affordable_accounts)
        })
    }

    fn adjust_last_account_opt(
        &self,
        last_payable: QualifiedPayableAccount,
    ) -> Option<AdjustedAccountBeforeFinalization> {
        let cw_balance = self.inner.unallocated_cw_service_fee_balance_minor();
        let proposed_adjusted_balance = if last_payable
            .qualified_as
            .balance_wei
            .checked_sub(cw_balance)
            == None
        {
            last_payable.qualified_as.balance_wei
        } else {
            diagnostics!(
                "LAST REMAINING ACCOUNT",
                "Balance adjusted to {} by exhausting the cw balance fully",
                cw_balance
            );

            cw_balance
        };
        // TODO the Disqualification check really makes sense only if we assigned less than the full balance!!
        let mut proposed_adjustment_vec = vec![UnconfirmedAdjustment::new(
            WeightedPayable::new(last_payable, u128::MAX), // The weight doesn't matter really and is made up
            proposed_adjusted_balance,
        )];

        match self
            .disqualification_arbiter
            .try_finding_an_account_to_disqualify_in_this_iteration(
                &proposed_adjustment_vec,
                &self.logger,
            ) {
            Some(_) => None,
            None => Some(proposed_adjustment_vec.remove(0).non_finalized_account),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adjustment {
    ByServiceFee,
    TransactionFeeInPriority { affordable_transaction_count: u16 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum PaymentAdjusterError {
    NotEnoughTransactionFeeBalanceForSingleTx {
        number_of_accounts: usize,
        per_transaction_requirement_minor: u128,
        cw_transaction_fee_balance_minor: U256,
    },
    NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
        number_of_accounts: usize,
        total_amount_demanded_minor: u128,
        cw_service_fee_balance_minor: u128,
    },
    AllAccountsEliminated,
}

impl Display for PaymentAdjusterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx {
                number_of_accounts,
                per_transaction_requirement_minor,
                cw_transaction_fee_balance_minor,
            } => write!(
                f,
                "Found a smaller transaction fee balance than it does for a single payment. \
                Number of canceled payments: {}. Transaction fee by single account: {} wei. \
                Consuming wallet balance: {} wei",
                number_of_accounts,
                per_transaction_requirement_minor.separate_with_commas(),
                cw_transaction_fee_balance_minor.separate_with_commas()
            ),
            PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                number_of_accounts,
                total_amount_demanded_minor,
                cw_service_fee_balance_minor,
            } => write!(
                f,
                "Found a smaller service fee balance than it does for a single payment. \
                Number of canceled payments: {}. Total amount demanded: {} wei. Consuming \
                wallet balance: {} wei",
                number_of_accounts.separate_with_commas(),
                total_amount_demanded_minor.separate_with_commas(),
                cw_service_fee_balance_minor.separate_with_commas()
            ),
            PaymentAdjusterError::AllAccountsEliminated => write!(
                f,
                "The adjustment algorithm had to eliminate each payable from the recently urged payment \
                due to lack of resources."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::adjustment_runners::TransactionAndServiceFeeAdjustmentRunner;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{AdjustedAccountBeforeFinalization, AdjustmentIterationResult, RequiredSpecialTreatment};
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::RequiredSpecialTreatment::TreatInsignificantAccount;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{weights_total};
    use crate::accountant::payment_adjuster::test_utils::{DisqualificationGaugeMock, make_extreme_payables, make_initialized_subject, MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR, PRESERVED_TEST_PAYMENT_THRESHOLDS};
    use crate::accountant::payment_adjuster::{Adjustment, PaymentAdjuster, PaymentAdjusterError, PaymentAdjusterReal};
    use crate::accountant::test_utils::{make_guaranteed_qualified_payables, make_non_guaranteed_qualified_payable, make_payable_account};
    use crate::accountant::{CreditorThresholds, gwei_to_wei, QualifiedPayableAccount, ResponseSkeleton};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::{Duration, SystemTime};
    use std::{usize, vec};
    use std::sync::{Arc, Mutex};
    use thousands::Separable;
    use web3::types::U256;
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;

    #[test]
    #[should_panic(expected = "Broken code: Called the null implementation of \
        the unallocated_cw_service_fee_balance_minor() method in PaymentAdjusterInner")]
    fn payment_adjuster_new_is_created_with_inner_null() {
        let result = PaymentAdjusterReal::new();

        let _ = result.inner.unallocated_cw_service_fee_balance_minor();
    }

    #[test]
    fn search_for_indispensable_adjustment_happy_path() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_gives_negative_answer";
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // Service fee balance > payments
        let input_1 = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                account_balances: Either::Right(vec![
                    gwei_to_wei::<u128, u64>(85),
                    gwei_to_wei::<u128, u64>(15) - 1,
                ]),
                cw_balance_minor: gwei_to_wei(100_u64),
            }),
            None,
        );
        // Service fee balance == payments
        let input_2 = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                account_balances: Either::Left(vec![85, 15]),
                cw_balance_minor: gwei_to_wei(100_u64),
            }),
            None,
        );
        // transaction fee balance > payments
        let input_3 = make_input_for_initial_check_tests(
            None,
            Some(TestConfigForTransactionFees {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts: 6,
                estimated_transaction_fee_units_per_transaction: 53_000,
                cw_transaction_fee_balance_major: (100 * 6 * 53_000) + 1,
            }),
        );
        // transaction fee balance == payments
        let input_4 = make_input_for_initial_check_tests(
            None,
            Some(TestConfigForTransactionFees {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts: 6,
                estimated_transaction_fee_units_per_transaction: 53_000,
                cw_transaction_fee_balance_major: 100 * 6 * 53_000,
            }),
        );

        [input_1, input_2, input_3, input_4]
            .into_iter()
            .enumerate()
            .for_each(|(idx, (qualified_payables, agent))| {
                assert_eq!(
                    subject.search_for_indispensable_adjustment(&qualified_payables, &*agent),
                    Ok(None),
                    "failed for tested input number {:?}",
                    idx + 1
                )
            });

        TestLogHandler::new().exists_no_log_containing(&format!("WARN: {test_name}:"));
    }

    #[test]
    fn search_for_indispensable_adjustment_sad_path_for_transaction_fee() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_sad_path_positive_for_transaction_fee";
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let number_of_accounts = 3;
        let service_fee_balances_config_opt = None;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            service_fee_balances_config_opt,
            Some(TestConfigForTransactionFees {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts,
                estimated_transaction_fee_units_per_transaction: 55_000,
                cw_transaction_fee_balance_major: 100 * 3 * 55_000 - 1,
            }),
        );

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(
            result,
            Ok(Some(Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2
            }))
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Transaction fee amount 16,499,999,000,000,000 wei \
        from your wallet will not cover anticipated fees to send 3 transactions. \
        Maximum is 2. The payments count needs to be adjusted."
        ));
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Please be aware that \
        ignoring your debts might result in delinquency bans. In order to consume services without \
        limitations, you will need to put more funds into your consuming wallet."
        ));
    }

    #[test]
    fn search_for_indispensable_adjustment_sad_path_for_service_fee_balance() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_positive_for_service_fee_balance";
        let logger = Logger::new(test_name);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = logger;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                account_balances: Either::Right(vec![
                    gwei_to_wei::<u128, u64>(85),
                    gwei_to_wei::<u128, u64>(15) + 1,
                ]),
                cw_balance_minor: gwei_to_wei(100_u64),
            }),
            None,
        );

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(result, Ok(Some(Adjustment::ByServiceFee)));
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Total of 100,000,000,001 \
        wei in MASQ was ordered while the consuming wallet held only 100,000,000,000 wei of the MASQ \
        token. Adjustment in their count or the amounts is required."));
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Please be aware that \
        ignoring your debts might result in delinquency bans. In order to consume services without \
        limitations, you will need to put more funds into your consuming wallet."
        ));
    }

    #[test]
    fn checking_three_accounts_happy_for_transaction_fee_but_service_fee_balance_is_unbearably_low()
    {
        let test_name = "checking_three_accounts_happy_for_transaction_fee_but_service_fee_balance_is_unbearably_low";
        let cw_service_fee_balance_minor = gwei_to_wei::<u128, _>(120_u64) / 2 - 1; // this would normally kick a serious error
        let service_fee_balances_config_opt = Some(TestConfigForServiceFeeBalances {
            account_balances: Either::Left(vec![120, 300, 500]),
            cw_balance_minor: cw_service_fee_balance_minor,
        });
        let (qualified_payables, agent) =
            make_input_for_initial_check_tests(service_fee_balances_config_opt, None);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 3,
                    total_amount_demanded_minor: 920_000_000_000,
                    cw_service_fee_balance_minor
                }
            )
        );
    }

    #[test]
    fn not_enough_transaction_fee_balance_for_even_a_single_transaction() {
        let subject = PaymentAdjusterReal::new();
        let number_of_accounts = 3;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                account_balances: Either::Left(vec![123]),
                cw_balance_minor: gwei_to_wei::<u128, u64>(444),
            }),
            Some(TestConfigForTransactionFees {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts,
                estimated_transaction_fee_units_per_transaction: 55_000,
                cw_transaction_fee_balance_major: 54_000 * 100,
            }),
        );

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts,
                    per_transaction_requirement_minor: 55_000 * gwei_to_wei::<u128, u64>(100),
                    cw_transaction_fee_balance_minor: U256::from(54_000)
                        * gwei_to_wei::<U256, u64>(100)
                }
            )
        );
    }

    #[test]
    fn payment_adjuster_error_implements_display() {
        vec![
            (
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 5,
                    total_amount_demanded_minor: 6_000_000_000,
                    cw_service_fee_balance_minor: 333_000_000,
                },
                "Found a smaller service fee balance than it does for a single payment. \
                Number of canceled payments: 5. Total amount demanded: 6,000,000,000 wei. \
                Consuming wallet balance: 333,000,000 wei",
            ),
            (
                PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts: 4,
                    per_transaction_requirement_minor: 70_000_000_000_000,
                    cw_transaction_fee_balance_minor: U256::from(90_000),
                },
                "Found a smaller transaction fee balance than it does for a single \
                payment. Number of canceled payments: 4. Transaction fee by single \
                account: 70,000,000,000,000 wei. Consuming wallet balance: 90,000 \
                wei",
            ),
            (
                PaymentAdjusterError::AllAccountsEliminated,
                "The adjustment algorithm had to eliminate each payable from the recently urged \
                payment due to lack of resources.",
            ),
        ]
        .into_iter()
        .for_each(|(error, expected_msg)| assert_eq!(error.to_string(), expected_msg))
    }

    #[test]
    fn apply_criteria_returns_accounts_sorted_by_criteria_in_descending_order() {
        let now = SystemTime::now();
        let subject = make_initialized_subject(now, None, None);
        let account_1 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 333_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 111_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghk"),
            balance_wei: 444_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = make_guaranteed_qualified_payables(
            vec![account_1.clone(), account_2.clone(), account_3.clone()],
            &PRESERVED_TEST_PAYMENT_THRESHOLDS,
            now,
        );

        let criteria_and_accounts = subject.calculate_weights_for_accounts(qualified_payables);

        let mut previous_weight = u128::MAX;
        let accounts_alone = criteria_and_accounts
            .into_iter()
            .map(|weighted_account| {
                assert!(
                    previous_weight > weighted_account.weight,
                    "Previous criteria {} wasn't larger than {} but should've been",
                    previous_weight,
                    weighted_account.weight
                );
                previous_weight = weighted_account.weight;
                weighted_account.qualified_account.qualified_as
            })
            .collect::<Vec<PayableAccount>>();
        assert_eq!(accounts_alone, vec![account_3, account_1, account_2])
    }

    #[test]
    fn minor_but_a_lot_aged_debt_is_prioritized_outweighed_and_stays_as_the_full_original_balance()
    {
        let now = SystemTime::now();
        let cw_service_fee_balance = 1_500_000_000_000_u128 - 25_000_000 - 1000;
        let mut subject = make_initialized_subject(now, Some(cw_service_fee_balance), None);
        let balance_1 = 1_500_000_000_000;
        let balance_2 = 25_000_000;
        let wallet_1 = make_wallet("blah");
        let account_1 = PayableAccount {
            wallet: wallet_1,
            balance_wei: balance_1,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(5_500)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("argh"),
            balance_wei: balance_2,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(20_000)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = make_guaranteed_qualified_payables(
            vec![account_1.clone(), account_2.clone()],
            &PRESERVED_TEST_PAYMENT_THRESHOLDS,
            now,
        );

        let mut result = subject
            .calculate_criteria_and_propose_adjustments_recursively(
                qualified_payables.clone(),
                TransactionAndServiceFeeAdjustmentRunner {},
            )
            .unwrap()
            .left()
            .unwrap();

        // First, let's have an example of why this test is important
        let criteria_and_accounts =
            subject.calculate_weights_for_accounts(qualified_payables.clone());
        let unconfirmed_adjustments =
            subject.compute_unconfirmed_adjustments(criteria_and_accounts);
        let proposed_adjusted_balance_2 = unconfirmed_adjustments[1]
            .non_finalized_account
            .proposed_adjusted_balance_minor;
        // The criteria sum of the second account grew very progressively due to the effect of the greater age;
        // consequences would've been that redistributing the new balances according to the computed criteria would've
        // attributed the second account with a larger amount to pay than it would've had before the test started;
        // to prevent it, we set a rule that no account can ever demand more than 100% of itself
        assert!(
            proposed_adjusted_balance_2 > 10 * balance_2,
            "we expected the proposed balance much bigger than the original which is {} but it was {}",
            balance_2,
            proposed_adjusted_balance_2
        );
        // So the assertion above shows the concern true.
        let first_returned_account = result.remove(0);
        // Outweighed accounts always take the first places
        assert_eq!(
            &first_returned_account.qualified_payable,
            &qualified_payables[1]
        );
        assert_eq!(
            first_returned_account.proposed_adjusted_balance_minor,
            balance_2
        );
        let second_returned_account = result.remove(0);
        assert_eq!(
            &second_returned_account.qualified_payable,
            &qualified_payables[0]
        );
        let upper_limit = 1_500_000_000_000_u128 - 25_000_000 - 25_000_000 - 1000;
        let lower_limit = (upper_limit * 9) / 10;
        assert!(
            lower_limit <= second_returned_account.proposed_adjusted_balance_minor
                && second_returned_account.proposed_adjusted_balance_minor <= upper_limit,
            "we expected the roughly adjusted account to be between {} and {} but was {}",
            lower_limit,
            upper_limit,
            second_returned_account.proposed_adjusted_balance_minor
        );
        assert!(result.is_empty());
    }

    #[test]
    fn outweighed_account_never_demands_more_than_cw_balance_because_disqualified_accounts_go_first(
    ) {
        // NOTE that the same is true for more outweighed accounts that would require more than
        // the whole cw balance together, therefore there is no such a test either.
        // This test answers the question of what is happening when the cw service fee balance cannot
        // cover the outweighed accounts, which is just a hypothesis we can never reach in
        // the reality.
        // If there are outweighed accounts some other accounts must be also around of which some
        // are under the disqualification limit pointing to one that would definitely head to its
        // disqualification.
        // With enough money, the other account might not meet disqualification which means, though,
        // the initial concern is still groundless: there must be enough money at the moment to
        // cover the outweighed account if there is another one which is considered neither as
        // outweighed or disqualified.
        const SECONDS_IN_3_DAYS: u64 = 259_200;
        let test_name =
            "outweighed_account_never_demands_more_than_cw_balance_because_disqualified_accounts_go_first";
        let now = SystemTime::now();
        let consuming_wallet_balance = 1_000_000_000_000_u128 - 1;
        let account_1 = PayableAccount {
            wallet: make_wallet("blah"),
            balance_wei: 1_000_000_000_000,
            last_paid_timestamp: now
                // Greater age like this together with smaller balance usually causes the account to outweigh
                .checked_sub(Duration::from_secs(SECONDS_IN_3_DAYS))
                .unwrap(),
            pending_payable_opt: None,
        };
        let balance_2 = 8_000_000_000_000_000;
        let wallet_2 = make_wallet("booga");
        let account_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: balance_2,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        let accounts = vec![account_1.clone(), account_2];
        let mut qualified_payables =
            make_guaranteed_qualified_payables(accounts, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let subject = make_initialized_subject(
            now,
            Some(consuming_wallet_balance),
            Some(Logger::new(test_name)),
        );
        let weighted_accounts = subject.calculate_weights_for_accounts(qualified_payables.clone());

        let result = subject.perform_adjustment_by_service_fee(weighted_accounts);

        let remaining = match result {
            AdjustmentIterationResult::SpecialTreatmentRequired {
                case: TreatInsignificantAccount,
                remaining_undecided_accounts: remaining,
            } => remaining,
            x => panic!("we expected to see a disqualified account but got: {:?}", x),
        };
        // We eliminated (disqualified) the other account than which was going to qualify as outweighed
        let expected_account = qualified_payables.remove(0);
        assert_eq!(remaining, vec![expected_account]);
    }

    #[test]
    fn adjustment_started_but_all_accounts_were_eliminated_anyway() {
        let test_name = "adjustment_started_but_all_accounts_were_eliminated_anyway";
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 3_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(50_000)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 1_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(150_000)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: 2_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(100_000)).unwrap(),
            pending_payable_opt: None,
        };
        let payables = vec![account_1, account_2, account_3];
        let qualified_payables =
            make_guaranteed_qualified_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let service_fee_balance_in_minor_units = todo!();
        // ((1_000_000_000_000
        // * EXCESSIVE_DEBT_PART_INSIGNIFICANCE_RATIO.multiplier)
        // / EXCESSIVE_DEBT_PART_INSIGNIFICANCE_RATIO.divisor)
        // - 1;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("we expected to get an error but it was ok"),
        };
        assert_eq!(err, PaymentAdjusterError::AllAccountsEliminated)
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: Not possible by original design"
    )]
    fn disqualified_account_with_no_remaining_accounts_is_not_possible() {
        let mut subject = PaymentAdjusterReal::new();
        let iteration_result = AdjustmentIterationResult::SpecialTreatmentRequired {
            case: RequiredSpecialTreatment::TreatInsignificantAccount,
            remaining_undecided_accounts: vec![],
        };

        let _ = subject.resolve_current_iteration_result(iteration_result);
    }

    #[test]
    fn account_disqualification_causes_all_other_accounts_to_seem_outweighed_as_cw_balance_becomes_excessive_for_them(
    ) {
        init_test_logging();
        let test_name = "account_disqualification_causes_all_other_accounts_to_seem_outweighed_as_cw_balance_becomes_excessive_for_them";
        let now = SystemTime::now();
        let balance_1 = 80_000_000_000_000_000_000;
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: balance_1,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(24_000)).unwrap(),
            pending_payable_opt: None,
        };
        let balance_2 = 60_000_000_000_000_000_000;
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: balance_2,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(200_000)).unwrap(),
            pending_payable_opt: None,
        };
        let balance_3 = 40_000_000_000_000_000_000;
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: balance_3,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(160_000)).unwrap(),
            pending_payable_opt: None,
        };
        let payables = vec![account_1, account_2.clone(), account_3.clone()];
        let qualified_payables =
            make_guaranteed_qualified_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let accounts_sum: u128 = balance_1 + balance_2 + balance_3;
        let service_fee_balance_in_minor_units = accounts_sum - ((balance_1 * 90) / 100);
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_affordable_accounts = { vec![account_2, account_3] };
        assert_eq!(result.affordable_accounts, expected_affordable_accounts);
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Every account outweighed (Probably \
        excessive funds after preceding disqualification). Returning from recursion"
        ));
    }

    fn prepare_subject(
        cw_balance: u128,
        now: SystemTime,
        disqualification_gauge: DisqualificationGaugeMock,
    ) -> PaymentAdjusterReal {
        let adjustment = Adjustment::ByServiceFee;
        let mut payment_adjuster = PaymentAdjusterReal::new();
        todo!("is this necessary?");
        //payment_adjuster.initialize_inner(cw_balance.into(), adjustment, now);
        payment_adjuster.disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        payment_adjuster
    }

    #[test]
    fn adjust_last_account_opt_for_balance_smaller_than_cw_but_no_need_to_disqualify() {
        let determine_limit_params_arc = Arc::new(Mutex::new(vec![]));
        let now = SystemTime::now();
        let account_balance = 4_500_600;
        let cw_balance = 4_500_601;
        let payable = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: account_balance,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(2_500)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payable =
            QualifiedPayableAccount::new(payable, 111222333, CreditorThresholds::new(1000000));
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_params(&determine_limit_params_arc)
            .determine_limit_result(4_500_600);
        let payment_adjuster = prepare_subject(cw_balance, now, disqualification_gauge);

        let result = payment_adjuster.adjust_last_account_opt(qualified_payable.clone());

        assert_eq!(
            result,
            Some(AdjustedAccountBeforeFinalization {
                qualified_payable: qualified_payable.clone(),
                proposed_adjusted_balance_minor: cw_balance,
            })
        );
        let determine_limit_params = determine_limit_params_arc.lock().unwrap();
        assert_eq!(
            *determine_limit_params,
            vec![(
                qualified_payable.qualified_as.balance_wei,
                qualified_payable.payment_threshold_intercept_minor,
                qualified_payable
                    .creditor_thresholds
                    .permanent_debt_allowed_wei
            )]
        )
    }

    fn test_adjust_last_account_opt_when_account_disqualified(
        cw_balance: u128,
        disqualification_gauge: DisqualificationGaugeMock,
    ) {
        let now = SystemTime::now();
        let garbage_balance_wei = 123456789;
        let garbage_last_paid_timestamp = SystemTime::now();
        let garbage_payment_threshold_intercept_minor = 33333333;
        let garbage_permanent_debt_allowed_wei = 11111111;
        let payable = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: garbage_balance_wei,
            last_paid_timestamp: garbage_last_paid_timestamp,
            pending_payable_opt: None,
        };
        let qualified_payable = QualifiedPayableAccount {
            qualified_as: payable,
            payment_threshold_intercept_minor: garbage_payment_threshold_intercept_minor,
            creditor_thresholds: CreditorThresholds {
                permanent_debt_allowed_wei: garbage_permanent_debt_allowed_wei,
            },
        };
        let payment_adjuster = prepare_subject(cw_balance, now, disqualification_gauge);

        let result = payment_adjuster.adjust_last_account_opt(qualified_payable);

        assert_eq!(result, None)
    }

    #[test]
    fn account_facing_much_smaller_cw_balance_hits_disqualification_when_adjustment_evens_the_edge()
    {
        let cw_balance = 1_000_111;
        let disqualification_gauge =
            DisqualificationGaugeMock::default().determine_limit_result(1_000_111);

        test_adjust_last_account_opt_when_account_disqualified(cw_balance, disqualification_gauge)
    }

    #[test]
    fn account_facing_much_smaller_cw_balance_hits_disqualification_when_adjustment_slightly_under()
    {
        let cw_balance = 1_000_111;
        let disqualification_gauge =
            DisqualificationGaugeMock::default().determine_limit_result(1_000_110);

        test_adjust_last_account_opt_when_account_disqualified(cw_balance, disqualification_gauge)
    }

    #[test]
    fn overloading_with_exaggerated_debt_conditions_to_see_if_we_can_pass_through_safely() {
        init_test_logging();
        let test_name =
            "overloading_with_exaggerated_debt_conditions_to_see_if_we_can_pass_through_safely";
        let now = SystemTime::now();
        // Each of the 3 accounts refers to a debt sized as the entire masq token supply and being 10 years old which
        // generates enormously large numbers in the criteria
        let extreme_payables = {
            let debt_age_in_months = vec![120, 120, 120];
            make_extreme_payables(
                Either::Left((
                    debt_age_in_months,
                    *MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR,
                )),
                now,
            )
        };
        let qualified_payables = make_guaranteed_qualified_payables(
            extreme_payables,
            &PRESERVED_TEST_PAYMENT_THRESHOLDS,
            now,
        );
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // In turn, tiny cw balance
        let cw_service_fee_balance = 1_000;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .service_fee_balance_minor_result(cw_service_fee_balance);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        // The error isn't important. Received just because we set an almost empty wallet
        let err = match result {
            Ok(_) => panic!("we expected err but got ok"),
            Err(e) => e,
        };
        assert_eq!(err, PaymentAdjusterError::AllAccountsEliminated);
        let expected_log = |wallet: &str, proposed_adjusted_balance_in_this_iteration: u64| {
            format!(
                "INFO: {test_name}: Shortage of MASQ in your consuming wallet impacts on payable \
                {wallet}, ruled out from this round of payments. The proposed adjustment {} wei \
                was less than half of the recorded debt, {} wei",
                proposed_adjusted_balance_in_this_iteration.separate_with_commas(),
                (*MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR).separate_with_commas()
            )
        };
        let log_handler = TestLogHandler::new();
        // Notice that the proposals grow as one disqualified account drops out in each iteration
        log_handler.exists_log_containing(&expected_log(
            "0x000000000000000000000000000000626c616830",
            333,
        ));
        log_handler.exists_log_containing(&expected_log(
            "0x000000000000000000000000000000626c616831",
            499,
        ));
        log_handler.exists_log_containing(&expected_log(
            "0x000000000000000000000000000000626c616832",
            1000,
        ));
    }

    #[test]
    fn qualified_accounts_count_before_equals_the_payments_count_after() {
        // Meaning adjustment by service fee but no account elimination
        init_test_logging();
        let test_name = "qualified_accounts_count_before_equals_the_payments_count_after";
        let now = SystemTime::now();
        let balance_1 = 4_444_444_444_444_444_444;
        let qualified_account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: balance_1,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(101_000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let balance_2 = 6_000_000_000_000_000_000;
        let qualified_account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: balance_2,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(150_000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let balance_3 = 6_666_666_666_000_000_000;
        let qualified_account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("ghi"),
                balance_wei: balance_3,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(100_000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![
            qualified_account_1.clone(),
            qualified_account_2.clone(),
            qualified_account_3.clone(),
        ];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let accounts_sum = balance_1 + balance_2 + balance_3;
        let service_fee_balance_in_minor_units = accounts_sum - 3_000_000_000_000_000_000;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_adjusted_balance_1 = 3_878_112_909_226_659_278;
        let expected_adjusted_balance_2 = 5_941_743_288_347_289_696;
        let expected_adjusted_balance_3 = 4_291_254_912_870_495_470;
        let expected_criteria_computation_output = {
            let account_1_adjusted = PayableAccount {
                balance_wei: expected_adjusted_balance_1,
                ..qualified_account_1.qualified_as
            };
            let account_2_adjusted = PayableAccount {
                balance_wei: expected_adjusted_balance_2,
                ..qualified_account_2.qualified_as
            };
            let account_3_adjusted = PayableAccount {
                balance_wei: expected_adjusted_balance_3,
                ..qualified_account_3.qualified_as
            };
            vec![account_2_adjusted, account_3_adjusted, account_1_adjusted]
        };
        assert_eq!(
            result.affordable_accounts,
            expected_criteria_computation_output
        );
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Payable Account                            Balance Wei
|
|                                           Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000646566 {}
|                                           {}
|0x0000000000000000000000000000000000676869 {}
|                                           {}
|0x0000000000000000000000000000000000616263 {}
|                                           {}",
            balance_2.separate_with_commas(),
            expected_adjusted_balance_2.separate_with_commas(),
            balance_3.separate_with_commas(),
            expected_adjusted_balance_3.separate_with_commas(),
            balance_1.separate_with_commas(),
            expected_adjusted_balance_1.separate_with_commas()
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn only_transaction_fee_causes_limitations_and_the_service_fee_balance_suffices() {
        init_test_logging();
        let test_name =
            "only_transaction_fee_causes_limitations_and_the_service_fee_balance_suffices";
        let now = SystemTime::now();
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: 111_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: 333_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("ghi"),
                balance_wei: 222_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(10_u128.pow(22));
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // The account 3 takes the first place for its age
        // (it weights more if the balance is so small)
        assert_eq!(
            result.affordable_accounts,
            vec![account_3.qualified_as, account_2.qualified_as]
        );
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Payable Account                            Balance Wei
|
|                                           Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000646566 333,000,000,000,000
|                                           333,000,000,000,000
|0x0000000000000000000000000000000000676869 222,000,000,000,000
|                                           222,000,000,000,000
|
|Ruled Out Accounts                         Original
|
|0x0000000000000000000000000000000000616263 111,000,000,000,000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn both_balances_insufficient_but_adjustment_by_service_fee_will_not_affect_the_payments_count()
    {
        // The course of events:
        // 1) adjustment by transaction fee (always means accounts elimination),
        // 2) adjustment by service fee (can but not have to cause an account drop-off)
        init_test_logging();
        let now = SystemTime::now();
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: 111_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: 333_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("ghk"),
                balance_wei: 222_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        let service_fee_balance_in_minor_units = 111_000_000_000_000_u128 + 333_000_000_000_000;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 123,
            context_id: 321,
        }); //just hardening, not so important
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // Account_1, the least important one, was eliminated for not big enough transaction fee balance
        let expected_accounts = {
            let account_2_adjusted = PayableAccount {
                balance_wei: 222_000_000_000_000,
                ..account_2.qualified_as
            };
            vec![account_3.qualified_as, account_2_adjusted]
        };
        assert_eq!(result.affordable_accounts, expected_accounts);
        assert_eq!(result.response_skeleton_opt, response_skeleton_opt);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
    }

    #[test]
    fn only_service_fee_balance_limits_the_payments_count() {
        init_test_logging();
        let test_name = "only_service_fee_balance_limits_the_payments_count";
        let now = SystemTime::now();
        let wallet_1 = make_wallet("def");
        // Account to be adjusted to keep as much as how much is left in the cw balance
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: wallet_1.clone(),
                balance_wei: 333_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(12000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        // Account to be outweighed and fully preserved
        let wallet_2 = make_wallet("abc");
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: wallet_2.clone(),
                balance_wei: 111_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(8000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        // Account to be disqualified
        let wallet_3 = make_wallet("ghk");
        let balance_3 = 600_000_000_000;
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: wallet_3.clone(),
                balance_wei: balance_3,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(6000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor_units = 333_000_000_000 + 50_000_000_000;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 111,
            context_id: 234,
        });
        // Another place where I pick a populated response skeleton for hardening
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_accounts = {
            let account_1_adjusted = PayableAccount {
                balance_wei: 272_000_000_000,
                ..account_1.qualified_as
            };
            vec![account_1_adjusted, account_2.qualified_as]
        };
        assert_eq!(result.affordable_accounts, expected_accounts);
        assert_eq!(result.response_skeleton_opt, response_skeleton_opt);
        assert_eq!(
            result.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 111,
                context_id: 234
            })
        );
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Shortage of MASQ \
        in your consuming wallet impacts on payable 0x000000000000000000000000000000000067686b, \
        ruled out from this round of payments. The proposed adjustment 79,556,958,958 wei was less \
        than half of the recorded debt, 600,000,000,000 wei"
        ));
    }

    struct CompetitiveAccountsTestInputs<'a> {
        common: WalletsSetup<'a>,
        account_1_balance_positive_correction_minor: u128,
        account_2_balance_positive_correction_minor: u128,
        account_1_age_positive_correction_secs: u64,
        account_2_age_positive_correction_secs: u64,
    }

    #[derive(Clone, Copy)]
    struct WalletsSetup<'a> {
        wallet_1: &'a Wallet,
        wallet_2: &'a Wallet,
    }

    fn test_two_competitive_accounts_with_one_disqualified<'a>(
        test_scenario_name: &str,
        inputs: CompetitiveAccountsTestInputs,
        expected_wallet_of_the_winning_account: &'a Wallet,
    ) {
        let now = SystemTime::now();
        let cw_service_fee_balance_in_minor = 100_000_000_000_000 - 1;
        let standard_balance_per_account = 100_000_000_000_000;
        let standard_age_per_account = 12000;
        let account_1 = PayableAccount {
            wallet: inputs.common.wallet_1.clone(),
            balance_wei: standard_balance_per_account
                + inputs.account_1_balance_positive_correction_minor,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    standard_age_per_account + inputs.account_1_age_positive_correction_secs,
                ))
                .unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: inputs.common.wallet_2.clone(),
            balance_wei: standard_balance_per_account
                + inputs.account_2_balance_positive_correction_minor,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    standard_age_per_account + inputs.account_2_age_positive_correction_secs,
                ))
                .unwrap(),
            pending_payable_opt: None,
        };
        let payables = vec![account_1, account_2];
        let qualified_payables =
            make_guaranteed_qualified_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let mut subject = PaymentAdjusterReal::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .service_fee_balance_minor_result(cw_service_fee_balance_in_minor);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt: None,
        };

        let mut result = subject
            .adjust_payments(adjustment_setup, now)
            .unwrap()
            .affordable_accounts;

        let winning_account = result.remove(0);
        assert_eq!(
            &winning_account.wallet, expected_wallet_of_the_winning_account,
            "{}: expected wallet {} but got {}",
            test_scenario_name, winning_account.wallet, expected_wallet_of_the_winning_account
        );
        assert_eq!(
            winning_account.balance_wei, cw_service_fee_balance_in_minor,
            "{}: expected full cw balance {}, but the account had {}",
            test_scenario_name, winning_account.balance_wei, cw_service_fee_balance_in_minor
        );
        assert!(
            result.is_empty(),
            "{}: is not empty, {:?} remains",
            test_scenario_name,
            result
        )
    }

    #[test]
    fn not_enough_service_fee_for_both_accounts_at_least_by_their_half_so_only_one_wins() {
        fn merge_test_name_with_test_scenario(description: &str) -> String {
            format!(
                "not_enough_service_fee_for_both_accounts_at_least_by_their_half_so_only_one_wins{}",
                description
            )
        }

        let w1 = make_wallet("abcd");
        let w2 = make_wallet("cdef");
        let common_input = WalletsSetup {
            wallet_1: &w1,
            wallet_2: &w2,
        };
        // scenario A
        let first_scenario_name = merge_test_name_with_test_scenario("when equally significant");
        let expected_wallet_of_the_winning_account = &w2;

        test_two_competitive_accounts_with_one_disqualified(
            &first_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                account_1_balance_positive_correction_minor: 0,
                account_2_balance_positive_correction_minor: 0,
                account_1_age_positive_correction_secs: 0,
                account_2_age_positive_correction_secs: 0,
            },
            expected_wallet_of_the_winning_account,
        );
        //--------------------------------------------------------------------
        // scenario B
        let second_scenario_name =
            merge_test_name_with_test_scenario("first more significant by balance");
        let expected_wallet_of_the_winning_account = &w1;

        test_two_competitive_accounts_with_one_disqualified(
            &second_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                account_1_balance_positive_correction_minor: 1,
                account_2_balance_positive_correction_minor: 0,
                account_1_age_positive_correction_secs: 0,
                account_2_age_positive_correction_secs: 0,
            },
            expected_wallet_of_the_winning_account,
        );
        //--------------------------------------------------------------------
        // scenario C
        let third_scenario_name =
            merge_test_name_with_test_scenario("second more significant by age");
        let expected_wallet_of_the_winning_account = &w2;

        test_two_competitive_accounts_with_one_disqualified(
            &third_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                account_1_balance_positive_correction_minor: 0,
                account_2_balance_positive_correction_minor: 0,
                account_1_age_positive_correction_secs: 0,
                account_2_age_positive_correction_secs: 1,
            },
            expected_wallet_of_the_winning_account,
        );
    }

    #[test]
    fn service_fee_as_well_as_transaction_fee_limits_the_payments_count() {
        init_test_logging();
        let test_name = "service_fee_as_well_as_transaction_fee_limits_the_payments_count";
        let now = SystemTime::now();
        // Thrown away as the second one due to shortage of service fee,
        // for the proposed adjusted balance insignificance (the third account withdraws
        // most of the available balance from the consuming wallet for itself)
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: 10_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        // Thrown away as the first one due to shortage of transaction fee,
        // as it is the least significant by criteria at the moment
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: 55_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let wallet_3 = make_wallet("ghi");
        let last_paid_timestamp_3 = now.checked_sub(Duration::from_secs(29000)).unwrap();
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: wallet_3.clone(),
                balance_wei: 333_000_000_000_000,
                last_paid_timestamp: last_paid_timestamp_3,
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1, account_2, account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor = 300_000_000_000_000_u128;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        assert_eq!(
            result.affordable_accounts,
            vec![PayableAccount {
                wallet: wallet_3,
                balance_wei: service_fee_balance_in_minor,
                last_paid_timestamp: last_paid_timestamp_3,
                pending_payable_opt: None,
            }]
        );
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Payable Account                            Balance Wei
|
|                                           Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000676869 333,000,000,000,000
|                                           300,000,000,000,000
|
|Ruled Out Accounts                         Original
|
|0x0000000000000000000000000000000000616263 10,000,000,000,000
|0x0000000000000000000000000000000000646566 55,000,000,000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn late_error_after_transaction_fee_adjustment_but_rechecked_transaction_fee_found_fatally_insufficient(
    ) {
        init_test_logging();
        let test_name = "late_error_after_transaction_fee_adjustment_but_rechecked_transaction_fee_found_fatally_insufficient";
        let now = SystemTime::now();
        // This account is eliminated in the transaction fee cut
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: 111_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: 333_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("ghi"),
                balance_wei: 222_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1, account_2, account_3];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // This is exactly the amount which will provoke an error
        let service_fee_balance_in_minor_units = (111_000_000_000_000 / 2) - 1;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        let err = match result {
            Ok(_) => panic!("expected an error but got Ok()"),
            Err(e) => e,
        };
        assert_eq!(
            err,
            PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                number_of_accounts: 2,
                total_amount_demanded_minor: 333_000_000_000_000 + 222_000_000_000_000,
                cw_service_fee_balance_minor: service_fee_balance_in_minor_units
            }
        );
        TestLogHandler::new()
            .exists_log_containing(&format!(
            "ERROR: {test_name}: Passed successfully adjustment by transaction fee but noticing \
            critical scarcity of MASQ balance. Operation will abort."));
    }

    struct TestConfigForServiceFeeBalances {
        // Either gwei or wei
        account_balances: Either<Vec<u64>, Vec<u128>>,
        cw_balance_minor: u128,
    }

    struct TestConfigForTransactionFees {
        agreed_transaction_fee_per_computed_unit_major: u64,
        number_of_accounts: usize,
        estimated_transaction_fee_units_per_transaction: u64,
        cw_transaction_fee_balance_major: u64,
    }

    fn make_input_for_initial_check_tests(
        service_fee_balances_config_opt: Option<TestConfigForServiceFeeBalances>,
        transaction_fee_config_opt: Option<TestConfigForTransactionFees>,
    ) -> (Vec<QualifiedPayableAccount>, Box<dyn BlockchainAgent>) {
        let service_fee_balances_config =
            get_service_fee_balances_config(service_fee_balances_config_opt);
        let balances_of_accounts_minor =
            get_service_fee_balances(service_fee_balances_config.account_balances);
        let accounts_count_from_sf_config = balances_of_accounts_minor.len();

        let transaction_fee_config =
            get_transaction_fee_config(transaction_fee_config_opt, accounts_count_from_sf_config);

        let payable_accounts = prepare_payable_accounts(
            transaction_fee_config.number_of_accounts,
            accounts_count_from_sf_config,
            balances_of_accounts_minor,
        );
        let qualified_payables = prepare_qualified_payables(payable_accounts);

        let blockchain_agent = make_agent(
            transaction_fee_config.cw_transaction_fee_balance_major,
            transaction_fee_config.estimated_transaction_fee_units_per_transaction,
            transaction_fee_config.agreed_transaction_fee_per_computed_unit_major,
            service_fee_balances_config.cw_balance_minor,
        );

        (qualified_payables, blockchain_agent)
    }

    fn get_service_fee_balances_config(
        service_fee_balances_config_opt: Option<TestConfigForServiceFeeBalances>,
    ) -> TestConfigForServiceFeeBalances {
        service_fee_balances_config_opt.unwrap_or_else(|| TestConfigForServiceFeeBalances {
            account_balances: Either::Left(vec![1, 1]),
            cw_balance_minor: u64::MAX as u128,
        })
    }
    fn get_service_fee_balances(account_balances: Either<Vec<u64>, Vec<u128>>) -> Vec<u128> {
        match account_balances {
            Either::Left(in_major) => in_major
                .into_iter()
                .map(|major| gwei_to_wei(major))
                .collect(),
            Either::Right(in_minor) => in_minor,
        }
    }

    fn get_transaction_fee_config(
        transaction_fee_config_opt: Option<TestConfigForTransactionFees>,
        accounts_count_from_sf_config: usize,
    ) -> TestConfigForTransactionFees {
        transaction_fee_config_opt.unwrap_or(TestConfigForTransactionFees {
            agreed_transaction_fee_per_computed_unit_major: 120,
            number_of_accounts: accounts_count_from_sf_config,
            estimated_transaction_fee_units_per_transaction: 55_000,
            cw_transaction_fee_balance_major: u64::MAX,
        })
    }

    fn prepare_payable_accounts(
        accounts_count_from_tf_config: usize,
        accounts_count_from_sf_config: usize,
        balances_of_accounts_minor: Vec<u128>,
    ) -> Vec<PayableAccount> {
        if accounts_count_from_tf_config != accounts_count_from_sf_config {
            (0..accounts_count_from_tf_config)
                .map(|idx| make_payable_account(idx as u64))
                .collect()
        } else {
            balances_of_accounts_minor
                .into_iter()
                .enumerate()
                .map(|(idx, balance)| {
                    let mut account = make_payable_account(idx as u64);
                    account.balance_wei = balance;
                    account
                })
                .collect()
        }
    }

    fn prepare_qualified_payables(
        payable_accounts: Vec<PayableAccount>,
    ) -> Vec<QualifiedPayableAccount> {
        payable_accounts
            .into_iter()
            .enumerate()
            .map(|(idx, payable)| {
                let balance = payable.balance_wei;
                QualifiedPayableAccount {
                    qualified_as: payable,
                    payment_threshold_intercept_minor: (balance / 10) * 7,
                    creditor_thresholds: CreditorThresholds {
                        permanent_debt_allowed_wei: (balance / 10) * 7,
                    },
                }
            })
            .collect()
    }

    fn make_agent(
        cw_balance_transaction_fee_major: u64,
        estimated_transaction_fee_units_per_transaction: u64,
        agreed_transaction_fee_price: u64,
        cw_service_fee_balance_minor: u128,
    ) -> Box<dyn BlockchainAgent> {
        let cw_transaction_fee_minor = gwei_to_wei(cw_balance_transaction_fee_major);
        let estimated_transaction_fee_per_transaction_minor = gwei_to_wei(
            estimated_transaction_fee_units_per_transaction * agreed_transaction_fee_price,
        );

        let blockchain_agent = BlockchainAgentMock::default()
            .transaction_fee_balance_minor_result(cw_transaction_fee_minor)
            .service_fee_balance_minor_result(cw_service_fee_balance_minor)
            .estimated_transaction_fee_per_transaction_minor_result(
                estimated_transaction_fee_per_transaction_minor,
            );

        Box::new(blockchain_agent)
    }
}