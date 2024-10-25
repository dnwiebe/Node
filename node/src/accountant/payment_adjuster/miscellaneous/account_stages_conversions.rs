// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::minimal_acceptable_balance_assigned_diagnostics;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedPayable,
};
use crate::accountant::payment_adjuster::preparatory_analyser::accounts_abstraction::DisqualificationLimitProvidingAccount;
use crate::accountant::QualifiedPayableAccount;

// Accounts that pass through the checks in PA and dart to BlockchainBridge right away
impl From<QualifiedPayableAccount> for PayableAccount {
    fn from(qualified_payable: QualifiedPayableAccount) -> Self {
        qualified_payable.bare_account
    }
}

// Transaction fee adjustment just done, but no need to go off with the other fee, so we only
// extract the original payable accounts of those retained after the adjustment. PA is done and can
// begin to return.
impl From<WeightedPayable> for PayableAccount {
    fn from(weighted_account: WeightedPayable) -> Self {
        weighted_account.analyzed_account.qualified_as.bare_account
    }
}

// When the consuming balance is being exhausted to zero. This represents the PA's resulted values.
impl From<AdjustedAccountBeforeFinalization> for PayableAccount {
    fn from(non_finalized_adjustment: AdjustedAccountBeforeFinalization) -> Self {
        let mut account = non_finalized_adjustment.original_account;
        account.balance_wei = non_finalized_adjustment.proposed_adjusted_balance_minor;
        account
    }
}

// Makes "remaining unresolved accounts" ready for another recursion that always begins with
// structures in the type of WeightedPayable
impl From<UnconfirmedAdjustment> for WeightedPayable {
    fn from(unconfirmed_adjustment: UnconfirmedAdjustment) -> Self {
        unconfirmed_adjustment.weighted_account
    }
}

// Used if an unconfirmed adjustment passes the confirmation
impl From<UnconfirmedAdjustment> for AdjustedAccountBeforeFinalization {
    fn from(unconfirmed_adjustment: UnconfirmedAdjustment) -> Self {
        let proposed_adjusted_balance_minor =
            unconfirmed_adjustment.proposed_adjusted_balance_minor;
        let weight = unconfirmed_adjustment.weighted_account.weight;
        let original_account = unconfirmed_adjustment
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account;

        AdjustedAccountBeforeFinalization::new(
            original_account,
            weight,
            proposed_adjusted_balance_minor,
        )
    }
}

// When we detect that the upcoming iterations will begin with a surplus in the remaining
// unallocated CW service fee, therefore the remaining accounts' balances are automatically granted
// an amount that equals to their disqualification limit (and can be later provided with even more)
impl From<WeightedPayable> for AdjustedAccountBeforeFinalization {
    fn from(weighted_account: WeightedPayable) -> Self {
        let limited_adjusted_balance = weighted_account.disqualification_limit();
        minimal_acceptable_balance_assigned_diagnostics(
            &weighted_account,
            limited_adjusted_balance,
        );
        let weight = weighted_account.weight;
        let original_account = weighted_account.analyzed_account.qualified_as.bare_account;
        AdjustedAccountBeforeFinalization::new(original_account, weight, limited_adjusted_balance)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedPayable,
    };
    use crate::accountant::test_utils::{make_meaningless_qualified_payable, make_payable_account};
    use crate::accountant::AnalyzedPayableAccount;

    #[test]
    fn conversion_between_non_finalized_account_and_payable_account() {
        let mut original_payable_account = make_payable_account(123);
        original_payable_account.balance_wei = 200_000_000;
        let non_finalized_account = AdjustedAccountBeforeFinalization::new(
            original_payable_account.clone(),
            666777,
            123_456_789,
        );

        let result = PayableAccount::from(non_finalized_account);

        original_payable_account.balance_wei = 123_456_789;
        assert_eq!(result, original_payable_account)
    }

    fn prepare_weighted_account(payable_account: PayableAccount) -> WeightedPayable {
        let garbage_disqualification_limit = 333_333_333;
        let garbage_weight = 777_777_777;
        let mut analyzed_account = AnalyzedPayableAccount::new(
            make_meaningless_qualified_payable(111),
            garbage_disqualification_limit,
        );
        analyzed_account.qualified_as.bare_account = payable_account;
        WeightedPayable::new(analyzed_account, garbage_weight)
    }

    #[test]
    fn conversation_between_weighted_payable_and_standard_payable_account() {
        let original_payable_account = make_payable_account(345);
        let weighted_account = prepare_weighted_account(original_payable_account.clone());

        let result = PayableAccount::from(weighted_account);

        assert_eq!(result, original_payable_account)
    }

    #[test]
    fn conversion_between_weighted_payable_and_non_finalized_account() {
        let original_payable_account = make_payable_account(123);
        let mut weighted_account = prepare_weighted_account(original_payable_account.clone());
        weighted_account
            .analyzed_account
            .disqualification_limit_minor = 200_000_000;
        weighted_account.weight = 78910;

        let result = AdjustedAccountBeforeFinalization::from(weighted_account);

        let expected_result =
            AdjustedAccountBeforeFinalization::new(original_payable_account, 78910, 200_000_000);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn conversion_between_unconfirmed_adjustment_and_non_finalized_account() {
        let mut original_payable_account = make_payable_account(123);
        original_payable_account.balance_wei = 200_000_000;
        let mut weighted_account = prepare_weighted_account(original_payable_account.clone());
        let weight = 321654;
        weighted_account.weight = weight;
        let proposed_adjusted_balance_minor = 111_222_333;
        let unconfirmed_adjustment =
            UnconfirmedAdjustment::new(weighted_account, proposed_adjusted_balance_minor);

        let result = AdjustedAccountBeforeFinalization::from(unconfirmed_adjustment);

        let expected_result = AdjustedAccountBeforeFinalization::new(
            original_payable_account,
            weight,
            proposed_adjusted_balance_minor,
        );
        assert_eq!(result, expected_result)
    }
}