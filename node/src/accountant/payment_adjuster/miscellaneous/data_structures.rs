// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;

#[derive(Debug)]
pub enum AdjustmentIterationResult {
    AllAccountsProcessedSmoothly(Vec<AdjustedAccountBeforeFinalization>),
    SpecialTreatmentNeeded {
        special_case: SpecialTreatment,
        remaining: Vec<PayableAccount>,
    },
}

#[derive(Debug)]
pub enum SpecialTreatment {
    TreatInsignificantAccount,
    TreatOutweighedAccounts(Vec<AdjustedAccountBeforeFinalization>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdjustedAccountBeforeFinalization {
    pub original_account: PayableAccount,
    pub proposed_adjusted_balance: u128,
}

impl AdjustedAccountBeforeFinalization {
    pub fn new(original_account: PayableAccount, proposed_adjusted_balance: u128) -> Self {
        Self {
            original_account,
            proposed_adjusted_balance,
        }
    }

    pub fn finalize_collection(
        account_infos: Vec<Self>,
        resolution: ProposedAdjustmentResolution,
    ) -> Vec<PayableAccount> {
        account_infos
            .into_iter()
            .map(|account_info| PayableAccount::from((account_info, resolution)))
            .collect()
    }
}

#[derive(Clone, Copy)]
pub enum ProposedAdjustmentResolution {
    Finalize,
    Revert,
}

// sets the minimal percentage of the original balance that must be
// proposed after the adjustment or the account will be eliminated for insignificance
#[derive(Debug, PartialEq, Eq)]
pub struct PercentageAccountInsignificance {
    // using integers means we have to represent accurate percentage
    // as set of two constants
    pub multiplier: u128,
    pub divisor: u128,
}
