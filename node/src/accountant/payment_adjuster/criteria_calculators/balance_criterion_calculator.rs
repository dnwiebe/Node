// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criteria_calculators::{
    CriterionCalculator, ParameterCriterionCalculator,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::log_2;
use crate::standard_impls_for_calculator;
test_only_use!(
    use std::sync::Mutex;
        use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::characteristics_config::BALANCE_DIAGNOSTICS_CONFIG_OPT;
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::DiagnosticsAxisX;
);

// This parameter affects the steepness inversely, but just slowly.
//
// Don't worry to change the number; it's not as scientific as it looks,
// I arrived at it after many attempts, true, but only until I became
// aligned with the tuning compared to the values gotten from the Age
// parameter (to reproduce the process you probably need to use
// the rendering tools from the diagnostics module)
const BALANCE_LOG_2_ARG_DIVISOR: u128 = 18_490_000;
// This parameter affects the steepness analogously, but energetically
const BALANCE_FINAL_MULTIPLIER: u128 = 2;

pub struct BalanceCriterionCalculator<I>
where
    I: Iterator<Item = (u128, PayableAccount)>,
{
    iter: I,
    formula: Box<dyn Fn(BalanceInput) -> u128>,
}

standard_impls_for_calculator!(
    BalanceCriterionCalculator,
    BalanceInput,
    "BALANCE",
    BALANCE_DIAGNOSTICS_CONFIG_OPT
);

impl<I> BalanceCriterionCalculator<I>
where
    I: Iterator<Item = (u128, PayableAccount)>,
{
    pub fn new(iter: I) -> Self {
        let formula = Box::new(|wrapped_balance_minor: BalanceInput| {
            let balance_minor = wrapped_balance_minor.0;
            let argument_for_log = Self::calculate_binary_argument(balance_minor);
            let binary_weight = Self::nonzero_log2(argument_for_log);
            balance_minor
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
                * BALANCE_FINAL_MULTIPLIER
        });
        Self { iter, formula }
    }

    fn nonzero_log2(input: u128) -> u32 {
        let log = log_2(input);
        if log > 0 {
            log
        } else {
            1
        }
    }

    fn calculate_binary_argument(balance_minor: u128) -> u128 {
        balance_minor / BALANCE_LOG_2_ARG_DIVISOR
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BalanceInput(pub u128);

impl From<&PayableAccount> for BalanceInput {
    fn from(account: &PayableAccount) -> Self {
        BalanceInput(account.balance_wei)
    }
}

#[cfg(test)]
pub mod characteristics_config {
    use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::BalanceInput;
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::DiagnosticsAxisX;
    use crate::accountant::payment_adjuster::test_utils::reinterpret_vec_of_values_on_x_axis;
    use lazy_static::lazy_static;
    use std::sync::Mutex;

    lazy_static! {
        pub static ref BALANCE_DIAGNOSTICS_CONFIG_OPT: Mutex<Option<DiagnosticsAxisX<BalanceInput>>> = {
            let literal_values = [
                123_456,
                7_777_777,
                1_888_999_999_888,
                543_210_000_000_000_000_000,
            ];
            let decadic_exponents = [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25,
            ];
            let horisontal_axis_decimal_exponents =
                reinterpret_vec_of_values_on_x_axis(literal_values, decadic_exponents);
            Mutex::new(Some(DiagnosticsAxisX {
                non_remarkable_values_supply: horisontal_axis_decimal_exponents,
                remarkable_values_opt: Some(vec![
                    (10_u128.pow(9), "GWEI"),
                    (10_u128.pow(18), "MASQ"),
                ]),
                convertor_to_expected_formula_input_type: Box::new(|balance_wei| {
                    BalanceInput(balance_wei)
                }),
            }))
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::{
        BalanceCriterionCalculator, BalanceInput, BALANCE_FINAL_MULTIPLIER,
        BALANCE_LOG_2_ARG_DIVISOR,
    };
    use crate::accountant::payment_adjuster::criteria_calculators::{
        CriterionCalculator, ParameterCriterionCalculator,
    };
    use crate::accountant::payment_adjuster::test_utils::Sentinel;
    use std::iter;

    #[test]
    fn constants_are_correct() {
        assert_eq!(BALANCE_LOG_2_ARG_DIVISOR, 18_490_000);
        assert_eq!(BALANCE_FINAL_MULTIPLIER, 2)
    }

    #[test]
    fn compute_binary_argument_works() {
        let arg_values = [
            1,
            BALANCE_LOG_2_ARG_DIVISOR - 1,
            BALANCE_LOG_2_ARG_DIVISOR,
            BALANCE_LOG_2_ARG_DIVISOR + 1,
            BALANCE_LOG_2_ARG_DIVISOR + 1000,
        ];

        let result: Vec<_> = arg_values
            .into_iter()
            .map(|arg| BalanceCriterionCalculator::<Sentinel>::calculate_binary_argument(arg))
            .collect();

        assert_eq!(
            result,
            vec![
                0,
                0,
                1,
                1,
                (BALANCE_LOG_2_ARG_DIVISOR + 1000) / BALANCE_LOG_2_ARG_DIVISOR
            ]
        )
    }

    #[test]
    fn nonzero_log2_works() {
        let result: Vec<_> = [0, 1, 2, 5, 66, 100, 131, 132, u64::MAX as u128 + 1]
            .into_iter()
            .map(|balance| BalanceCriterionCalculator::<Sentinel>::nonzero_log2(balance))
            .collect();

        assert_eq!(result, vec![1, 1, 1, 2, 6, 6, 7, 7, 64])
    }

    #[test]
    fn calculator_returns_the_right_main_param_name() {
        let subject = BalanceCriterionCalculator::new(iter::empty());

        let result = subject.parameter_name();

        assert_eq!(result, "BALANCE")
    }

    #[test]
    fn balance_criteria_calculation_works() {
        let subject = BalanceCriterionCalculator::new(iter::empty());
        let balance_wei_wrapped = BalanceInput(111_333_555_777);

        let result = subject.formula()(balance_wei_wrapped);

        let expected_result = {
            let binary_weight =
                BalanceCriterionCalculator::<Sentinel>::nonzero_log2(BalanceCriterionCalculator::<
                    Sentinel,
                >::calculate_binary_argument(
                    balance_wei_wrapped.0
                ));
            balance_wei_wrapped
                .0
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
                * BALANCE_FINAL_MULTIPLIER
        };
        assert_eq!(result, expected_result)
    }
}