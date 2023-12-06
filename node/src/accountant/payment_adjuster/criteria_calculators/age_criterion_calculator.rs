// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criteria_calculators::{
    CriterionCalculator, ParameterCriterionCalculator,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::x_or_1;
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use crate::standard_impls_for_calculator;
use std::time::SystemTime;
test_only_use!(
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::DiagnosticsAxisX;
        use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::characteristics_config::AGE_DIAGNOSTICS_CONFIG_OPT;
    use std::sync::Mutex;
);

const AGE_MAIN_EXPONENT: u32 = 3;
const AGE_DESC_MULTIPLIER_ARG_EXP: u32 = 2;
const AGE_DESC_MULTIPLIER_LOG_STRESS_EXP: u32 = 2;
const AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER: u128 = 1_000;
const AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER: u128 = 10;
const AGE_DESC_MULTIPLIER_DIVISOR_EXP: u32 = 3;

pub struct AgeCriterionCalculator<I>
where
    I: Iterator<Item = (u128, PayableAccount)>,
{
    iter: I,
    formula: Box<dyn Fn(AgeInput) -> u128>,
}

standard_impls_for_calculator!(
    AgeCriterionCalculator,
    AgeInput,
    "AGE",
    AGE_DIAGNOSTICS_CONFIG_OPT
);

impl<I> AgeCriterionCalculator<I>
where
    I: Iterator<Item = (u128, PayableAccount)>,
{
    pub fn new(iter: I, payment_adjuster: &PaymentAdjusterReal) -> Self {
        let now = payment_adjuster.inner.now();

        let formula = Box::new(move |wrapped_last_paid_timestamp: AgeInput| {
            let last_paid_timestamp = wrapped_last_paid_timestamp.0;
            let elapsed_secs: u64 = Self::nonzero_elapsed(now, last_paid_timestamp);

            let divisor = Self::nonzero_compute_divisor(elapsed_secs);

            let log_multiplier = Self::compute_descending_multiplier(elapsed_secs, divisor);

            (elapsed_secs as u128)
                .checked_pow(AGE_MAIN_EXPONENT)
                .expect("pow overflow")
                .checked_div(divisor)
                .expect("div overflow")
                .checked_mul(log_multiplier)
                .expect("mul overflow")
        });
        Self { iter, formula }
    }

    fn nonzero_elapsed(now: SystemTime, previous_timestamp: SystemTime) -> u64 {
        let elapsed = now
            .duration_since(previous_timestamp)
            .expect("time traveller")
            .as_secs();
        if elapsed > 0 {
            elapsed
        } else {
            1
        }
    }

    fn nonzero_compute_divisor(elapsed_sec: u64) -> u128 {
        (elapsed_sec as f64).sqrt().ceil() as u128
    }

    fn nonzero_log_value(num: f64) -> u128 {
        if num < 2.0 {
            1
        } else {
            num.log2() as u128
        }
    }

    // This multiplier is meant to push against the growth of the age criterion,
    // slowing it down more and more as the time parameter increases.
    // The reason is that balance numbers soon get huge but yet are not so unrealistic.
    // For a balanced solution, the age criterion formula is designed to progress
    // more steeply in the area of rather smaller amounts of seconds, while if
    // we move on towards a couple of days, weeks, months and so on, the impact of the parameter
    // diminishes
    fn compute_descending_multiplier(elapsed_secs: u64, divisor: u128) -> u128 {
        let fast_growing_argument = (elapsed_secs as u128)
            .checked_pow(AGE_DESC_MULTIPLIER_ARG_EXP)
            .expect("pow blew up") as f64;

        let log_value = Self::nonzero_log_value(fast_growing_argument);

        let log_stressed = log_value.pow(AGE_DESC_MULTIPLIER_LOG_STRESS_EXP)
            * AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER;

        let divisor_stressed = divisor * AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER;

        let final_log_multiplier =
            (log_stressed / divisor_stressed).pow(AGE_DESC_MULTIPLIER_DIVISOR_EXP);

        x_or_1(final_log_multiplier)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AgeInput(pub SystemTime);

impl From<&PayableAccount> for AgeInput {
    fn from(account: &PayableAccount) -> Self {
        AgeInput(account.last_paid_timestamp)
    }
}

#[cfg(test)]
pub mod characteristics_config {
    use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::AgeInput;
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::DiagnosticsAxisX;
    use crate::accountant::payment_adjuster::test_utils::reinterpret_vec_of_values_on_x_axis;
    use lazy_static::lazy_static;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::time::SystemTime;

    lazy_static! {
        pub static ref AGE_DIAGNOSTICS_CONFIG_OPT: Mutex<Option<DiagnosticsAxisX<AgeInput>>> = {
            let now = SystemTime::now();
            let literal_values = [
                1,
                5,
                9,
                25,
                44,
                50,
                75,
                180,
                600,
                900,
                33_333,
                86_400,
                255_000,
                6_700_000,
                55_333_000,
                200_300_400,
                500_000_000,
                7_000_000_000,
                78_000_000_000,
                444_333_444_444,
            ];
            let decadic_exponents = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
            let horisontal_axis_data_suply =
                reinterpret_vec_of_values_on_x_axis(literal_values, decadic_exponents);
            Mutex::new(Some(DiagnosticsAxisX {
                non_remarkable_values_supply: horisontal_axis_data_suply,
                remarkable_values_opt: Some(vec![
                    (60, "MINUTE"),
                    (3_600, "HOUR"),
                    (86_400, "DAY"),
                    (604_800, "WEEK"),
                ]),
                convertor_to_expected_formula_input_type: Box::new(
                    move |secs_since_last_paid_payable| {
                        let native_time = now
                            .checked_sub(Duration::from_secs(secs_since_last_paid_payable as u64))
                            .expect("time travelling");
                        AgeInput(native_time)
                    },
                ),
            }))
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::{
        AgeCriterionCalculator, AgeInput, AGE_DESC_MULTIPLIER_ARG_EXP,
        AGE_DESC_MULTIPLIER_DIVISOR_EXP, AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER,
        AGE_DESC_MULTIPLIER_LOG_STRESS_EXP, AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER,
        AGE_MAIN_EXPONENT,
    };
    use crate::accountant::payment_adjuster::criteria_calculators::{
        CriterionCalculator, ParameterCriterionCalculator,
    };
    use crate::accountant::payment_adjuster::test_utils::{make_initialized_subject, Sentinel};
    use std::iter::empty;
    use std::time::{Duration, SystemTime};

    #[test]
    fn constants_are_correct() {
        assert_eq!(AGE_MAIN_EXPONENT, 3);
        assert_eq!(AGE_DESC_MULTIPLIER_ARG_EXP, 2);
        assert_eq!(AGE_DESC_MULTIPLIER_LOG_STRESS_EXP, 2);
        assert_eq!(AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER, 1_000);
        assert_eq!(AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER, 10);
        assert_eq!(AGE_DESC_MULTIPLIER_DIVISOR_EXP, 3);
    }

    #[test]
    fn nonzero_compute_divisor_works() {
        let result: Vec<_> = [1, 100, 81, 82, 80]
            .into_iter()
            .map(|secs| AgeCriterionCalculator::<Sentinel>::nonzero_compute_divisor(secs))
            .collect();

        assert_eq!(result, vec![1, 10, 9, 10, 9])
    }

    #[test]
    fn nonzero_elapsed_works() {
        let now = SystemTime::now();
        let result: Vec<_> = [
            // The first entry is normally considered 0 s
            now.checked_sub(Duration::from_nanos(55)).unwrap(),
            now.checked_sub(Duration::from_secs(1)).unwrap(),
            now.checked_sub(Duration::from_secs(2)).unwrap(),
        ]
        .into_iter()
        .map(|timestamp| AgeCriterionCalculator::<Sentinel>::nonzero_elapsed(now, timestamp))
        .collect();

        assert_eq!(result, vec![1, 1, 2])
    }

    #[test]
    fn compute_descending_multiplier_works() {
        let result: Vec<_> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 18]
            .into_iter()
            .take(12)
            .map(|exp| 10_u64.pow(exp))
            .map(|seconds_elapsed| {
                let divisor =
                    AgeCriterionCalculator::<Sentinel>::nonzero_compute_divisor(seconds_elapsed);
                AgeCriterionCalculator::<Sentinel>::compute_descending_multiplier(
                    seconds_elapsed,
                    divisor,
                )
            })
            .collect();

        assert_eq!(
            result,
            vec![
                729000000, 4826809000, 1435249152, 308915776, 40353607, 3511808, 287496, 21952,
                1331, 1, 1, 1
            ]
        )
    }

    #[test]
    fn nonzero_log_works() {
        let result = vec![0.0, 0.6, 1.3, 1.99999, 2.0, 2.1, 5.0, 9.0]
            .into_iter()
            .map(|num| AgeCriterionCalculator::<Sentinel>::nonzero_log_value(num))
            .collect::<Vec<u128>>();

        assert_eq!(result, vec![1, 1, 1, 1, 1, 1, 2, 3])
    }

    #[test]
    fn calculator_returns_the_right_main_param_name() {
        let payment_adjuster = make_initialized_subject(SystemTime::now(), None, None);
        let subject = AgeCriterionCalculator::new(empty(), &payment_adjuster);

        let result = subject.parameter_name();

        assert_eq!(result, "AGE")
    }

    #[test]
    fn age_criteria_calculation_works() {
        let now = SystemTime::now();
        let payment_adjuster = make_initialized_subject(now, None, None);
        let subject = AgeCriterionCalculator::new(empty(), &payment_adjuster);
        let last_paid_timestamp_wrapped = AgeInput(
            SystemTime::now()
                .checked_sub(Duration::from_secs(1500))
                .unwrap(),
        );

        let result = subject.formula()(last_paid_timestamp_wrapped);

        let expected_criterion = {
            let elapsed_secs: u64 = now
                .duration_since(last_paid_timestamp_wrapped.0)
                .unwrap()
                .as_secs();
            let divisor = AgeCriterionCalculator::<Sentinel>::nonzero_compute_divisor(elapsed_secs);
            let log_multiplier = AgeCriterionCalculator::<Sentinel>::compute_descending_multiplier(
                elapsed_secs,
                divisor,
            );
            (elapsed_secs as u128)
                .checked_pow(AGE_MAIN_EXPONENT)
                .unwrap()
                .checked_div(divisor)
                .unwrap()
                .checked_mul(log_multiplier)
                .unwrap()
        };
        assert_eq!(result, expected_criterion)
    }
}