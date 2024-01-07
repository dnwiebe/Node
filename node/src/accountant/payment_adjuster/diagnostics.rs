// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use std::fmt::Debug;

const PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS: bool = false;

pub const DIAGNOSTICS_MIDDLE_COLUMN_WIDTH: usize = 60;

#[macro_export]
macro_rules! diagnostics {
    // Display a brief description and values from a collection
    ($description: literal, $debuggable_collection: expr) => {
        collection_diagnostics($description, $debuggable_collection)
    };
    // Display a brief description and formatted literal with arguments
    ($description: literal, $($formatted_values: tt)*) => {
        diagnostics(None::<fn()->String>, $description, || format!($($formatted_values)*))
    };
    // Display an account by wallet address, brief description and formatted literal with arguments
    ($wallet_ref: expr, $description: expr,  $($formatted_values: tt)*) => {
        diagnostics(
            Some(||$wallet_ref.to_string()),
            $description,
            || format!($($formatted_values)*)
        )
    };
}

// Intended to be used through the overloaded macro diagnostics!() for better clearness
// and differentiation from the primary functionality
pub fn diagnostics<F1, F2>(subject_renderer_opt: Option<F1>, description: &str, value_renderer: F2)
where
    F1: Fn() -> String,
    F2: Fn() -> String,
{
    if PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS {
        let subject = if let Some(subject_renderer) = subject_renderer_opt {
            subject_renderer()
        } else {
            "".to_string()
        };
        eprintln!(
            "{:<subject_column_length$} {:<length$} {}",
            subject,
            description,
            value_renderer(),
            subject_column_length = WALLET_ADDRESS_LENGTH,
            length = DIAGNOSTICS_MIDDLE_COLUMN_WIDTH
        )
    }
}

// Intended to be used through the overloaded macro diagnostics!() for better clearness
// and differentiation from the primary functionality
pub fn collection_diagnostics<D: Debug>(label: &str, accounts: &[D]) {
    if PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS {
        eprintln!("{}", label);
        accounts
            .iter()
            .for_each(|account| eprintln!("{:?}", account));
    }
}

pub mod separately_defined_diagnostic_functions {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::criteria_calculators::CriterionCalculatorDiagnostics;
    use crate::accountant::payment_adjuster::diagnostics;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
    use crate::sub_lib::wallet::Wallet;
    use thousands::Separable;

    pub fn possibly_outweighed_accounts_diagnostics(
        account_info: &AdjustedAccountBeforeFinalization,
    ) {
        diagnostics!(
            &account_info.original_account.wallet,
            "OUTWEIGHED ACCOUNT FOUND",
            "Original balance: {}, proposed balance: {}",
            account_info
                .original_account
                .balance_wei
                .separate_with_commas(),
            account_info
                .proposed_adjusted_balance
                .separate_with_commas()
        );
    }

    pub fn account_nominated_for_disqualification_diagnostics(
        account_info: &AdjustedAccountBeforeFinalization,
        proposed_adjusted_balance: u128,
        disqualification_edge: u128,
    ) {
        diagnostics!(
            account_info.original_account.wallet,
            "ACCOUNT NOMINATED FOR DISQUALIFICATION FOR INSIGNIFICANCE AFTER ADJUSTMENT",
            "Proposed: {}, disqualification limit: {}",
            proposed_adjusted_balance.separate_with_commas(),
            disqualification_edge.separate_with_commas()
        );
    }

    pub fn exhausting_cw_balance_diagnostics(
        non_finalized_account_info: &AdjustedAccountBeforeFinalization,
        possible_extra_addition: u128,
    ) {
        diagnostics!(
            "EXHAUSTING CW ON PAYMENT",
            "For account {} from proposed {} to the possible maximum of {}",
            non_finalized_account_info.original_account.wallet,
            non_finalized_account_info.proposed_adjusted_balance,
            non_finalized_account_info.proposed_adjusted_balance + possible_extra_addition
        );
    }

    pub fn not_exhausting_cw_balance_diagnostics(
        non_finalized_account_info: &AdjustedAccountBeforeFinalization,
    ) {
        diagnostics!(
            "FULLY EXHAUSTED CW, PASSING ACCOUNT OVER",
            "Account {} with original balance {} must be finalized with proposed {}",
            non_finalized_account_info.original_account.wallet,
            non_finalized_account_info.original_account.balance_wei,
            non_finalized_account_info.proposed_adjusted_balance
        );
    }

    pub fn proposed_adjusted_balance_diagnostics(
        account: &PayableAccount,
        proposed_adjusted_balance: u128,
    ) {
        diagnostics!(
            &account.wallet,
            "PROPOSED ADJUSTED BALANCE",
            "{}",
            proposed_adjusted_balance.separate_with_commas()
        );
    }

    pub fn try_finding_an_account_to_disqualify_diagnostics(
        disqualification_suspected_accounts: &[&AdjustedAccountBeforeFinalization],
        wallet: &Wallet,
    ) {
        diagnostics!(
            "PICKED DISQUALIFIED ACCOUNT",
            "From {:?} picked {}",
            disqualification_suspected_accounts,
            wallet
        );
    }

    pub fn inside_calculator_local_diagnostics<D: CriterionCalculatorDiagnostics + ?Sized>(
        wallet_ref: &Wallet,
        calculator: &D,
        criterion: u128,
        added_in_the_sum: u128,
    ) {
        const FIRST_COLUMN_WIDTH: usize = 30;
        diagnostics!(
            wallet_ref,
            "PARTIAL CRITERION CALCULATED",
            "{:<width$} {} and summed up as {}",
            calculator.input_parameter_name(),
            criterion.separate_with_commas(),
            added_in_the_sum.separate_with_commas(),
            width = FIRST_COLUMN_WIDTH
        );
    }
}

#[cfg(test)]
pub mod formulas_progressive_characteristics {
    use itertools::Itertools;
    use std::fmt::Debug;
    use std::fs::File;
    use std::io::Read;
    use std::iter::once;
    use std::path::Path;
    use std::sync::{Mutex, Once};
    use thousands::Separable;

    // For debugging and tuning up purposes. It lets you see the curve of calculated criterion
    // in dependence to different values of a distinct parameter
    pub const COMPUTE_FORMULAS_CHARACTERISTICS: bool = false;
    // You must preserve the 'static' keyword
    static SUMMARIES_OF_FORMULA_CHARACTERISTICS_FOR_EACH_PARAMETER: Mutex<Vec<String>> =
        Mutex::new(vec![]);
    // You must preserve the 'static' keyword
    //
    // The singleton ensures that the characteristics are always displayed only once, no matter
    // how many tests requested
    static FORMULAS_CHARACTERISTICS_SINGLETON: Once = Once::new();

    pub struct DiagnosticsAxisX<A> {
        pub non_remarkable_values_supply: Vec<u128>,
        pub remarkable_values_opt: Option<Vec<(u128, &'static str)>>,
        pub convertor_to_expected_formula_input_type: Box<dyn Fn(u128) -> A + Send>,
    }

    impl<A> DiagnosticsAxisX<A> {
        fn finalize_input_with_remarkable_values(&self) -> Vec<u128> {
            match self.remarkable_values_opt.as_ref() {
                Some(vals) => {
                    let filtered_remarkable_values = vals.iter().map(|(num, _)| num);
                    let standard_input = self.non_remarkable_values_supply.iter();
                    filtered_remarkable_values
                        .chain(standard_input)
                        .sorted()
                        .dedup()
                        .map(|num| *num)
                        .collect()
                }
                None => self.non_remarkable_values_supply.clone(),
            }
        }
    }

    pub fn render_formulas_characteristics_for_diagnostics_if_enabled() {
        if COMPUTE_FORMULAS_CHARACTERISTICS {
            FORMULAS_CHARACTERISTICS_SINGLETON.call_once(|| {
                let comprehend_debug_summary =
                    SUMMARIES_OF_FORMULA_CHARACTERISTICS_FOR_EACH_PARAMETER
                        .lock()
                        .expect("diagnostics poisoned")
                        .join("\n\n");

                eprintln!("{}", comprehend_debug_summary)
            })
        }
    }

    fn render_notation(
        coordinate_value: u128,
        remarkable_vals: Option<&[(u128, &'static str)]>,
    ) -> String {
        match should_mark_be_used(coordinate_value, remarkable_vals) {
            Some(mark) => format!("{}  {}", coordinate_value.separate_with_commas(), mark),
            None => coordinate_value.separate_with_commas(),
        }
    }
    fn should_mark_be_used(
        coordinate_value: u128,
        remarkable_vals: Option<&[(u128, &'static str)]>,
    ) -> Option<&'static str> {
        match remarkable_vals {
            Some(vals) => vals
                .iter()
                .find(|(val, _)| coordinate_value == *val)
                .map(|(_, mark)| *mark),
            None => None,
        }
    }

    pub fn compute_progressive_characteristics<CriterionCalculatorInput>(
        main_param_name: &'static str,
        config_opt: Option<DiagnosticsAxisX<CriterionCalculatorInput>>,
        formula: &dyn Fn(CriterionCalculatorInput) -> u128,
    ) where
        CriterionCalculatorInput: Debug,
    {
        config_opt.map(|mut config| {
            let input_values = config.finalize_input_with_remarkable_values();
            let remarkable = config.remarkable_values_opt.take();
            let config_x_axis_type_formatter = config.convertor_to_expected_formula_input_type;
            let characteristics = input_values.into_iter().map(|single_coordinate| {
                let correctly_formatted_input = config_x_axis_type_formatter(single_coordinate);
                let input_with_commas =
                    render_notation(single_coordinate, todo!("supply remarkable"));
                let computed_value_with_commas =
                    formula(correctly_formatted_input).separate_with_commas();
                format!(
                    "x: {:<length$} y: {}",
                    input_with_commas,
                    computed_value_with_commas,
                    length = 40
                )
            });
            let head = once(format!(
                "CHARACTERISTICS OF THE FORMULA FOR {}",
                main_param_name
            ));
            let full_text = head.into_iter().chain(characteristics).join("\n");
            SUMMARIES_OF_FORMULA_CHARACTERISTICS_FOR_EACH_PARAMETER
                .lock()
                .expect("diagnostics poisoned")
                .push(full_text);
        });
    }

    fn read_diagnostics_inputs_from_file(path: &Path) -> Vec<u128> {
        let mut file = File::open(path).expect("inputs badly prepared");
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();
        let mut first_two_lines = buffer.lines().take(2);
        let first = first_two_lines.next().expect("first line missing");
        let second = first_two_lines.next().expect("second line missing");
        let first_line_starter = extract_line_starter(first);
        if extract_line_starter(first) != "literals:"
            || extract_line_starter(second) != "decimal_exponents"
        {
            panic!("Inputs in the file in {:?} should have the following format. First line starting \
           \"literals:\", second line with \"decimal_exponents:\", both immediately followed by comma \
           separated integers or left blank", path)
        }
        serialize_values_on_x_axis_from_vecs(
            parse_numbers_from_line(first),
            parse_numbers_from_line(second),
        )
    }

    fn extract_line_starter(line: &str) -> String {
        line.chars().take_while(|char| !char.is_numeric()).collect()
    }

    fn parse_numbers_from_line<N>(line: &str) -> Vec<N> {
        todo!("implement me");
        // line.chars().take()
    }

    pub fn serialize_values_on_x_axis_from_vecs(
        nums_declared_as_literals: Vec<u128>,
        nums_declared_as_decimal_exponents: Vec<u32>,
    ) -> Vec<u128> {
        let exponent_based_numbers = nums_declared_as_decimal_exponents
            .into_iter()
            .map(|exponent| 10_u128.pow(exponent));
        nums_declared_as_literals
            .into_iter()
            .chain(exponent_based_numbers)
            .sorted()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::COMPUTE_FORMULAS_CHARACTERISTICS;
    use crate::accountant::payment_adjuster::diagnostics::PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS;

    #[test]
    fn constants_are_correct() {
        assert_eq!(PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS, false);
        assert_eq!(COMPUTE_FORMULAS_CHARACTERISTICS, false)
    }
}
