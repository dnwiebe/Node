use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::{App, Arg, ArgGroup, SubCommand};
use masq_lib::as_any_ref_in_trait_impl;
use masq_lib::messages::{UiSetConfigurationRequest, UiSetConfigurationResponse};
use masq_lib::shared_schema::gas_price_arg;
use masq_lib::shared_schema::min_hops_arg;
use masq_lib::short_writeln;
use masq_lib::utils::ExpectValue;
use std::num::IntErrorKind;

#[derive(Debug, PartialEq, Eq)]
pub struct SetConfigurationCommand {
    pub name: String,
    pub value: String,
}

impl SetConfigurationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let parameter_opt = pieces.get(1).map(|s| &s[2..]);
        match set_configuration_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => {
                let parameter = parameter_opt.expectv("required param");
                Ok(SetConfigurationCommand {
                    name: parameter.to_string(),
                    value: matches
                        .value_of(parameter)
                        .expectv("required param")
                        .to_string(),
                })
            }

            Err(e) => Err(format!("{}", e)),
        }
    }
}

fn validate_start_block(start_block: String) -> Result<(), String> {
    if "latest".eq_ignore_ascii_case(&start_block) || "none".eq_ignore_ascii_case(&start_block) {
        Ok(())
    } else {
        match start_block.parse::<u64>() {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == &IntErrorKind::PosOverflow => Err(
                format!("Unable to parse '{}' into a starting block number or provide 'none' or 'latest' for the latest block number: digits exceed {}.",
                        start_block, u64::MAX),
            ),
            Err(e) => Err(format!("Unable to parse '{}' into a starting block number or provide 'none' or 'latest' for the latest block number: {}.", start_block, e))
        }
    }
}

impl Command for SetConfigurationCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiSetConfigurationRequest {
            name: self.name.clone(),
            value: self.value.clone(),
        };

        let _: UiSetConfigurationResponse = transaction(input, context, 1000)?;
        short_writeln!(context.stdout(), "Parameter was successfully set");
        Ok(())
    }

    as_any_ref_in_trait_impl!();
}

const SET_CONFIGURATION_ABOUT: &str =
    "Sets Node configuration parameters being enabled for this operation when the Node is running.";
const START_BLOCK_HELP: &str =
    "Ordinal number of the Ethereum block where scanning for transactions will start. Use 'latest' or 'none' for Latest block.";

pub fn set_configurationify<'a>(shared_schema_arg: Arg<'a, 'a>) -> Arg<'a, 'a> {
    shared_schema_arg.takes_value(true).min_values(1)
}

pub fn set_configuration_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("set-configuration")
        .about(SET_CONFIGURATION_ABOUT)
        .arg(set_configurationify(gas_price_arg()))
        .arg(set_configurationify(min_hops_arg()))
        .arg(
            Arg::with_name("start-block")
                .help(START_BLOCK_HELP)
                .long("start-block")
                .value_name("START-BLOCK")
                .takes_value(true)
                .required(false)
                .validator(validate_start_block),
        )
        .group(
            ArgGroup::with_name("parameter")
                .args(&["gas-price", "min-hops", "start-block"])
                .required(true),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{
        ToMessageBody, UiSetConfigurationRequest, UiSetConfigurationResponse,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            SET_CONFIGURATION_ABOUT,
            "Sets Node configuration parameters being enabled for this operation when the Node is running."
        );
        assert_eq!(
            START_BLOCK_HELP,
            "Ordinal number of the Ethereum block where scanning for transactions will start. Use 'latest' or 'none' for Latest block."
        );
    }

    #[test]
    fn only_one_parameter_at_a_time_is_permitted() {
        let result = set_configuration_subcommand()
            .get_matches_from_safe(&[
                "set-configuration",
                "--gas-price",
                "70",
                "--start-block",
                "44444",
            ])
            .unwrap_err()
            .to_string();
        assert!(result.contains("cannot be used with one or more of the other specified arguments"));
    }

    #[test]
    fn validate_start_block_catches_invalid_values() {
        assert_eq!(validate_start_block("abc".to_string()), Err("Unable to parse 'abc' into a starting block number or provide 'none' or 'latest' for the latest block number: invalid digit found in string.".to_string()));
        assert_eq!(validate_start_block("918446744073709551615".to_string()), Err("Unable to parse '918446744073709551615' into a starting block number or provide 'none' or 'latest' for the latest block number: digits exceed 18446744073709551615.".to_string()));
        assert_eq!(validate_start_block("123,456,789".to_string()), Err("Unable to parse '123,456,789' into a starting block number or provide 'none' or 'latest' for the latest block number: invalid digit found in string.".to_string()));
        assert_eq!(validate_start_block("123'456'789".to_string()), Err("Unable to parse '123'456'789' into a starting block number or provide 'none' or 'latest' for the latest block number: invalid digit found in string.".to_string()));
    }
    #[test]
    fn validate_start_block_works() {
        assert_eq!(
            validate_start_block("18446744073709551615".to_string()),
            Ok(())
        );
        assert_eq!(validate_start_block("1566".to_string()), Ok(()));
        assert_eq!(validate_start_block("none".to_string()), Ok(()));
        assert_eq!(validate_start_block("None".to_string()), Ok(()));
        assert_eq!(validate_start_block("NONE".to_string()), Ok(()));
        assert_eq!(validate_start_block("nOnE".to_string()), Ok(()));
        assert_eq!(validate_start_block("latest".to_string()), Ok(()));
        assert_eq!(validate_start_block("LATEST".to_string()), Ok(()));
        assert_eq!(validate_start_block("LaTeST".to_string()), Ok(()));
        assert_eq!(validate_start_block("lATEst".to_string()), Ok(()));
    }

    #[test]
    fn command_execution_works_all_fine() {
        test_command_execution("--start-block", "123456");
        test_command_execution("--gas-price", "123456");
        test_command_execution("--min-hops", "6");
    }

    #[test]
    fn set_configuration_command_throws_err_for_missing_values() {
        set_configuration_command_throws_err_for_missing_value("--start-block");
        set_configuration_command_throws_err_for_missing_value("--gas-price");
        set_configuration_command_throws_err_for_missing_value("--min-hops");
    }

    #[test]
    fn set_configuration_command_throws_err_for_invalid_arg() {
        let (invalid_arg, some_value) = ("--invalid-arg", "123");

        let result = SetConfigurationCommand::new(&[
            "set-configuration".to_string(),
            invalid_arg.to_string(),
            some_value.to_string(),
        ]);

        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("Found argument"), "{}", err_msg);
        assert!(err_msg.contains("--invalid-arg"), "{}", err_msg);
        assert!(
            err_msg.contains("which wasn't expected, or isn't valid in this context"),
            "{}",
            err_msg
        );
    }

    fn test_command_execution(name: &str, value: &str) {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetConfigurationResponse {}.tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = SetConfigurationCommand::new(&[
            "set-configuration".to_string(),
            name.to_string(),
            value.to_string(),
        ])
        .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiSetConfigurationRequest {
                    name: name[2..].to_string(),
                    value: value.to_string(),
                }
                .tmb(0),
                1000
            )]
        );
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(&stderr.get_string(), "");
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(&stdout.get_string(), "Parameter was successfully set\n");
    }

    fn set_configuration_command_throws_err_for_missing_value(name: &str) {
        let result =
            SetConfigurationCommand::new(&["set-configuration".to_string(), name.to_string()]);

        let err_msg_fragment = "requires a value but none was supplied";
        let actual_err_msg = result.err().unwrap();
        assert_eq!(
            actual_err_msg.contains(err_msg_fragment),
            true,
            "'{}' did not contain '{}'",
            actual_err_msg,
            err_msg_fragment
        );
    }
}
