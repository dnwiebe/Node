// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    dump_parameter_line, transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use masq_lib::as_any_ref_in_trait_impl;
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::messages::{UiConfigurationRequest, UiConfigurationResponse};
use masq_lib::short_writeln;
use masq_lib::utils::to_string;
use std::fmt::{Debug, Display};
use std::io::Write;
use std::iter::once;
use thousands::Separable;

const COLUMN_WIDTH: usize = 33;

#[derive(Debug, PartialEq, Eq)]
pub struct ConfigurationCommand {
    pub db_password: Option<String>,
}

const CONFIGURATION_ABOUT: &str = "Displays a running Node's current configuration.";
const CONFIGURATION_ARG_HELP: &str =
    "Password of the database from which the configuration will be read.";

pub fn configuration_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("configuration")
        .about(CONFIGURATION_ABOUT)
        .arg(
            Arg::with_name("db-password")
                .help(CONFIGURATION_ARG_HELP)
                .index(1)
                .required(false),
        )
}

impl Command for ConfigurationCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiConfigurationRequest {
            db_password_opt: self.db_password.clone(),
        };
        let output: Result<UiConfigurationResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(response) => {
                Self::dump_configuration(context.stdout(), response);
                Ok(())
            }
            Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                short_writeln!(
                    context.stderr(),
                    "MASQNode is not running; therefore its configuration cannot be displayed."
                );
                Err(Payload(code, message))
            }
            Err(e) => {
                short_writeln!(context.stderr(), "Configuration retrieval failed: {:?}", e);
                Err(e)
            }
        }
    }

    as_any_ref_in_trait_impl!();
}

impl ConfigurationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match configuration_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };

        Ok(ConfigurationCommand {
            db_password: matches.value_of("db-password").map(to_string),
        })
    }

    fn dump_configuration(stream: &mut dyn Write, configuration: UiConfigurationResponse) {
        dump_parameter_line(stream, "NAME", "VALUE");
        dump_parameter_line(
            stream,
            "Blockchain service URL:",
            &configuration
                .blockchain_service_url_opt
                .unwrap_or_else(|| "[?]".to_string()),
        );
        dump_parameter_line(stream, "Chain:", &configuration.chain_name);
        dump_parameter_line(
            stream,
            "Clandestine port:",
            &configuration.clandestine_port.to_string(),
        );
        dump_parameter_line(
            stream,
            "Consuming wallet private key:",
            &Self::interpret_option(&configuration.consuming_wallet_private_key_opt),
        );
        dump_parameter_line(
            stream,
            "Current schema version:",
            &configuration.current_schema_version,
        );
        dump_parameter_line(
            stream,
            "Earning wallet address:",
            &Self::interpret_option(&configuration.earning_wallet_address_opt),
        );
        dump_parameter_line(stream, "Gas price:", &configuration.gas_price.to_string());
        dump_parameter_line(
            stream,
            "Max block count:",
            &configuration
                .max_block_count_opt
                .map(|m| m.separate_with_commas())
                .unwrap_or_else(|| "[Unlimited]".to_string()),
        );
        dump_parameter_line(
            stream,
            "Neighborhood mode:",
            &configuration.neighborhood_mode,
        );
        dump_parameter_line(
            stream,
            "Port mapping protocol:",
            &Self::interpret_option(&configuration.port_mapping_protocol_opt),
        );
        dump_parameter_line(
            stream,
            "Start block:",
            &configuration
                .start_block_opt
                .map(|m| m.separate_with_commas())
                .unwrap_or_else(|| "[Latest]".to_string()),
        );
        Self::dump_value_list(stream, "Past neighbors:", &configuration.past_neighbors);
        let payment_thresholds = Self::preprocess_combined_parameters({
            let p_c = &configuration.payment_thresholds;
            &[
                ("Debt threshold:", &p_c.debt_threshold_gwei, "gwei"),
                ("Maturity threshold:", &p_c.maturity_threshold_sec, "s"),
                ("Payment grace period:", &p_c.payment_grace_period_sec, "s"),
                (
                    "Permanent debt allowed:",
                    &p_c.permanent_debt_allowed_gwei,
                    "gwei",
                ),
                ("Threshold interval:", &p_c.threshold_interval_sec, "s"),
                ("Unban below:", &p_c.unban_below_gwei, "gwei"),
            ]
        });
        Self::dump_value_list(stream, "Payment thresholds:", &payment_thresholds);
        let rate_pack = Self::preprocess_combined_parameters({
            let r_p = &configuration.rate_pack;
            &[
                ("Routing byte rate:", &r_p.routing_byte_rate, "wei"),
                ("Routing service rate:", &r_p.routing_service_rate, "wei"),
                ("Exit byte rate:", &r_p.exit_byte_rate, "wei"),
                ("Exit service rate:", &r_p.exit_service_rate, "wei"),
            ]
        });
        Self::dump_value_list(stream, "Rate pack:", &rate_pack);
        let scan_intervals = Self::preprocess_combined_parameters({
            let s_i = &configuration.scan_intervals;
            &[
                ("Pending payable:", &s_i.pending_payable_sec, "s"),
                ("Payable:", &s_i.payable_sec, "s"),
                ("Receivable:", &s_i.receivable_sec, "s"),
            ]
        });
        Self::dump_value_list(stream, "Scan intervals:", &scan_intervals);
    }

    fn dump_value_list(stream: &mut dyn Write, name: &str, values: &[String]) {
        if values.is_empty() {
            dump_parameter_line(stream, name, "[?]");
            return;
        }
        let mut name_row = true;
        values.iter().for_each(|value| {
            if name_row {
                dump_parameter_line(stream, name, value);
                name_row = false;
            } else {
                dump_parameter_line(stream, "", value);
            }
        })
    }

    fn interpret_option(value_opt: &Option<String>) -> String {
        match value_opt {
            None => "[?]".to_string(),
            Some(s) => s.clone(),
        }
    }

    fn preprocess_combined_parameters(
        parameters: &[(&str, &dyn DisplaySeparable, &str)],
    ) -> Vec<String> {
        let iter_of_strings = parameters.iter().map(|(description, value, unit)| {
            format!(
                "{:width$} {} {}",
                description,
                value.separate_with_commas(),
                unit,
                width = COLUMN_WIDTH
            )
        });
        once(String::from("")).chain(iter_of_strings).collect()
    }
}

trait DisplaySeparable: Display + Separable {}
impl DisplaySeparable for u64 {}
impl DisplaySeparable for String {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
    use masq_lib::messages::{
        ToMessageBody, UiConfigurationResponse, UiPaymentThresholds, UiRatePack, UiScanIntervals,
    };
    use masq_lib::utils::AutomapProtocol;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CONFIGURATION_ABOUT,
            "Displays a running Node's current configuration."
        );
        assert_eq!(
            CONFIGURATION_ARG_HELP,
            "Password of the database from which the configuration will be read."
        );
    }

    #[test]
    fn command_factory_works_with_password() {
        let subject = CommandFactoryReal::new();

        let command = subject
            .make(&["configuration".to_string(), "password".to_string()])
            .unwrap();

        let configuration_command = command
            .as_any()
            .downcast_ref::<ConfigurationCommand>()
            .unwrap();

        assert_eq!(
            *configuration_command,
            ConfigurationCommand {
                db_password: Some("password".to_string())
            }
        );
    }

    #[test]
    fn command_factory_works_without_password() {
        let subject = CommandFactoryReal::new();

        let command = subject.make(&["configuration".to_string()]).unwrap();

        let configuration_command = command
            .as_any()
            .downcast_ref::<ConfigurationCommand>()
            .unwrap();
        assert_eq!(
            configuration_command,
            &ConfigurationCommand { db_password: None }
        );
    }

    #[test]
    fn doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::Payload(
                NODE_NOT_RUNNING_ERROR,
                "irrelevant".to_string()
            ))
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MASQNode is not running; therefore its configuration cannot be displayed.\n"
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn configuration_command_happy_path_with_secrets() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiConfigurationResponse {
            blockchain_service_url_opt: Some("https://infura.io/ID".to_string()),
            current_schema_version: "schema version".to_string(),
            clandestine_port: 1234,
            chain_name: "ropsten".to_string(),
            gas_price: 2345,
            neighborhood_mode: "standard".to_string(),
            max_block_count_opt: None,
            consuming_wallet_private_key_opt: Some("consuming wallet private key".to_string()),
            consuming_wallet_address_opt: Some("consuming wallet address".to_string()),
            earning_wallet_address_opt: Some("earning address".to_string()),
            port_mapping_protocol_opt: Some(AutomapProtocol::Pcp.to_string()),
            past_neighbors: vec!["neighbor 1".to_string(), "neighbor 2".to_string()],
            payment_thresholds: UiPaymentThresholds {
                threshold_interval_sec: 11111,
                debt_threshold_gwei: 1201412000,
                payment_grace_period_sec: 4578,
                permanent_debt_allowed_gwei: 112000,
                maturity_threshold_sec: 3333,
                unban_below_gwei: 120000,
            },
            rate_pack: UiRatePack {
                routing_byte_rate: 99025000,
                routing_service_rate: 138000000,
                exit_byte_rate: 129000000,
                exit_service_rate: 160000000,
            },
            start_block_opt: None,
            scan_intervals: UiScanIntervals {
                pending_payable_sec: 150500,
                payable_sec: 155000,
                receivable_sec: 250666,
            },
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject =
            ConfigurationCommand::new(&["configuration".to_string(), "password".to_string()])
                .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConfigurationRequest {
                    db_password_opt: Some("password".to_string())
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            format!(
                "\
|NAME                              VALUE\n\
|Blockchain service URL:           https://infura.io/ID\n\
|Chain:                            ropsten\n\
|Clandestine port:                 1234\n\
|Consuming wallet private key:     consuming wallet private key\n\
|Current schema version:           schema version\n\
|Earning wallet address:           earning address\n\
|Gas price:                        2345\n\
|Max block count:                  [Unlimited]\n\
|Neighborhood mode:                standard\n\
|Port mapping protocol:            PCP\n\
|Start block:                      [Latest]\n\
|Past neighbors:                   neighbor 1\n\
|                                  neighbor 2\n\
|Payment thresholds:               \n\
|                                  Debt threshold:                   1,201,412,000 gwei\n\
|                                  Maturity threshold:               3,333 s\n\
|                                  Payment grace period:             4,578 s\n\
|                                  Permanent debt allowed:           112,000 gwei\n\
|                                  Threshold interval:               11,111 s\n\
|                                  Unban below:                      120,000 gwei\n\
|Rate pack:                        \n\
|                                  Routing byte rate:                99,025,000 wei\n\
|                                  Routing service rate:             138,000,000 wei\n\
|                                  Exit byte rate:                   129,000,000 wei\n\
|                                  Exit service rate:                160,000,000 wei\n\
|Scan intervals:                   \n\
|                                  Pending payable:                  150,500 s\n\
|                                  Payable:                          155,000 s\n\
|                                  Receivable:                       250,666 s\n"
            )
            .replace('|', "")
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), "");
    }

    #[test]
    fn configuration_command_happy_path_without_secrets() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiConfigurationResponse {
            blockchain_service_url_opt: Some("https://infura.io/ID".to_string()),
            current_schema_version: "schema version".to_string(),
            clandestine_port: 1234,
            chain_name: "amoy".to_string(),
            gas_price: 2345,
            max_block_count_opt: Some(100_000),
            neighborhood_mode: "zero-hop".to_string(),
            consuming_wallet_address_opt: None,
            consuming_wallet_private_key_opt: None,
            earning_wallet_address_opt: Some("earning wallet".to_string()),
            port_mapping_protocol_opt: Some(AutomapProtocol::Pcp.to_string()),
            past_neighbors: vec![],
            payment_thresholds: UiPaymentThresholds {
                threshold_interval_sec: 1000,
                debt_threshold_gwei: 2500,
                payment_grace_period_sec: 666,
                permanent_debt_allowed_gwei: 1200,
                maturity_threshold_sec: 500,
                unban_below_gwei: 1400,
            },
            rate_pack: UiRatePack {
                routing_byte_rate: 15,
                routing_service_rate: 17,
                exit_byte_rate: 20,
                exit_service_rate: 30,
            },
            start_block_opt: Some(1234567890u64),
            scan_intervals: UiScanIntervals {
                pending_payable_sec: 1000,
                payable_sec: 1000,
                receivable_sec: 1000,
            },
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConfigurationRequest {
                    db_password_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            format!(
                "\
|NAME                              VALUE\n\
|Blockchain service URL:           https://infura.io/ID\n\
|Chain:                            amoy\n\
|Clandestine port:                 1234\n\
|Consuming wallet private key:     [?]\n\
|Current schema version:           schema version\n\
|Earning wallet address:           earning wallet\n\
|Gas price:                        2345\n\
|Max block count:                  100,000\n\
|Neighborhood mode:                zero-hop\n\
|Port mapping protocol:            PCP\n\
|Start block:                      1,234,567,890\n\
|Past neighbors:                   [?]\n\
|Payment thresholds:               \n\
|                                  Debt threshold:                   2,500 gwei\n\
|                                  Maturity threshold:               500 s\n\
|                                  Payment grace period:             666 s\n\
|                                  Permanent debt allowed:           1,200 gwei\n\
|                                  Threshold interval:               1,000 s\n\
|                                  Unban below:                      1,400 gwei\n\
|Rate pack:                        \n\
|                                  Routing byte rate:                15 wei\n\
|                                  Routing service rate:             17 wei\n\
|                                  Exit byte rate:                   20 wei\n\
|                                  Exit service rate:                30 wei\n\
|Scan intervals:                   \n\
|                                  Pending payable:                  1,000 s\n\
|                                  Payable:                          1,000 s\n\
|                                  Receivable:                       1,000 s\n",
            )
            .replace('|', "")
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), "");
    }

    #[test]
    fn configuration_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConfigurationRequest {
                    db_password_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "Configuration retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
