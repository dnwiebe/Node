// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::DEFAULT_PENDING_TOO_LONG_SEC;
use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
use crate::bootstrapper::BootstrapperConfig;
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::accountant::{PaymentThresholds, ScanIntervals, DEFAULT_EARNING_WALLET};
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::cryptde_real::CryptDEReal;
use crate::sub_lib::neighborhood::{
    Hops, NeighborhoodConfig, NeighborhoodMode, NodeDescriptor, RatePack,
};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::wallet::Wallet;
use clap::value_t;
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::{DEFAULT_CHAIN, MASQ_URL_PREFIX};
use masq_lib::logger::Logger;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::{ConfiguratorError, ParamError};
use masq_lib::utils::{to_string, AutomapProtocol, ExpectValue};
use rustc_hex::FromHex;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub trait UnprivilegedParseArgsConfiguration {
    // Only initialization that cannot be done with privilege should happen here.
    fn unprivileged_parse_args(
        &self,
        multi_config: &MultiConfig,
        unprivileged_config: &mut BootstrapperConfig,
        persistent_config: &mut dyn PersistentConfiguration,
        logger: &Logger,
    ) -> Result<(), ConfiguratorError> {
        unprivileged_config
            .blockchain_bridge_config
            .blockchain_service_url_opt =
            if has_user_specified(multi_config, "blockchain-service-url") {
                value_m!(multi_config, "blockchain-service-url", String)
            } else {
                match persistent_config.blockchain_service_url() {
                    Ok(Some(price)) => Some(price),
                    Ok(None) => None,
                    Err(pce) => return Err(pce.into_configurator_error("gas-price")),
                }
            };
        unprivileged_config.clandestine_port_opt = value_m!(multi_config, "clandestine-port", u16);
        unprivileged_config.blockchain_bridge_config.gas_price =
            if has_user_specified(multi_config, "gas-price") {
                value_m!(multi_config, "gas-price", u64).expectv("gas price")
            } else {
                match persistent_config.gas_price() {
                    Ok(price) => price,
                    Err(pce) => return Err(pce.into_configurator_error("gas-price")),
                }
            };
        unprivileged_config.db_password_opt = value_m!(multi_config, "db-password", String);
        configure_accountant_config(multi_config, unprivileged_config, persistent_config)?;
        unprivileged_config.mapping_protocol_opt =
            compute_mapping_protocol_opt(multi_config, persistent_config, logger);
        let mnc_result = {
            get_wallets(multi_config, persistent_config, unprivileged_config)?;
            make_neighborhood_config(self, multi_config, persistent_config, unprivileged_config)
        };

        mnc_result.map(|config| unprivileged_config.neighborhood_config = config)
    }

    fn get_past_neighbors(
        &self,
        persistent_config: &mut dyn PersistentConfiguration,
        unprivileged_config: &mut BootstrapperConfig,
    ) -> Result<Vec<NodeDescriptor>, ConfiguratorError>;
}

pub struct UnprivilegedParseArgsConfigurationDaoReal {}

impl UnprivilegedParseArgsConfiguration for UnprivilegedParseArgsConfigurationDaoReal {
    fn get_past_neighbors(
        &self,
        persistent_config: &mut dyn PersistentConfiguration,
        unprivileged_config: &mut BootstrapperConfig,
    ) -> Result<Vec<NodeDescriptor>, ConfiguratorError> {
        Ok(
            match &get_db_password(unprivileged_config, persistent_config)? {
                Some(db_password) => match persistent_config.past_neighbors(db_password) {
                    Ok(Some(past_neighbors)) => past_neighbors,
                    Ok(None) => vec![],
                    Err(PersistentConfigError::PasswordError) => {
                        return Err(ConfiguratorError::new(vec![ParamError::new(
                            "db-password",
                            "PasswordError",
                        )]))
                    }
                    Err(e) => {
                        return Err(ConfiguratorError::new(vec![ParamError::new(
                            "[past neighbors]",
                            &format!("{:?}", e),
                        )]))
                    }
                },
                None => vec![],
            },
        )
    }
}

pub struct UnprivilegedParseArgsConfigurationDaoNull {}

impl UnprivilegedParseArgsConfiguration for UnprivilegedParseArgsConfigurationDaoNull {
    fn get_past_neighbors(
        &self,
        _persistent_config: &mut dyn PersistentConfiguration,
        _unprivileged_config: &mut BootstrapperConfig,
    ) -> Result<Vec<NodeDescriptor>, ConfiguratorError> {
        Ok(vec![])
    }
}

pub fn get_wallets(
    multi_config: &MultiConfig,
    persistent_config: &mut dyn PersistentConfiguration,
    config: &mut BootstrapperConfig,
) -> Result<(), ConfiguratorError> {
    let mc_consuming_opt = value_m!(multi_config, "consuming-private-key", String);
    let mc_earning_opt = value_m!(multi_config, "earning-wallet", String);
    let pc_consuming_opt = if let Some(db_password) = &config.db_password_opt {
        match persistent_config.consuming_wallet_private_key(db_password.as_str()) {
            Ok(pco) => pco,
            Err(PersistentConfigError::PasswordError) => None,
            Err(e) => return Err(e.into_configurator_error("consuming-private-key")),
        }
    } else {
        None
    };
    let pc_earning_opt = match persistent_config.earning_wallet_address() {
        Ok(peo) => peo,
        Err(e) => return Err(e.into_configurator_error("earning-wallet")),
    };
    let consuming_opt = match (&mc_consuming_opt, &pc_consuming_opt) {
        (None, _) => pc_consuming_opt,
        (Some(_), None) => mc_consuming_opt,
        (Some(m), Some(c)) if wallet_params_are_equal(m, c) => pc_consuming_opt,
        _ => {
            return Err(ConfiguratorError::required(
                "consuming-private-key",
                "Cannot change to a private key different from that previously set",
            ))
        }
    };
    let earning_opt = match (&mc_earning_opt, &pc_earning_opt) {
        (None, _) => pc_earning_opt,
        (Some(_), None) => mc_earning_opt,
        (Some(m), Some(c)) if wallet_params_are_equal(m, c) => pc_earning_opt,
        (Some(m), Some(c)) => {
            return Err(ConfiguratorError::required(
                "earning-wallet",
                &format!(
                    "Cannot change to an address ({}) different from that previously set ({})",
                    m, c
                ),
            ))
        }
    };
    let consuming_wallet_opt = consuming_opt.map(|consuming_private_key| {
        let key_bytes = consuming_private_key
            .from_hex::<Vec<u8>>()
            .unwrap_or_else(|_| {
                panic!(
                    "Wallet corruption: bad hex value for consuming wallet private key: {}",
                    consuming_private_key
                )
            });
        let key_pair = Bip32EncryptionKeyProvider::from_raw_secret(key_bytes.as_slice())
            .unwrap_or_else(|_| {
                panic!(
                    "Wallet corruption: consuming wallet private key in invalid format: {:?}",
                    key_bytes
                )
            });
        Wallet::from(key_pair)
    });
    let earning_wallet_opt = earning_opt.map(|earning_address| {
        Wallet::from_str(&earning_address).unwrap_or_else(|_| {
            panic!(
                "Wallet corruption: bad value for earning wallet address: {}",
                earning_address
            )
        })
    });
    config.consuming_wallet_opt = consuming_wallet_opt;
    config.earning_wallet = earning_wallet_opt.unwrap_or_else(|| DEFAULT_EARNING_WALLET.clone());
    Ok(())
}

fn wallet_params_are_equal(a: &str, b: &str) -> bool {
    a.to_uppercase() == b.to_uppercase()
}

pub fn make_neighborhood_config<T: UnprivilegedParseArgsConfiguration + ?Sized>(
    parse_args_configurator: &T,
    multi_config: &MultiConfig,
    persistent_config: &mut dyn PersistentConfiguration,
    unprivileged_config: &mut BootstrapperConfig,
) -> Result<NeighborhoodConfig, ConfiguratorError> {
    let neighbor_configs: Vec<NodeDescriptor> = {
        match convert_ci_configs(multi_config)? {
            Some(configs) => configs,
            None => parse_args_configurator
                .get_past_neighbors(persistent_config, unprivileged_config)?,
        }
    };

    let min_hops: Hops = match value_m!(multi_config, "min-hops", Hops) {
        Some(hops) => hops,
        None => match persistent_config.min_hops() {
            Ok(hops) => hops,
            Err(e) => panic!("Unable to find min_hops value in database: {:?}", e),
        },
    };

    match make_neighborhood_mode(multi_config, neighbor_configs, persistent_config) {
        Ok(mode) => Ok(NeighborhoodConfig { mode, min_hops }),
        Err(e) => Err(e),
    }
}

fn make_neighborhood_mode(
    multi_config: &MultiConfig,
    neighbor_configs: Vec<NodeDescriptor>,
    persistent_config: &mut dyn PersistentConfiguration,
) -> Result<NeighborhoodMode, ConfiguratorError> {
    let neighborhood_mode_opt = value_m!(multi_config, "neighborhood-mode", String);
    match neighborhood_mode_opt {
        Some(ref s) if s == "standard" || s == "originate-only" => {
            let rate_pack = configure_rate_pack(multi_config, persistent_config)?;
            match s.as_str() {
                "standard" => neighborhood_mode_standard(multi_config, neighbor_configs, rate_pack),
                "originate-only" => {
                    if neighbor_configs.is_empty() {
                        Err(ConfiguratorError::required("neighborhood-mode", "Node cannot run as --neighborhood-mode originate-only without --neighbors specified"))
                    } else {
                        Ok(NeighborhoodMode::OriginateOnly(neighbor_configs, rate_pack))
                    }
                }
                _ => unreachable!(),
            }
        }
        Some(ref s) if s == "consume-only" => {
            let mut errors = ConfiguratorError::new(vec![]);
            if neighbor_configs.is_empty() {
                errors = errors.another_required("neighborhood-mode", "Node cannot run as --neighborhood-mode consume-only without --neighbors specified");
            }
            if value_m!(multi_config, "dns-servers", String).is_some() {
                errors = errors.another_required("neighborhood-mode", "Node cannot run as --neighborhood-mode consume-only if --dns-servers is specified");
            }
            if !errors.is_empty() {
                Err(errors)
            } else {
                Ok(NeighborhoodMode::ConsumeOnly(neighbor_configs))
            }
        }
        Some(ref s) if s == "zero-hop" => {
            if value_m!(multi_config, "ip", IpAddr).is_some() {
                Err(ConfiguratorError::required(
                    "neighborhood-mode",
                    "Node cannot run as --neighborhood-mode zero-hop if --ip is specified",
                ))
            } else {
                if !neighbor_configs.is_empty() {
                    let password_opt = value_m!(multi_config, "db-password", String);
                    zero_hop_neighbors_configuration(
                        password_opt,
                        neighbor_configs,
                        persistent_config,
                    )?
                }
                Ok(NeighborhoodMode::ZeroHop)
            }
        }
        // These two cases are untestable
        Some(ref s) => panic!(
            "--neighborhood-mode {} has not been properly provided for in the code",
            s
        ),
        None => {
            let rate_pack = configure_rate_pack(multi_config, persistent_config)?;
            neighborhood_mode_standard(multi_config, neighbor_configs, rate_pack)
        }
    }
}

fn zero_hop_neighbors_configuration(
    password_opt: Option<String>,
    descriptors: Vec<NodeDescriptor>,
    persistent_config: &mut dyn PersistentConfiguration,
) -> Result<(), ConfiguratorError> {
    match password_opt {
        Some(password) => {
            if let Err(e) = persistent_config.set_past_neighbors(Some(descriptors), &password) {
                return Err(e.into_configurator_error("neighbors"));
            }
        }
        None => {
            return Err(ConfiguratorError::required(
                "neighbors",
                "Cannot proceed without a password",
            ));
        }
    }
    Ok(())
}

fn neighborhood_mode_standard(
    multi_config: &MultiConfig,
    neighbor_configs: Vec<NodeDescriptor>,
    rate_pack: RatePack,
) -> Result<NeighborhoodMode, ConfiguratorError> {
    let ip = get_public_ip(multi_config)?;
    Ok(NeighborhoodMode::Standard(
        NodeAddr::new(&ip, &[]),
        neighbor_configs,
        rate_pack,
    ))
}

fn get_public_ip(multi_config: &MultiConfig) -> Result<IpAddr, ConfiguratorError> {
    match value_m!(multi_config, "ip", String) {
        Some(ip_str) => match IpAddr::from_str(&ip_str) {
            Ok(ip_addr) => Ok(ip_addr),
            Err(_) => todo!("Drive in a better error message"), //Err(ConfiguratorError::required("ip", &format! ("blockety blip: '{}'", ip_str),
        },
        None => Ok(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))), // sentinel: means "Try Automap"
    }
}

fn convert_ci_configs(
    multi_config: &MultiConfig,
) -> Result<Option<Vec<NodeDescriptor>>, ConfiguratorError> {
    type DescriptorParsingResult = Result<NodeDescriptor, ParamError>;
    match value_m!(multi_config, "neighbors", String) {
        None => Ok(None),
        Some(joined_configs) => {
            let separate_configs: Vec<String> =
                joined_configs.split(',').map(to_string).collect_vec();
            if separate_configs.is_empty() {
                Ok(None)
            } else {
                let desired_chain = Chain::from(
                    value_m!(multi_config, "chain", String)
                        .unwrap_or_else(|| DEFAULT_CHAIN.rec().literal_identifier.to_string())
                        .as_str(),
                );
                let cryptde_for_key_len: Box<dyn CryptDE> = {
                    if value_m!(multi_config, "fake-public-key", String).is_none() {
                        Box::new(CryptDEReal::new(desired_chain))
                    } else {
                        Box::new(CryptDENull::new(desired_chain))
                    }
                };
                let results = validate_descriptors_from_user(
                    separate_configs,
                    cryptde_for_key_len,
                    desired_chain,
                );
                let (ok, err): (Vec<DescriptorParsingResult>, Vec<DescriptorParsingResult>) =
                    results.into_iter().partition(|result| result.is_ok());
                let ok = ok
                    .into_iter()
                    .map(|ok| ok.expect("NodeDescriptor"))
                    .collect_vec();
                let err = err
                    .into_iter()
                    .map(|err| err.expect_err("ParamError"))
                    .collect_vec();
                if err.is_empty() {
                    Ok(Some(ok))
                } else {
                    Err(ConfiguratorError::new(err))
                }
            }
        }
    }
}

fn validate_descriptors_from_user(
    descriptors: Vec<String>,
    cryptde_for_key_len: Box<dyn CryptDE>,
    desired_native_chain: Chain,
) -> Vec<Result<NodeDescriptor, ParamError>> {
    descriptors.into_iter().map(|node_desc_from_ci| {
        let node_desc_trimmed = node_desc_from_ci.trim();
        match NodeDescriptor::try_from((cryptde_for_key_len.as_ref(), node_desc_trimmed)) {
            Ok(descriptor) => {
                let competence_from_descriptor = descriptor.blockchain;
                if desired_native_chain == competence_from_descriptor {
                    validate_mandatory_node_addr(node_desc_trimmed, descriptor)
                } else {
                    let desired_chain = desired_native_chain.rec().literal_identifier;
                    Err(ParamError::new(
                        "neighbors", &format!(
                            "Mismatched chains. You are requiring access to '{}' ({}{}:<public key>@<node address>) with descriptor belonging to '{}'",
                            desired_chain, MASQ_URL_PREFIX,
                            desired_chain,
                            competence_from_descriptor.rec().literal_identifier
                        )
                    ))
                }
            }
            Err(e) => Err(ParamError::new("neighbors", &e))
        }
    })
        .collect_vec()
}

fn validate_mandatory_node_addr(
    supplied_descriptor: &str,
    descriptor: NodeDescriptor,
) -> Result<NodeDescriptor, ParamError> {
    if descriptor.node_addr_opt.is_some() {
        Ok(descriptor)
    } else {
        Err(ParamError::new(
            "neighbors",
            &format!(
                "Neighbors supplied without ip addresses and ports are not valid: '{}<N/A>:<N/A>",
                if supplied_descriptor.ends_with("@:") {
                    supplied_descriptor.strip_suffix(':').expect("logic failed")
                } else {
                    supplied_descriptor
                }
            ),
        ))
    }
}

fn compute_mapping_protocol_opt(
    multi_config: &MultiConfig,
    persistent_config: &mut dyn PersistentConfiguration,
    logger: &Logger,
) -> Option<AutomapProtocol> {
    let persistent_mapping_protocol_opt = match persistent_config.mapping_protocol() {
        Ok(mp_opt) => mp_opt,
        Err(e) => {
            warning!(
                logger,
                "Could not read mapping protocol from database: {:?}",
                e
            );
            None
        }
    };
    let mapping_protocol_specified = multi_config.occurrences_of("mapping-protocol") > 0;
    let computed_mapping_protocol_opt = match (
        value_m!(multi_config, "mapping-protocol", AutomapProtocol),
        persistent_mapping_protocol_opt,
        mapping_protocol_specified,
    ) {
        (None, Some(persisted_mapping_protocol), false) => Some(persisted_mapping_protocol),
        (None, _, true) => None,
        (cmd_line_mapping_protocol_opt, _, _) => cmd_line_mapping_protocol_opt,
    };
    if computed_mapping_protocol_opt != persistent_mapping_protocol_opt {
        if computed_mapping_protocol_opt.is_none() {
            debug!(logger, "Blanking mapping protocol out of the database")
        }
        match persistent_config.set_mapping_protocol(computed_mapping_protocol_opt) {
            Ok(_) => (),
            Err(e) => {
                warning!(
                    logger,
                    "Could not save mapping protocol to database: {:?}",
                    e
                );
            }
        }
    }
    computed_mapping_protocol_opt
}

fn configure_accountant_config(
    multi_config: &MultiConfig,
    config: &mut BootstrapperConfig,
    persist_config: &mut dyn PersistentConfiguration,
) -> Result<(), ConfiguratorError> {
    let payment_thresholds = process_combined_params(
        "payment-thresholds",
        multi_config,
        persist_config,
        |str: &str| PaymentThresholds::try_from(str),
        |pc: &dyn PersistentConfiguration| pc.payment_thresholds(),
        |pc: &mut dyn PersistentConfiguration, curves| pc.set_payment_thresholds(curves),
    )?;

    check_payment_thresholds(&payment_thresholds)?;

    let scan_intervals = process_combined_params(
        "scan-intervals",
        multi_config,
        persist_config,
        |str: &str| ScanIntervals::try_from(str),
        |pc: &dyn PersistentConfiguration| pc.scan_intervals(),
        |pc: &mut dyn PersistentConfiguration, intervals| pc.set_scan_intervals(intervals),
    )?;
    let suppress_initial_scans =
        value_m!(multi_config, "scans", String).unwrap_or_else(|| "on".to_string()) == *"off";

    config.payment_thresholds_opt = Some(payment_thresholds);
    config.scan_intervals_opt = Some(scan_intervals);
    config.suppress_initial_scans = suppress_initial_scans;
    config.when_pending_too_long_sec = DEFAULT_PENDING_TOO_LONG_SEC;
    Ok(())
}

fn check_payment_thresholds(
    payment_thresholds: &PaymentThresholds,
) -> Result<(), ConfiguratorError> {
    if payment_thresholds.debt_threshold_gwei <= payment_thresholds.permanent_debt_allowed_gwei {
        let msg = format!(
            "Value of DebtThresholdGwei ({}) must be bigger than PermanentDebtAllowedGwei ({})",
            payment_thresholds.debt_threshold_gwei, payment_thresholds.permanent_debt_allowed_gwei
        );
        return Err(ConfiguratorError::required("payment-thresholds", &msg));
    }
    if payment_thresholds.threshold_interval_sec > 10_u64.pow(9) {
        return Err(ConfiguratorError::required(
            "payment-thresholds",
            "Value of ThresholdIntervalSec must not exceed 1,000,000,000 s",
        ));
    }
    Ok(())
}

fn configure_rate_pack(
    multi_config: &MultiConfig,
    persist_config: &mut dyn PersistentConfiguration,
) -> Result<RatePack, ConfiguratorError> {
    process_combined_params(
        "rate-pack",
        multi_config,
        persist_config,
        |str: &str| RatePack::try_from(str),
        |pc: &dyn PersistentConfiguration| pc.rate_pack(),
        |pc: &mut dyn PersistentConfiguration, rate_pack| pc.set_rate_pack(rate_pack),
    )
}

fn process_combined_params<'a, T: PartialEq, C1, C2>(
    parameter_name: &'a str,
    multi_config: &MultiConfig,
    persist_config: &'a mut dyn PersistentConfiguration,
    parser: fn(&str) -> Result<T, String>,
    persistent_config_getter: C1,
    persistent_config_setter: C2,
) -> Result<T, ConfiguratorError>
where
    C1: Fn(&dyn PersistentConfiguration) -> Result<T, PersistentConfigError>,
    C2: Fn(&mut dyn PersistentConfiguration, String) -> Result<(), PersistentConfigError>,
{
    Ok(
        match (
            value_m!(multi_config, parameter_name, String),
            persistent_config_getter(persist_config),
        ) {
            (Some(cli_string_values), pc_result) => {
                let cli_values: T = parser(&cli_string_values)
                    .map_err(|e| ConfiguratorError::required(parameter_name, &e))?;
                let pc_values: T = pc_result.unwrap_or_else(|e| {
                    panic!("{}: database query failed due to {:?}", parameter_name, e)
                });
                if cli_values != pc_values {
                    persistent_config_setter(persist_config, cli_string_values).unwrap_or_else(
                        |e| {
                            panic!(
                                "{}: writing database failed due to: {:?}",
                                parameter_name, e
                            )
                        },
                    )
                }
                cli_values
            }
            (_, pc_result) => pc_result.unwrap_or_else(|e| {
                panic!("{}: database query failed due to {:?}", parameter_name, e)
            }),
        },
    )
}

fn get_db_password(
    config: &mut BootstrapperConfig,
    persistent_config: &mut dyn PersistentConfiguration,
) -> Result<Option<String>, ConfiguratorError> {
    if let Some(db_password) = &config.db_password_opt {
        set_db_password_at_first_mention(db_password, persistent_config)?;
        return Ok(Some(db_password.clone()));
    }
    Ok(None)
}

fn set_db_password_at_first_mention(
    db_password: &str,
    persistent_config: &mut dyn PersistentConfiguration,
) -> Result<bool, ConfiguratorError> {
    match persistent_config.check_password(None) {
        Ok(true) => match persistent_config.change_password(None, db_password) {
            Ok(_) => Ok(true),
            Err(e) => Err(e.into_configurator_error("db-password")),
        },
        Ok(false) => Ok(false),
        Err(e) => Err(e.into_configurator_error("db-password")),
    }
}

pub fn has_user_specified(multi_config: &MultiConfig, parameter: &str) -> bool {
    multi_config.occurrences_of(parameter) > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::utils::ThresholdUtils;
    use crate::apps::app_node;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::database::db_initializer::DbInitializationConfig;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::db_config::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::db_config::persistent_configuration::PersistentConfigError::NotPresent;
    use crate::db_config::persistent_configuration::PersistentConfigurationReal;
    use crate::sub_lib::accountant::DEFAULT_PAYMENT_THRESHOLDS;
    use crate::sub_lib::cryptde::{PlainData, PublicKey};
    use crate::sub_lib::neighborhood::{Hops, DEFAULT_RATE_PACK};
    use crate::sub_lib::utils::make_new_multi_config;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::neighborhood_test_utils::MIN_HOPS_FOR_TEST;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::unshared_test_utils::{
        configure_default_persistent_config, default_persistent_config_just_accountant_config,
        make_persistent_config_real_with_config_dao_null, make_simplified_multi_config,
        ACCOUNTANT_CONFIG_PARAMS, MAPPING_PROTOCOL, RATE_PACK, ZERO,
    };
    use crate::test_utils::{main_cryptde, ArgsBuilder};
    use masq_lib::constants::DEFAULT_GAS_PRICE;
    use masq_lib::multi_config::{CommandLineVcl, NameValueVclArg, VclArg, VirtualCommandLine};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::running_test;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn convert_ci_configs_handles_blockchain_mismatch() {
        let multi_config = make_simplified_multi_config([
            "--neighbors",
            "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@12.23.34.45:5678",
            "--chain",
            DEFAULT_CHAIN.rec().literal_identifier,
        ]);

        let result = convert_ci_configs(&multi_config).err().unwrap();

        assert_eq!(
            result,
            ConfiguratorError::required(
                "neighbors",
                &format!("Mismatched chains. You are requiring access to '{identifier}' (masq://{identifier}:<public key>@<node address>) with descriptor belonging to 'eth-ropsten'",identifier = DEFAULT_CHAIN.rec().literal_identifier)
            )
        )
    }

    #[test]
    fn make_neighborhood_config_standard_happy_path() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "standard")
                    .param("--min-hops", "1")
                    .param("--ip", "1.2.3.4")
                    .param(
                        "--neighbors",
                        &format!("masq://{identifier}:mhtjjdMt7Gyoebtb1yiK0hdaUx6j84noHdaAHeDR1S4@1.2.3.4:1234/2345,masq://{identifier}:Si06R3ulkOjJOLw1r2R9GOsY87yuinHU_IHK2FJyGnk@2.3.4.5:3456/4567",identifier = DEFAULT_CHAIN.rec().literal_identifier),
                    )
                    .into(),
            ))]
        ).unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(RATE_PACK),
            &mut BootstrapperConfig::new(),
        );

        let dummy_cryptde = CryptDEReal::new(TEST_DEFAULT_CHAIN);
        assert_eq!(
            result,
            Ok(NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[]),
                    vec![
                        NodeDescriptor::try_from((
                            &dummy_cryptde as &dyn CryptDE,
                            format!("masq://{}:mhtjjdMt7Gyoebtb1yiK0hdaUx6j84noHdaAHeDR1S4@1.2.3.4:1234/2345",DEFAULT_CHAIN.rec().literal_identifier).as_str()
                        ))
                            .unwrap(),
                        NodeDescriptor::try_from((
                            &dummy_cryptde as &dyn CryptDE,
                            format!("masq://{}:Si06R3ulkOjJOLw1r2R9GOsY87yuinHU_IHK2FJyGnk@2.3.4.5:3456/4567",DEFAULT_CHAIN.rec().literal_identifier).as_str()
                        ))
                            .unwrap()
                    ],
                    DEFAULT_RATE_PACK
                ),
                min_hops: Hops::OneHop,
            })
        );
    }

    #[test]
    #[should_panic(expected = "Unable to find min_hops value in database: NotPresent")]
    fn node_panics_if_min_hops_value_does_not_exist_inside_multi_config_or_db() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "standard")
                    .opt("--min-hops")
                    .into(),
            ))],
        )
        .unwrap();
        let mut persistent_config = PersistentConfigurationMock::new()
            .min_hops_result(Err(PersistentConfigError::NotPresent));

        let _result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut persistent_config,
            &mut BootstrapperConfig::new(),
        );
    }

    #[test]
    fn make_neighborhood_config_standard_missing_min_hops() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "standard")
                    .param(
                        "--neighbors",
                        &format!("masq://{identifier}:QmlsbA@1.2.3.4:1234/2345,masq://{identifier}:VGVk@2.3.4.5:3456/4567",identifier = DEFAULT_CHAIN.rec().literal_identifier),
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
            .unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(RATE_PACK),
            &mut BootstrapperConfig::new(),
        );

        let min_hops = result.unwrap().min_hops;
        assert_eq!(min_hops, Hops::ThreeHops);
    }

    #[test]
    fn make_neighborhood_config_standard_uses_default_value_when_no_min_hops_value_is_provided() {
        running_test();
        let args = ArgsBuilder::new()
            .param("--neighborhood-mode", "standard")
            .param(
                "--neighbors",
                &format!("masq://{identifier}:QmlsbA@1.2.3.4:1234/2345,masq://{identifier}:VGVk@2.3.4.5:3456/4567",identifier = DEFAULT_CHAIN.rec().literal_identifier),
            )
            .param("--fake-public-key", "booga")
            .opt("--min-hops");
        let vcl = CommandLineVcl::new(args.into());
        let multi_config = make_new_multi_config(&app_node(), vec![Box::new(vcl)]).unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(RATE_PACK),
            &mut BootstrapperConfig::new(),
        );

        let min_hops = result.unwrap().min_hops;
        assert_eq!(min_hops, Hops::ThreeHops);
    }

    #[test]
    fn make_neighborhood_config_standard_throws_err_when_undesirable_min_hops_value_is_provided() {
        running_test();
        let args = ArgsBuilder::new()
            .param("--neighborhood-mode", "standard")
            .param(
                "--neighbors",
                &format!("masq://{identifier}:QmlsbA@1.2.3.4:1234/2345,masq://{identifier}:VGVk@2.3.4.5:3456/4567",identifier = DEFAULT_CHAIN.rec().literal_identifier),
            )
            .param("--fake-public-key", "booga")
            .param("--min-hops", "100");
        let vcl = CommandLineVcl::new(args.into());

        let result = make_new_multi_config(&app_node(), vec![Box::new(vcl)])
            .err()
            .unwrap();

        assert_eq!(
            result,
            ConfiguratorError::required("min-hops", "Invalid value: '100'")
        );
    }

    #[test]
    fn make_neighborhood_config_standard_missing_ip() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "standard")
                    .param(
                        "--neighbors",
                        &format!("masq://{identifier}:QmlsbA@1.2.3.4:1234/2345,masq://{identifier}:VGVk@2.3.4.5:3456/4567",identifier = DEFAULT_CHAIN.rec().literal_identifier),
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
            .unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(RATE_PACK),
            &mut BootstrapperConfig::new(),
        );

        let node_addr = match result {
            Ok(NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(node_addr, _, _),
                min_hops: Hops::ThreeHops,
            }) => node_addr,
            x => panic!("Wasn't expecting {:?}", x),
        };
        assert_eq!(node_addr.ip_addr(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn make_neighborhood_config_originate_only_doesnt_need_ip() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "originate-only")
                    .param(
                        "--neighbors",
                        &format!("masq://{identifier}:QmlsbA@1.2.3.4:1234/2345,masq://{identifier}:VGVk@2.3.4.5:3456/4567",identifier = DEFAULT_CHAIN.rec().literal_identifier),
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
            .unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(RATE_PACK),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result.unwrap().mode,
            NeighborhoodMode::OriginateOnly(
                vec![
                    NodeDescriptor::try_from((
                        main_cryptde(),
                        format!(
                            "masq://{}:QmlsbA@1.2.3.4:1234/2345",
                            DEFAULT_CHAIN.rec().literal_identifier
                        )
                        .as_str()
                    ))
                    .unwrap(),
                    NodeDescriptor::try_from((
                        main_cryptde(),
                        format!(
                            "masq://{}:VGVk@2.3.4.5:3456/4567",
                            DEFAULT_CHAIN.rec().literal_identifier
                        )
                        .as_str()
                    ))
                    .unwrap()
                ],
                DEFAULT_RATE_PACK
            )
        );
    }

    #[test]
    fn make_neighborhood_config_originate_only_does_need_at_least_one_neighbor() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "originate-only")
                    .into(),
            ))],
        )
        .unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(RATE_PACK).check_password_result(Ok(false)),
            &mut BootstrapperConfig::new(),
        );

        assert_eq! (result, Err(ConfiguratorError::required("neighborhood-mode", "Node cannot run as --neighborhood-mode originate-only without --neighbors specified")))
    }

    #[test]
    fn make_neighborhood_config_consume_only_doesnt_need_ip() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "consume-only")
                    .param(
                        "--neighbors",
                        &format!("masq://{identifier}:QmlsbA@1.2.3.4:1234/2345,masq://{identifier}:VGVk@2.3.4.5:3456/4567",identifier = DEFAULT_CHAIN.rec().literal_identifier),
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
            .unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(ZERO),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result.unwrap().mode,
            NeighborhoodMode::ConsumeOnly(vec![
                NodeDescriptor::try_from((
                    main_cryptde(),
                    format!(
                        "masq://{}:QmlsbA@1.2.3.4:1234/2345",
                        DEFAULT_CHAIN.rec().literal_identifier
                    )
                    .as_str()
                ))
                .unwrap(),
                NodeDescriptor::try_from((
                    main_cryptde(),
                    format!(
                        "masq://{}:VGVk@2.3.4.5:3456/4567",
                        DEFAULT_CHAIN.rec().literal_identifier
                    )
                    .as_str()
                ))
                .unwrap()
            ],),
        );
    }

    #[test]
    fn make_neighborhood_config_consume_only_rejects_dns_servers_and_needs_at_least_one_neighbor() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "consume-only")
                    .param("--dns-servers", "1.1.1.1")
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
        .unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(ZERO),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighborhood-mode",
                "Node cannot run as --neighborhood-mode consume-only without --neighbors specified"
            )
            .another_required(
                "neighborhood-mode",
                "Node cannot run as --neighborhood-mode consume-only if --dns-servers is specified"
            ))
        )
    }

    #[test]
    fn make_neighborhood_config_zero_hop_doesnt_need_ip_or_neighbors() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "zero-hop")
                    .into(),
            ))],
        )
        .unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(ZERO).check_password_result(Ok(false)),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(result.unwrap().mode, NeighborhoodMode::ZeroHop);
    }

    #[test]
    fn make_neighborhood_config_zero_hop_cant_tolerate_ip() {
        running_test();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "zero-hop")
                    .param("--ip", "1.2.3.4")
                    .into(),
            ))],
        )
        .unwrap();

        let result = make_neighborhood_config(
            &UnprivilegedParseArgsConfigurationDaoReal {},
            &multi_config,
            &mut configure_default_persistent_config(ZERO).check_password_result(Ok(false)),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighborhood-mode",
                "Node cannot run as --neighborhood-mode zero-hop if --ip is specified"
            ))
        )
    }

    #[test]
    fn get_past_neighbors_handles_good_password_but_no_past_neighbors_parse_args_configuration_dao_real(
    ) {
        running_test();
        let mut persistent_config =
            configure_default_persistent_config(ZERO).check_password_result(Ok(false));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        let result = subject
            .get_past_neighbors(&mut persistent_config, &mut unprivileged_config)
            .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn get_past_neighbors_handles_non_password_error_for_parse_args_configuration_dao_real() {
        running_test();
        let mut persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(false))
            .past_neighbors_result(Err(PersistentConfigError::NotPresent));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        let result = subject.get_past_neighbors(&mut persistent_config, &mut unprivileged_config);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![ParamError::new(
                "[past neighbors]",
                "NotPresent"
            )]))
        );
    }

    #[test]
    fn get_past_neighbors_handles_unavailable_password_for_parse_args_configuration_dao_real() {
        //sets the password in the database - we'll have to resolve if the use case is appropriate
        running_test();
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .check_password_result(Ok(true))
            .change_password_result(Ok(()));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        let result = subject
            .get_past_neighbors(&mut persistent_config, &mut unprivileged_config)
            .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn get_past_neighbors_does_nothing_for_parse_args_configuration_dao_null() {
        //slightly adapted aside reality; we would've been using PersistentConfigurationReal
        //with ConfigDaoNull but it wouldn't have necessarily panicked if its method called so we use PersistentConfigMock
        //which can provide us with a reaction like so
        running_test();
        let mut persistent_config = PersistentConfigurationMock::new();
        let mut unprivileged_config = BootstrapperConfig::new();
        let subject = UnprivilegedParseArgsConfigurationDaoNull {};

        let result = subject.get_past_neighbors(&mut persistent_config, &mut unprivileged_config);

        assert_eq!(result, Ok(vec![]));
        //Nothing panicked so we could not call real persistent config's methods.
    }

    #[test]
    fn set_db_password_at_first_mention_handles_existing_password() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(false));

        let result = set_db_password_at_first_mention("password", &mut persistent_config);

        assert_eq!(result, Ok(false));
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(*check_password_params, vec![None])
    }

    #[test]
    fn set_db_password_at_first_mention_sets_password_correctly() {
        let change_password_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .check_password_result(Ok(true))
            .change_password_params(&change_password_params_arc)
            .change_password_result(Ok(()));

        let result = set_db_password_at_first_mention("password", &mut persistent_config);

        assert_eq!(result, Ok(true));
        let change_password_params = change_password_params_arc.lock().unwrap();
        assert_eq!(
            *change_password_params,
            vec![(None, "password".to_string())]
        )
    }

    #[test]
    fn set_db_password_at_first_mention_handles_password_check_error() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .check_password_params(&check_password_params_arc)
            .check_password_result(Err(PersistentConfigError::NotPresent));

        let result = set_db_password_at_first_mention("password", &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("db-password"))
        );
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(*check_password_params, vec![None])
    }

    #[test]
    fn set_db_password_at_first_mention_handles_password_set_error() {
        let change_password_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .check_password_result(Ok(true))
            .change_password_params(&change_password_params_arc)
            .change_password_result(Err(PersistentConfigError::NotPresent));

        let result = set_db_password_at_first_mention("password", &mut persistent_config);

        assert_eq!(
            result,
            Err(NotPresent.into_configurator_error("db-password"))
        );
        let change_password_params = change_password_params_arc.lock().unwrap();
        assert_eq!(
            *change_password_params,
            vec![(None, "password".to_string())]
        )
    }

    #[test]
    fn get_db_password_if_supplied() {
        running_test();
        let mut config = BootstrapperConfig::new();
        let mut persistent_config =
            configure_default_persistent_config(ZERO).check_password_result(Ok(false));
        config.db_password_opt = Some("password".to_string());

        let result = get_db_password(&mut config, &mut persistent_config);

        assert_eq!(result, Ok(Some("password".to_string())));
    }

    #[test]
    fn get_db_password_doesnt_bother_if_database_has_no_password_yet() {
        running_test();
        let mut config = BootstrapperConfig::new();
        let mut persistent_config =
            configure_default_persistent_config(ZERO).check_password_result(Ok(true));

        let result = get_db_password(&mut config, &mut persistent_config);

        assert_eq!(result, Ok(None));
    }

    #[test]
    fn get_db_password_handles_database_write_error() {
        running_test();
        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .check_password_result(Ok(true))
            .change_password_result(Err(PersistentConfigError::NotPresent));

        let result = get_db_password(&mut config, &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("db-password"))
        );
    }

    #[test]
    fn convert_ci_configs_handles_leftover_whitespaces_between_descriptors_and_commas() {
        let multi_config = make_simplified_multi_config([
            "--chain",
            "eth-ropsten",
            "--fake-public-key",
            "ABCDE",
            "--neighbors",
            "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@1.2.3.4:5555, masq://eth-ropsten:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542 , masq://eth-ropsten:A6PGHT3rRjaeFpD_rFi3qGEXAVPq7bJDfEUZpZaIyq8@14.10.50.6:10504",
        ]);
        let public_key = PublicKey::new(b"ABCDE");
        let cryptde = CryptDENull::from(&public_key, Chain::EthRopsten);
        let cryptde_traitified = &cryptde as &dyn CryptDE;

        let result = convert_ci_configs(&multi_config);

        assert_eq!(result, Ok(Some(
            vec![
                NodeDescriptor::try_from((cryptde_traitified, "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@1.2.3.4:5555")).unwrap(),
                NodeDescriptor::try_from((cryptde_traitified, "masq://eth-ropsten:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542")).unwrap(),
                NodeDescriptor::try_from((cryptde_traitified, "masq://eth-ropsten:A6PGHT3rRjaeFpD_rFi3qGEXAVPq7bJDfEUZpZaIyq8@14.10.50.6:10504")).unwrap()])
            )
        )
    }

    #[test]
    fn convert_ci_configs_does_not_like_neighbors_with_bad_syntax() {
        running_test();
        let multi_config = make_simplified_multi_config(["--neighbors", "ooga,booga"]);

        let result = convert_ci_configs(&multi_config).err();

        assert_eq!(
            result,
            Some(ConfiguratorError::new(vec![
                ParamError::new(
                    "neighbors",
                    "Prefix or more missing. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'ooga'"
                ),
                ParamError::new(
                    "neighbors",
                    "Prefix or more missing. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'booga'"
                ),
            ]))
        );
    }

    #[test]
    fn convert_ci_configs_complains_about_descriptor_without_node_address_when_mainnet_required() {
        let descriptor = format!(
            "masq://{}:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@:",
            DEFAULT_CHAIN.rec().literal_identifier
        );
        let multi_config = make_simplified_multi_config(["--neighbors", &descriptor]);

        let result = convert_ci_configs(&multi_config);

        assert_eq!(result,Err(ConfiguratorError::new(vec![ParamError::new("neighbors", &format!("Neighbors supplied without ip addresses and ports are not valid: '{}<N/A>:<N/A>",&descriptor[..descriptor.len()-1]))])));
    }

    #[test]
    fn convert_ci_configs_complains_about_descriptor_without_node_address_when_test_chain_required()
    {
        let multi_config = make_simplified_multi_config([
            "--chain",
            "eth-ropsten",
            "--neighbors",
            "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@:",
        ]);

        let result = convert_ci_configs(&multi_config);

        assert_eq!(result,Err(ConfiguratorError::new(vec![ParamError::new("neighbors", "Neighbors supplied without ip addresses and ports are not valid: 'masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@<N/A>:<N/A>")])))
    }

    #[test]
    fn configure_zero_hop_with_neighbors_supplied() {
        running_test();
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let mut config = BootstrapperConfig::new();
        let mut persistent_config = configure_default_persistent_config(
            RATE_PACK | ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL,
        )
        .set_past_neighbors_params(&set_past_neighbors_params_arc)
        .set_past_neighbors_result(Ok(()));
        let multi_config = make_simplified_multi_config([
            "--chain",
            "eth-ropsten",
            "--neighbors",
            "masq://eth-ropsten:UJNoZW5p-PDVqEjpr3b_8jZ_93yPG8i5dOAgE1bhK_A@2.3.4.5:2345",
            "--db-password",
            "password",
            "--neighborhood-mode",
            "zero-hop",
            "--fake-public-key",
            "booga",
        ]);
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        let _ = subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(config.neighborhood_config.mode, NeighborhoodMode::ZeroHop);
        let set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        assert_eq!(
            *set_past_neighbors_params,
            vec![(
                Some(vec![NodeDescriptor::try_from((
                    main_cryptde(),
                    "masq://eth-ropsten:UJNoZW5p-PDVqEjpr3b_8jZ_93yPG8i5dOAgE1bhK_A@2.3.4.5:2345"
                ))
                .unwrap()]),
                "password".to_string()
            )]
        )
    }

    #[test]
    fn setting_zero_hop_neighbors_is_ignored_if_no_neighbors_supplied() {
        running_test();
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let mut config = BootstrapperConfig::new();
        let mut persistent_config = configure_default_persistent_config(
            RATE_PACK | ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL,
        )
        .set_past_neighbors_params(&set_past_neighbors_params_arc);
        let multi_config = make_simplified_multi_config([
            "--chain",
            "eth-ropsten",
            "--neighborhood-mode",
            "zero-hop",
        ]);
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        let _ = subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(config.neighborhood_config.mode, NeighborhoodMode::ZeroHop);
        let set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        assert!(set_past_neighbors_params.is_empty())
    }

    #[test]
    fn configure_zero_hop_with_neighbors_but_no_password() {
        running_test();
        let mut persistent_config = PersistentConfigurationMock::new();
        //no results prepared for set_past_neighbors() and no panic so it was not called
        let descriptor_list = vec![NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:UJNoZW5p-PDVqEjpr3b_8jZ_93yPG8i5dOAgE1bhK_A@2.3.4.5:2345",
        ))
        .unwrap()];

        let result =
            zero_hop_neighbors_configuration(None, descriptor_list, &mut persistent_config);

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighbors",
                "Cannot proceed without a password"
            ))
        );
    }

    #[test]
    fn configure_zero_hop_with_neighbors_but_setting_values_failed() {
        running_test();
        let mut persistent_config = PersistentConfigurationMock::new().set_past_neighbors_result(
            Err(PersistentConfigError::DatabaseError("Oh yeah".to_string())),
        );
        let descriptor_list = vec![NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:UJNoZW5p-PDVqEjpr3b_8jZ_93yPG8i5dOAgE1bhK_A@2.3.4.5:2345",
        ))
        .unwrap()];

        let result = zero_hop_neighbors_configuration(
            Some("password".to_string()),
            descriptor_list,
            &mut persistent_config,
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighbors",
                "DatabaseError(\"Oh yeah\")"
            ))
        );
    }

    #[test]
    fn unprivileged_parse_args_dao_real_creates_configurations() {
        let home_dir = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "unprivileged_parse_args_dao_real_creates_configurations",
        );
        assert_unprivileged_parse_args_creates_configurations(
            home_dir,
            &UnprivilegedParseArgsConfigurationDaoReal {},
        )
    }

    #[test]
    fn unprivileged_parse_args_dao_null_creates_configurations() {
        let home_dir = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "unprivileged_parse_args_dao_null_creates_configurations",
        );
        assert_unprivileged_parse_args_creates_configurations(
            home_dir,
            &UnprivilegedParseArgsConfigurationDaoNull {},
        )
    }

    fn assert_unprivileged_parse_args_creates_configurations(
        home_dir: PathBuf,
        subject: &dyn UnprivilegedParseArgsConfiguration,
    ) {
        running_test();
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir.clone(), DbInitializationConfig::test_default())
                .unwrap(),
        ));
        let consuming_private_key_text =
            "ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01";
        let consuming_private_key = PlainData::from_str(consuming_private_key_text).unwrap();
        let mut persistent_config = PersistentConfigurationReal::new(config_dao);
        let password = "secret-db-password";
        let args = ArgsBuilder::new()
            .param("--config-file", "specified_config.toml")
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
            .param(
                "--neighbors",
                &format!("masq://{identifier}:QmlsbA@1.2.3.4:1234/2345,masq://{identifier}:VGVk@2.3.4.5:3456/4567",identifier = DEFAULT_CHAIN.rec().literal_identifier),
            )
            .param("--ip", "34.56.78.90")
            .param("--clandestine-port", "1234")
            .param("--ui-port", "5335")
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--blockchain-service-url", "http://127.0.0.1:8545")
            .param("--log-level", "trace")
            .param("--fake-public-key", "AQIDBA")
            .param("--db-password", password)
            .param(
                "--earning-wallet",
                "0x0123456789012345678901234567890123456789",
            )
            .param("--consuming-private-key", consuming_private_key_text)
            .param("--mapping-protocol", "pcp")
            .param("--real-user", "999:999:/home/booga");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test logger"),
            )
            .unwrap();

        assert_eq!(
            value_m!(multi_config, "config-file", PathBuf),
            Some(PathBuf::from("specified_config.toml")),
        );
        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url_opt,
            Some("http://127.0.0.1:8545".to_string())
        );
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap()
        );
        assert_eq!(Some(1234u16), config.clandestine_port_opt);
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap()
        );
        assert_eq!(
            config.consuming_wallet_opt,
            Some(Wallet::from(
                Bip32EncryptionKeyProvider::from_raw_secret(consuming_private_key.as_slice())
                    .unwrap()
            )),
        );
        assert_eq!(
            config.neighborhood_config.mode,
            NeighborhoodMode::Standard(
                NodeAddr::new(&IpAddr::from_str("34.56.78.90").unwrap(), &[]),
                vec![
                    NodeDescriptor::try_from((
                        main_cryptde(),
                        format!(
                            "masq://{}:QmlsbA@1.2.3.4:1234/2345",
                            DEFAULT_CHAIN.rec().literal_identifier
                        )
                        .as_str()
                    ))
                    .unwrap(),
                    NodeDescriptor::try_from((
                        main_cryptde(),
                        format!(
                            "masq://{}:VGVk@2.3.4.5:3456/4567",
                            DEFAULT_CHAIN.rec().literal_identifier
                        )
                        .as_str()
                    ))
                    .unwrap(),
                ],
                DEFAULT_RATE_PACK.clone()
            )
        );
        assert_eq!(config.db_password_opt, Some(password.to_string()));
        assert_eq!(config.mapping_protocol_opt, Some(AutomapProtocol::Pcp));
    }

    #[test]
    fn unprivileged_parse_args_creates_configuration_with_defaults() {
        running_test();
        let args = ArgsBuilder::new();
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();
        let mut persistent_config = configure_default_persistent_config(
            RATE_PACK | ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL,
        )
        .check_password_result(Ok(false));
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test logger"),
            )
            .unwrap();

        assert_eq!(None, config.clandestine_port_opt);
        assert!(config
            .neighborhood_config
            .mode
            .neighbor_configs()
            .is_empty());
        assert_eq!(
            config
                .neighborhood_config
                .mode
                .node_addr_opt()
                .unwrap()
                .ip_addr(),
            IpAddr::from_str("0.0.0.0").unwrap(),
        );
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone(),);
        assert_eq!(config.consuming_wallet_opt, None);
        assert_eq!(config.mapping_protocol_opt, None);
    }

    #[test]
    fn unprivileged_parse_args_with_neighbor_and_mapping_protocol_in_database_but_not_command_line()
    {
        running_test();
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--fake-public-key", "BORSCHT")
            .param("--db-password", "password");
        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_configuration = {
            let config = make_persistent_config(
                Some("password"),
                None,
                None,
                None,
                Some(
                    "masq://eth-ropsten:AQIDBA@1.2.3.4:1234,masq://eth-ropsten:AgMEBQ@2.3.4.5:2345",
                ),
                None,
                None,
            )
            .check_password_result(Ok(false))
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .past_neighbors_params(&past_neighbors_params_arc)
            .blockchain_service_url_result(Ok(None));
            default_persistent_config_just_accountant_config(config)
        };
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test logger"),
            )
            .unwrap();

        assert_eq!(
            config.neighborhood_config.mode.neighbor_configs(),
            &[
                NodeDescriptor::try_from((
                    main_cryptde(),
                    "masq://eth-ropsten:AQIDBA@1.2.3.4:1234"
                ))
                .unwrap(),
                NodeDescriptor::try_from((
                    main_cryptde(),
                    "masq://eth-ropsten:AgMEBQ@2.3.4.5:2345"
                ))
                .unwrap(),
            ]
        );
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(past_neighbors_params[0], "password".to_string());
        assert_eq!(config.mapping_protocol_opt, Some(AutomapProtocol::Pcp));
        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(*set_mapping_protocol_params, vec![]);
    }

    #[test]
    fn unprivileged_parse_args_with_blockchain_service_in_database_but_not_command_line() {
        running_test();
        let args = ArgsBuilder::new().param("--neighborhood-mode", "zero-hop");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();
        let mut persistent_configuration = {
            let config = make_persistent_config(None, None, None, None, None, None, None)
                .blockchain_service_url_result(Ok(Some("https://infura.io/ID".to_string())));
            default_persistent_config_just_accountant_config(config)
        };
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url_opt,
            Some("https://infura.io/ID".to_string())
        );
    }

    #[test]
    fn unprivileged_parse_args_with_mapping_protocol_both_on_command_line_and_in_database() {
        running_test();
        let args = ArgsBuilder::new().param("--mapping-protocol", "pmp");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(0b0000_1101)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pcp)))
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .set_mapping_protocol_result(Ok(()));
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test logger"),
            )
            .unwrap();

        assert_eq!(config.mapping_protocol_opt, Some(AutomapProtocol::Pmp));
        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(
            *set_mapping_protocol_params,
            vec![Some(AutomapProtocol::Pmp)]
        );
    }

    #[test]
    fn unprivileged_parse_args_consuming_private_key_happy_path() {
        running_test();
        let home_directory = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "parse_args_consuming_private_key_happy_path",
        );

        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--data-directory", home_directory.to_str().unwrap())
            .opt("--db-password");
        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming-private-key",
            &"cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ))];

        let faux_environment = CommandLineVcl::from(vcl_args);

        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(faux_environment),
            Box::new(CommandLineVcl::new(args.into())),
        ];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut configure_default_persistent_config(
                    RATE_PACK | MAPPING_PROTOCOL | ACCOUNTANT_CONFIG_PARAMS,
                ),
                &Logger::new("test logger"),
            )
            .unwrap();

        assert!(config.consuming_wallet_opt.is_some());
        assert_eq!(
            format!("{}", config.consuming_wallet_opt.unwrap()),
            "0x8e4d2317e56c8fd1fc9f13ba2aa62df1c5a542a7".to_string()
        );
    }

    #[test]
    fn unprivileged_parse_args_accountant_config_with_combined_params_from_command_line_different_from_database(
    ) {
        running_test();
        let set_scan_intervals_params_arc = Arc::new(Mutex::new(vec![]));
        let set_payment_thresholds_params_arc = Arc::new(Mutex::new(vec![]));
        let args = [
            "--ip",
            "1.2.3.4",
            "--scan-intervals",
            "180|150|130",
            "--payment-thresholds",
            "100000|10000|1000|20000|1000|20000",
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_configuration =
            configure_default_persistent_config(RATE_PACK | MAPPING_PROTOCOL)
                .scan_intervals_result(Ok(ScanIntervals {
                    pending_payable_scan_interval: Duration::from_secs(100),
                    payable_scan_interval: Duration::from_secs(101),
                    receivable_scan_interval: Duration::from_secs(102),
                }))
                .payment_thresholds_result(Ok(PaymentThresholds {
                    threshold_interval_sec: 3000,
                    debt_threshold_gwei: 30000,
                    payment_grace_period_sec: 3000,
                    maturity_threshold_sec: 30000,
                    permanent_debt_allowed_gwei: 30000,
                    unban_below_gwei: 30000,
                }))
                .set_scan_intervals_params(&set_scan_intervals_params_arc)
                .set_scan_intervals_result(Ok(()))
                .set_payment_thresholds_params(&set_payment_thresholds_params_arc)
                .set_payment_thresholds_result(Ok(()));
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        let expected_scan_intervals = ScanIntervals {
            pending_payable_scan_interval: Duration::from_secs(180),
            payable_scan_interval: Duration::from_secs(150),
            receivable_scan_interval: Duration::from_secs(130),
        };
        let expected_payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 1000,
            debt_threshold_gwei: 100000,
            payment_grace_period_sec: 1000,
            maturity_threshold_sec: 10000,
            permanent_debt_allowed_gwei: 20000,
            unban_below_gwei: 20000,
        };
        assert_eq!(
            config.payment_thresholds_opt,
            Some(expected_payment_thresholds)
        );
        assert_eq!(config.scan_intervals_opt, Some(expected_scan_intervals));
        assert_eq!(config.suppress_initial_scans, false);
        assert_eq!(
            config.when_pending_too_long_sec,
            DEFAULT_PENDING_TOO_LONG_SEC
        );
        let set_scan_intervals_params = set_scan_intervals_params_arc.lock().unwrap();
        assert_eq!(*set_scan_intervals_params, vec!["180|150|130".to_string()]);
        let set_payment_thresholds_params = set_payment_thresholds_params_arc.lock().unwrap();
        assert_eq!(
            *set_payment_thresholds_params,
            vec!["100000|10000|1000|20000|1000|20000".to_string()]
        )
    }

    #[test]
    fn unprivileged_parse_args_configures_accountant_config_with_values_from_command_line_which_are_equal_to_those_in_database(
    ) {
        running_test();
        let args = [
            "--ip",
            "1.2.3.4",
            "--scan-intervals",
            "180|150|130",
            "--payment-thresholds",
            "100000|1000|1000|20000|1000|20000",
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_configuration =
            configure_default_persistent_config(RATE_PACK | MAPPING_PROTOCOL)
                .scan_intervals_result(Ok(ScanIntervals {
                    pending_payable_scan_interval: Duration::from_secs(180),
                    payable_scan_interval: Duration::from_secs(150),
                    receivable_scan_interval: Duration::from_secs(130),
                }))
                .payment_thresholds_result(Ok(PaymentThresholds {
                    threshold_interval_sec: 1000,
                    debt_threshold_gwei: 100000,
                    payment_grace_period_sec: 1000,
                    maturity_threshold_sec: 1000,
                    permanent_debt_allowed_gwei: 20000,
                    unban_below_gwei: 20000,
                }));
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        let expected_payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 1000,
            debt_threshold_gwei: 100000,
            payment_grace_period_sec: 1000,
            maturity_threshold_sec: 1000,
            permanent_debt_allowed_gwei: 20000,
            unban_below_gwei: 20000,
        };
        let expected_scan_intervals = ScanIntervals {
            pending_payable_scan_interval: Duration::from_secs(180),
            payable_scan_interval: Duration::from_secs(150),
            receivable_scan_interval: Duration::from_secs(130),
        };
        let expected_suppress_initial_scans = false;
        let expected_when_pending_too_long_sec = DEFAULT_PENDING_TOO_LONG_SEC;
        assert_eq!(
            config.payment_thresholds_opt,
            Some(expected_payment_thresholds)
        );
        assert_eq!(config.scan_intervals_opt, Some(expected_scan_intervals));
        assert_eq!(
            config.suppress_initial_scans,
            expected_suppress_initial_scans
        );
        assert_eq!(
            config.when_pending_too_long_sec,
            expected_when_pending_too_long_sec
        );
        //no prepared results for the setter methods, that is they were uncalled
    }

    #[test]
    fn unprivileged_parse_args_rate_pack_values_from_cli_different_from_database_standard_mode() {
        running_test();
        let set_rate_pack_params_arc = Arc::new(Mutex::new(vec![]));
        let args = [
            "--ip",
            "1.2.3.4",
            "--neighborhood-mode",
            "standard",
            "--rate-pack",
            "2|3|4|5",
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_configuration =
            configure_default_persistent_config(MAPPING_PROTOCOL | ACCOUNTANT_CONFIG_PARAMS)
                .rate_pack_result(Ok(RatePack {
                    routing_byte_rate: 3,
                    routing_service_rate: 5,
                    exit_byte_rate: 4,
                    exit_service_rate: 7,
                }))
                .set_rate_pack_result(Ok(()))
                .set_rate_pack_params(&set_rate_pack_params_arc);
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        let actual_rate_pack = *config.neighborhood_config.mode.rate_pack();
        let expected_rate_pack = RatePack {
            routing_byte_rate: 2,
            routing_service_rate: 3,
            exit_byte_rate: 4,
            exit_service_rate: 5,
        };
        assert_eq!(actual_rate_pack, expected_rate_pack);
        let set_rate_pack_params = set_rate_pack_params_arc.lock().unwrap();
        assert_eq!(*set_rate_pack_params, vec!["2|3|4|5".to_string()])
    }

    #[test]
    fn unprivileged_parse_args_rate_pack_with_values_from_cli_equal_to_database_standard_mode() {
        running_test();
        let args = [
            "--ip",
            "1.2.3.4",
            "--neighborhood-mode",
            "standard",
            "--rate-pack",
            "6|7|8|9",
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_configuration =
            configure_default_persistent_config(ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL)
                .rate_pack_result(Ok(RatePack {
                    routing_byte_rate: 6,
                    routing_service_rate: 7,
                    exit_byte_rate: 8,
                    exit_service_rate: 9,
                }));
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(config.neighborhood_config.mode.is_standard(), true);
        let actual_rate_pack = *config.neighborhood_config.mode.rate_pack();
        let expected_rate_pack = RatePack {
            routing_byte_rate: 6,
            routing_service_rate: 7,
            exit_byte_rate: 8,
            exit_service_rate: 9,
        };
        assert_eq!(actual_rate_pack, expected_rate_pack);
        //no prepared results for the setter methods, that is they were uncalled
    }

    #[test]
    fn unprivileged_parse_args_rate_pack_with_values_from_cli_equal_to_database_originate_only_mode(
    ) {
        running_test();
        let args = [
            "--ip",
            "1.2.3.4",
            "--chain",
            "polygon-mainnet",
            "--neighborhood-mode",
            "originate-only",
            "--rate-pack",
            "2|3|4|5",
            "--neighbors",
            "masq://polygon-mainnet:d2U3Dv1BqtS5t_Zz3mt9_sCl7AgxUlnkB4jOMElylrU@172.50.48.6:9342",
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_configuration =
            configure_default_persistent_config(ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL)
                .rate_pack_result(Ok(RatePack {
                    routing_byte_rate: 2,
                    routing_service_rate: 3,
                    exit_byte_rate: 4,
                    exit_service_rate: 5,
                }));
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(config.neighborhood_config.mode.is_originate_only(), true);
        let actual_rate_pack = *config.neighborhood_config.mode.rate_pack();
        let expected_rate_pack = RatePack {
            routing_byte_rate: 2,
            routing_service_rate: 3,
            exit_byte_rate: 4,
            exit_service_rate: 5,
        };
        assert_eq!(actual_rate_pack, expected_rate_pack);
        //no prepared results for the setter methods, that is they're uncalled
    }

    #[test]
    fn configure_accountant_config_discovers_invalid_payment_thresholds_params_combination_given_from_users_input(
    ) {
        let multi_config = make_simplified_multi_config([
            "--payment-thresholds",
            "19999|10000|1000|20000|1000|20000",
        ]);
        let mut bootstrapper_config = BootstrapperConfig::new();
        let mut persistent_config =
            configure_default_persistent_config(ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL)
                .set_payment_thresholds_result(Ok(()));

        let result = configure_accountant_config(
            &multi_config,
            &mut bootstrapper_config,
            &mut persistent_config,
        );

        let expected_msg = "Value of DebtThresholdGwei (19999) must be bigger than PermanentDebtAllowedGwei (20000)";
        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "payment-thresholds",
                expected_msg
            ))
        )
    }

    #[test]
    fn check_payment_thresholds_works_for_equal_debt_parameters() {
        let mut payment_thresholds = *DEFAULT_PAYMENT_THRESHOLDS;
        payment_thresholds.permanent_debt_allowed_gwei = 10000;
        payment_thresholds.debt_threshold_gwei = 10000;

        let result = check_payment_thresholds(&payment_thresholds);

        let expected_msg = "Value of DebtThresholdGwei (10000) must be bigger than PermanentDebtAllowedGwei (10000)";
        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "payment-thresholds",
                expected_msg
            ))
        )
    }

    #[test]
    fn check_payment_thresholds_works_for_too_small_debt_threshold() {
        let mut payment_thresholds = *DEFAULT_PAYMENT_THRESHOLDS;
        payment_thresholds.permanent_debt_allowed_gwei = 10000;
        payment_thresholds.debt_threshold_gwei = 9999;

        let result = check_payment_thresholds(&payment_thresholds);

        let expected_msg = "Value of DebtThresholdGwei (9999) must be bigger than PermanentDebtAllowedGwei (10000)";
        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "payment-thresholds",
                expected_msg
            ))
        )
    }

    #[test]
    fn check_payment_thresholds_does_not_permit_threshold_interval_longer_than_1_000_000_000_s() {
        //this goes to the furthest extreme where the delta of debt limits is just 1 gwei, which,
        //if divided by the slope interval equal or longer 10^9 and rounded, gives 0
        let mut payment_thresholds = *DEFAULT_PAYMENT_THRESHOLDS;
        payment_thresholds.permanent_debt_allowed_gwei = 100;
        payment_thresholds.debt_threshold_gwei = 101;
        payment_thresholds.threshold_interval_sec = 1_000_000_001;

        let result = check_payment_thresholds(&payment_thresholds);

        let expected_msg = "Value of ThresholdIntervalSec must not exceed 1,000,000,000 s";
        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "payment-thresholds",
                expected_msg
            ))
        );
        payment_thresholds.threshold_interval_sec -= 1;
        let last_value_possible = ThresholdUtils::slope(&payment_thresholds);
        assert_eq!(last_value_possible, -1)
    }

    #[test]
    fn unprivileged_parse_args_with_invalid_consuming_wallet_private_key_reacts_correctly() {
        running_test();
        let home_directory = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "parse_args_with_invalid_consuming_wallet_private_key_panics_correctly",
        );
        let args = ArgsBuilder::new().param("--data-directory", home_directory.to_str().unwrap());
        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming-private-key",
            &"not valid hex",
        ))];
        let faux_environment = CommandLineVcl::from(vcl_args);
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(faux_environment),
            Box::new(CommandLineVcl::new(args.into())),
        ];

        let result = make_new_multi_config(&app_node(), vcls).err().unwrap();

        assert_eq!(
            result,
            ConfiguratorError::required("consuming-private-key", "Invalid value: not valid hex")
        )
    }

    fn execute_process_combined_params_for_rate_pack(
        multi_config: &MultiConfig,
        persist_config: &mut dyn PersistentConfiguration,
    ) -> Result<RatePack, ConfiguratorError> {
        process_combined_params(
            "rate-pack",
            multi_config,
            persist_config,
            |str: &str| RatePack::try_from(str),
            |pc: &dyn PersistentConfiguration| pc.rate_pack(),
            |pc: &mut dyn PersistentConfiguration, rate_pack| pc.set_rate_pack(rate_pack),
        )
    }

    #[test]
    fn process_combined_params_handles_parse_error() {
        let multi_config = make_simplified_multi_config(["--rate-pack", "8|9"]);
        let mut persist_config =
            PersistentConfigurationMock::default().rate_pack_result(Ok(DEFAULT_RATE_PACK));

        let result =
            execute_process_combined_params_for_rate_pack(&multi_config, &mut persist_config);

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "rate-pack",
                "Wrong number of values: expected 4 but 2 supplied"
            ))
        )
    }

    #[test]
    #[should_panic(expected = "rate-pack: database query failed due to NotPresent")]
    fn process_combined_params_panics_on_persistent_config_getter_method_with_cli_present() {
        let multi_config = make_simplified_multi_config(["--rate-pack", "4|5|6|7"]);
        let mut persist_config = PersistentConfigurationMock::default()
            .rate_pack_result(Err(PersistentConfigError::NotPresent));

        let _ = execute_process_combined_params_for_rate_pack(&multi_config, &mut persist_config);
    }

    #[test]
    #[should_panic(expected = "rate-pack: writing database failed due to: TransactionError")]
    fn process_combined_params_panics_on_persistent_config_setter_method_with_cli_present() {
        let multi_config = make_simplified_multi_config(["--rate-pack", "4|5|6|7"]);
        let mut persist_config = PersistentConfigurationMock::default()
            .rate_pack_result(Ok(RatePack::try_from("1|1|2|2").unwrap()))
            .set_rate_pack_result(Err(PersistentConfigError::TransactionError));

        let _ = execute_process_combined_params_for_rate_pack(&multi_config, &mut persist_config);
    }

    #[test]
    #[should_panic(expected = "rate-pack: database query failed due to NotPresent")]
    fn process_combined_params_panics_on_persistent_config_getter_method_with_cli_absent() {
        let multi_config = make_simplified_multi_config([]);
        let mut persist_config = PersistentConfigurationMock::default()
            .rate_pack_result(Err(PersistentConfigError::NotPresent));

        let _ = execute_process_combined_params_for_rate_pack(&multi_config, &mut persist_config);
    }

    #[test]
    fn get_wallets_with_brand_new_database_establishes_default_earning_wallet_without_requiring_password(
    ) {
        running_test();
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config =
            make_persistent_config(None, None, None, None, None, None, None);
        let mut config = BootstrapperConfig::new();

        get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        assert_eq!(config.consuming_wallet_opt, None);
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone());
    }

    #[test]
    fn get_wallets_handles_failure_of_consuming_wallet_private_key() {
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(Ok(None))
            .consuming_wallet_private_key_result(Err(PersistentConfigError::NotPresent));
        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());

        let result = get_wallets(&multi_config, &mut persistent_config, &mut config);

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("consuming-private-key"))
        );
    }

    #[test]
    fn earning_wallet_address_different_from_database() {
        running_test();
        let args = [
            "--earning-wallet",
            "0x0123456789012345678901234567890123456789",
        ];
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config(
            None,
            None,
            Some("0x9876543210987654321098765432109876543210"),
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        let result = get_wallets(&multi_config, &mut persistent_config, &mut config).err();

        assert_eq! (result, Some (ConfiguratorError::new (vec![
            ParamError::new ("earning-wallet", "Cannot change to an address (0x0123456789012345678901234567890123456789) different from that previously set (0x9876543210987654321098765432109876543210)")
        ])));
    }

    #[test]
    fn earning_wallet_address_matches_database() {
        running_test();
        let args = [
            "--earning-wallet",
            "0xb00fa567890123456789012345678901234B00FA",
        ];
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config(
            None,
            None,
            Some("0xB00FA567890123456789012345678901234b00fa"),
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        assert_eq!(
            config.earning_wallet,
            Wallet::new("0xb00fa567890123456789012345678901234b00fa")
        );
    }

    #[test]
    fn consuming_wallet_private_key_different_from_database() {
        running_test();
        let consuming_private_key_hex =
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD";
        let args = ["--consuming-private-key", consuming_private_key_hex];
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config(
            Some("password"),
            Some("DCBADCBADCBADCBADCBADCBADCBADCBADCBADCBADCBADCBADCBADCBADCBADCBA"),
            Some("0x0123456789012345678901234567890123456789"),
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());

        let result = get_wallets(&multi_config, &mut persistent_config, &mut config).err();

        assert_eq!(
            result,
            Some(ConfiguratorError::new(vec![ParamError::new(
                "consuming-private-key",
                "Cannot change to a private key different from that previously set"
            )]))
        )
    }

    #[test]
    fn consuming_wallet_private_key_with_no_db_password_parameter() {
        running_test();
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config = make_persistent_config(
            None,
            Some("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
            None,
            None,
            None,
        )
        .check_password_result(Ok(false));
        let mut config = BootstrapperConfig::new();

        get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        assert_eq!(config.consuming_wallet_opt, None);
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap()
        );
    }

    #[test]
    fn configure_rate_pack_command_line_absent_config_dao_null_so_all_defaults() {
        running_test();
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config = make_persistent_config_real_with_config_dao_null();

        let result = configure_rate_pack(&multi_config, &mut persistent_config).unwrap();

        let expected_rate_pack = RatePack {
            routing_byte_rate: DEFAULT_RATE_PACK.routing_byte_rate,
            routing_service_rate: DEFAULT_RATE_PACK.routing_service_rate,
            exit_byte_rate: DEFAULT_RATE_PACK.exit_byte_rate,
            exit_service_rate: DEFAULT_RATE_PACK.exit_service_rate,
        };
        assert_eq!(result, expected_rate_pack)
    }

    #[test]
    fn compute_mapping_protocol_returns_saved_value_if_nothing_supplied() {
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(ArgsBuilder::new().into()))],
        )
        .unwrap();
        let logger = Logger::new("test");
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pmp)));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, Some(AutomapProtocol::Pmp));
        // No result provided for .set_mapping_protocol; if it's called, the panic will fail this test
    }

    #[test]
    fn compute_mapping_protocol_saves_computed_value_if_different() {
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--mapping-protocol", "IGDP")
                    .into(),
            ))],
        )
        .unwrap();
        let logger = Logger::new("test");
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pmp)))
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .set_mapping_protocol_result(Ok(()));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, Some(AutomapProtocol::Igdp));
        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(
            *set_mapping_protocol_params,
            vec![Some(AutomapProtocol::Igdp)]
        );
    }

    #[test]
    fn compute_mapping_protocol_blanks_database_if_command_line_with_missing_value() {
        let multi_config = make_simplified_multi_config(["--mapping-protocol"]);
        let logger = Logger::new("test");
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pmp)))
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .set_mapping_protocol_result(Ok(()));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, None);
        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(*set_mapping_protocol_params, vec![None]);
    }

    #[test]
    fn compute_mapping_protocol_does_not_resave_entry_if_no_change() {
        let multi_config = make_simplified_multi_config(["--mapping-protocol", "igdp"]);
        let logger = Logger::new("test");
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Igdp)));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, Some(AutomapProtocol::Igdp));
        // No result provided for .set_mapping_protocol; if it's called, the panic will fail this test
    }

    #[test]
    fn compute_mapping_protocol_logs_and_uses_none_if_saved_mapping_protocol_cannot_be_read() {
        init_test_logging();
        let multi_config = make_simplified_multi_config([]);
        let logger = Logger::new("BAD_MP_READ");
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .mapping_protocol_result(Err(PersistentConfigError::NotPresent));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, None);
        // No result provided for .set_mapping_protocol; if it's called, the panic will fail this test
        TestLogHandler::new().exists_log_containing(
            "WARN: BAD_MP_READ: Could not read mapping protocol from database: NotPresent",
        );
    }

    #[test]
    fn compute_mapping_protocol_logs_and_moves_on_if_mapping_protocol_cannot_be_saved() {
        init_test_logging();
        let multi_config = make_simplified_multi_config(["--mapping-protocol", "IGDP"]);
        let logger = Logger::new("BAD_MP_WRITE");
        let mut persistent_config = configure_default_persistent_config(ZERO)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pcp)))
            .set_mapping_protocol_result(Err(PersistentConfigError::NotPresent));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, Some(AutomapProtocol::Igdp));
        TestLogHandler::new().exists_log_containing(
            "WARN: BAD_MP_WRITE: Could not save mapping protocol to database: NotPresent",
        );
    }

    #[test]
    fn get_public_ip_returns_sentinel_if_multiconfig_provides_none() {
        let multi_config = make_new_multi_config(&app_node(), vec![]).unwrap();

        let result = get_public_ip(&multi_config);

        assert_eq!(result, Ok(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    }

    #[test]
    fn get_public_ip_uses_multi_config() {
        let args = ArgsBuilder::new().param("--ip", "4.3.2.1");
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_multi_config(&app_node(), vec![vcl]).unwrap();

        let result = get_public_ip(&multi_config);

        assert_eq!(result, Ok(IpAddr::from_str("4.3.2.1").unwrap()));
    }

    #[test]
    fn unprivileged_configuration_handles_scans_off() {
        running_test();
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};
        let args = ["--ip", "1.2.3.4", "--scans", "off"];
        let mut bootstrapper_config = BootstrapperConfig::new();

        subject
            .unprivileged_parse_args(
                &make_simplified_multi_config(args),
                &mut bootstrapper_config,
                &mut configure_default_persistent_config(
                    ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL | RATE_PACK,
                ),
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(bootstrapper_config.suppress_initial_scans, true);
    }

    #[test]
    fn unprivileged_configuration_handles_scans_on() {
        running_test();
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};
        let args = ["--ip", "1.2.3.4", "--scans", "on"];
        let mut bootstrapper_config = BootstrapperConfig::new();

        subject
            .unprivileged_parse_args(
                &make_simplified_multi_config(args),
                &mut bootstrapper_config,
                &mut configure_default_persistent_config(
                    ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL | RATE_PACK,
                ),
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(bootstrapper_config.suppress_initial_scans, false);
    }

    #[test]
    fn unprivileged_configuration_defaults_scans() {
        running_test();
        let subject = UnprivilegedParseArgsConfigurationDaoReal {};
        let args = ["--ip", "1.2.3.4"];
        let mut bootstrapper_config = BootstrapperConfig::new();

        subject
            .unprivileged_parse_args(
                &make_simplified_multi_config(args),
                &mut bootstrapper_config,
                &mut configure_default_persistent_config(
                    ACCOUNTANT_CONFIG_PARAMS | MAPPING_PROTOCOL | RATE_PACK,
                ),
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(bootstrapper_config.suppress_initial_scans, false);
    }

    fn make_persistent_config(
        db_password_opt: Option<&str>,
        consuming_wallet_private_key_opt: Option<&str>,
        earning_wallet_address_opt: Option<&str>,
        gas_price_opt: Option<u64>,
        past_neighbors_opt: Option<&str>,
        rate_pack_opt: Option<RatePack>,
        min_hops_opt: Option<Hops>,
    ) -> PersistentConfigurationMock {
        let consuming_wallet_private_key_opt = consuming_wallet_private_key_opt.map(to_string);
        let earning_wallet_opt = match earning_wallet_address_opt {
            None => None,
            Some(address) => Some(Wallet::from_str(address).unwrap()),
        };
        let gas_price = gas_price_opt.unwrap_or(DEFAULT_GAS_PRICE);
        let past_neighbors_result = match (past_neighbors_opt, db_password_opt) {
            (Some(past_neighbors), Some(_)) => Ok(Some(
                past_neighbors
                    .split(",")
                    .map(|s| NodeDescriptor::try_from((main_cryptde(), s)).unwrap())
                    .collect::<Vec<NodeDescriptor>>(),
            )),
            _ => Ok(None),
        };
        let rate_pack = rate_pack_opt.unwrap_or(DEFAULT_RATE_PACK);
        let min_hops = min_hops_opt.unwrap_or(MIN_HOPS_FOR_TEST);
        PersistentConfigurationMock::new()
            .consuming_wallet_private_key_result(Ok(consuming_wallet_private_key_opt))
            .earning_wallet_address_result(Ok(earning_wallet_address_opt.map(to_string)))
            .earning_wallet_result(Ok(earning_wallet_opt))
            .gas_price_result(Ok(gas_price))
            .past_neighbors_result(past_neighbors_result)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pcp)))
            .rate_pack_result(Ok(rate_pack))
            .min_hops_result(Ok(min_hops))
    }
}
