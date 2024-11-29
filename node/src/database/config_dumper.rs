// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::apps::app_config_dumper;
use crate::blockchain::bip39::Bip39;
use crate::bootstrapper::RealUser;
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{
    DbInitializer, DbInitializerReal, InitializationError, DATABASE_FILE,
};
use crate::db_config::config_dao::{ConfigDao, ConfigDaoReal, ConfigDaoRecord};
use crate::db_config::typed_config_layer::{decode_bytes, encode_bytes};
use crate::node_configurator::{
    data_directory_from_context, real_user_data_directory_path_and_chain, DirsWrapper,
};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::run_modes_factories::DumpConfigRunner;
use crate::sub_lib::cryptde::{CryptDE, PlainData};
use crate::sub_lib::cryptde_real::CryptDEReal;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::utils::make_new_multi_config;
use clap::value_t;
use heck::MixedCase;
use masq_lib::blockchains::chains::Chain;
use masq_lib::command::StdStreams;
use masq_lib::multi_config::{CommandLineVcl, EnvironmentVcl, VirtualCommandLine};
use masq_lib::shared_schema::ConfiguratorError;
use rustc_hex::ToHex;
use serde_json::json;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

pub struct DumpConfigRunnerReal {
    pub(crate) dirs_wrapper: Box<dyn DirsWrapper>,
}

impl DumpConfigRunner for DumpConfigRunnerReal {
    fn go(&self, streams: &mut StdStreams, args: &[String]) -> Result<(), ConfiguratorError> {
        let dirs_wrapper_ref: &dyn DirsWrapper = self.dirs_wrapper.as_ref();
        let (real_user, data_directory, chain, password_opt) =
            distill_args(dirs_wrapper_ref, args)?;
        let cryptde = CryptDEReal::new(chain);
        PrivilegeDropperReal::new().drop_privileges(&real_user);
        let config_dao = make_config_dao(
            &data_directory,
            DbInitializationConfig::migration_suppressed(),
        ); //dump config is not supposed to migrate db
        let configuration = config_dao.get_all().expect("Couldn't fetch configuration");
        let json = configuration_to_json(configuration, password_opt, &cryptde);
        write_string(streams, json);
        Ok(())
    }

    as_any_ref_in_trait_impl!();
}

fn write_string(streams: &mut StdStreams, json: String) {
    short_writeln!(streams.stdout, "{}", json);
    streams
        .stdout
        .flush()
        .expect("Couldn't flush JSON to stdout");
}

fn configuration_to_json(
    configuration: Vec<ConfigDaoRecord>,
    password_opt: Option<String>,
    cryptde: &dyn CryptDE,
) -> String {
    let mut map = Map::new();
    configuration.into_iter().for_each(|record| {
        let json_name = record.name.to_mixed_case();
        let value_opt = match (&record.value_opt, record.encrypted, &password_opt) {
            (None, _, _) => None,
            (Some(value), false, _) => Some(value.to_string()),
            (Some(value), true, None) => Some(value.to_string()),
            (Some(value), true, Some(password)) => match Bip39::decrypt_bytes(value, password) {
                Ok(decrypted_value) => Some(translate_bytes(&json_name, decrypted_value, cryptde)),
                Err(_) => Some(value.to_string()),
            },
        };
        let json_value = match value_opt {
            Some(s) => json!(s),
            None => json!(null),
        };
        map.insert(json_name, json_value);
    });
    let value: Value = Value::Object(map);
    serde_json::to_string_pretty(&value).expect("Couldn't serialize configuration to JSON")
}

fn translate_bytes(json_name: &str, input: PlainData, cryptde: &dyn CryptDE) -> String {
    let to_utf8 = |data: PlainData| {
        String::from_utf8(data.clone().into()).unwrap_or_else(|_| {
            panic!(
                "Database is corrupt: {} byte string '{:?}' cannot be interpreted as UTF-8",
                json_name, data
            )
        })
    };
    match json_name {
        "exampleEncrypted" => encode_bytes(Some(input))
            .expect("Never happen.")
            .expect("Value disappeared"),
        "pastNeighbors" => {
            let string = to_utf8(input);
            let bytes = decode_bytes(Some(string))
                .expect("Database is corrupt: past_neighbors cannot be decoded")
                .expect("Value disappeared");
            let node_descriptors =
                serde_cbor::de::from_slice::<Vec<NodeDescriptor>>(bytes.as_slice())
                    .expect("Database is corrupt: past_neighbors contains bad CBOR");
            node_descriptors
                .into_iter()
                .map(|nd| nd.to_string(cryptde))
                .collect::<Vec<String>>()
                .join(",")
        }
        "consumingWalletPrivateKey" => input.as_slice().to_hex(),
        _ => to_utf8(input),
    }
}

fn make_config_dao(data_directory: &Path, init_config: DbInitializationConfig) -> ConfigDaoReal {
    let conn = DbInitializerReal::default()
        .initialize(data_directory,init_config)
        .unwrap_or_else(|e| if e == InitializationError::Nonexistent {panic!("\
        Could not find database at: {}. It is created when the Node operates the first time. Running \
          --dump-config before that has no effect",data_directory.to_string_lossy())} else {
            panic!(
                "Can't initialize database at {:?}: {:?}",
                data_directory.join(DATABASE_FILE),
                e
            )
        });
    ConfigDaoReal::new(conn)
}

fn distill_args(
    dirs_wrapper: &dyn DirsWrapper,
    args: &[String],
) -> Result<(RealUser, PathBuf, Chain, Option<String>), ConfiguratorError> {
    let app = app_config_dumper();
    let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
        Box::new(CommandLineVcl::new(args.to_vec())),
        Box::new(EnvironmentVcl::new(&app)),
    ];
    let multi_config = make_new_multi_config(&app, vcls)?;
    let (real_user, data_directory_path, chain) =
        real_user_data_directory_path_and_chain(dirs_wrapper, &multi_config);
    let directory = match data_directory_path {
        Some(data_dir) => data_dir,
        None => data_directory_from_context(dirs_wrapper, &real_user, chain),
    };
    let password_opt = value_m!(multi_config, "db-password", String);
    Ok((real_user, directory, chain, password_opt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip39::Bip39;
    use crate::database::db_initializer::ExternalData;
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::db_config::config_dao::ConfigDao;
    use crate::db_config::persistent_configuration::{
        PersistentConfiguration, PersistentConfigurationReal,
    };
    use crate::db_config::typed_config_layer::encode_bytes;
    use crate::node_configurator::DirsWrapperReal;
    use crate::node_test_utils::DirsWrapperMock;
    use crate::sub_lib::accountant::{DEFAULT_PAYMENT_THRESHOLDS, DEFAULT_SCAN_INTERVALS};
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::neighborhood::{NodeDescriptor, DEFAULT_RATE_PACK};
    use crate::test_utils::database_utils::bring_db_0_back_to_life_and_return_connection;
    use crate::test_utils::{main_cryptde, ArgsBuilder};
    use masq_lib::constants::CURRENT_SCHEMA_VERSION;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::environment_guard::{ClapGuard, EnvironmentGuard};
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::NeighborhoodModeLight;
    use rustc_hex::ToHex;
    use std::fs::{create_dir_all, File};
    use std::io::ErrorKind;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn database_must_be_created_by_node_before_dump_config_is_used() {
        let _ = EnvironmentGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "database_must_be_created_by_node_before_dump_config_used",
        );
        let mut holder = FakeStreamHolder::new();
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .opt("--dump-config")
            .into();
        let subject = DumpConfigRunnerReal {
            dirs_wrapper: Box::new(DirsWrapperReal::default()),
        };

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            subject.go(&mut holder.streams(), args_vec.as_slice())
        }))
        .unwrap_err();

        let string_panic = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            string_panic,
            &format!(
                "Could not find database at: {}. It is created when the Node \
         operates the first time. Running --dump-config before that has no effect",
                data_dir.to_str().unwrap()
            )
        );
        let err = File::open(&data_dir.join(DATABASE_FILE)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound)
    }

    #[test]
    fn dump_config_does_not_migrate_obsolete_database() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_does_not_migrate_obsolete_database",
        );
        create_dir_all(&data_dir)
            .expect("Could not create chain directory inside config_file_not_specified_but_exists home/MASQ directory");
        let conn = bring_db_0_back_to_life_and_return_connection(&data_dir.join(DATABASE_FILE));
        let dao = ConfigDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));
        let schema_version_before = dao.get("schema_version").unwrap().value_opt.unwrap();
        assert_eq!(schema_version_before, "0");
        let mut holder = FakeStreamHolder::new();
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", Chain::PolyMainnet.rec().literal_identifier)
            .opt("--dump-config")
            .into();
        let subject = DumpConfigRunnerReal {
            dirs_wrapper: Box::new(DirsWrapperReal::default()),
        };

        let result = subject.go(&mut holder.streams(), args_vec.as_slice());

        assert!(result.is_ok());
        let schema_version_after = dao.get("schema_version").unwrap().value_opt.unwrap();
        assert_eq!(schema_version_before, schema_version_after);
        assert_eq!(holder.stderr.get_bytes().is_empty(), true);
    }

    fn check_that_dump_config_dumps_existing_database_without_password(
        database_path: PathBuf,
        mock_dirs_wrapper_opt: Option<Box<dyn DirsWrapper>>,
        non_default_data_directory_opt: Option<PathBuf>,
    ) {
        let _clap_guard = ClapGuard::new();
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::default()
                .initialize(
                    &database_path,
                    DbInitializationConfig::create_or_migrate(ExternalData::new(
                        Chain::PolyMainnet,
                        NeighborhoodModeLight::ZeroHop,
                        None,
                    )),
                )
                .unwrap();
            let mut persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config.change_password(None, "password").unwrap();
            persistent_config
                .set_wallet_info(
                    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
                    "0x0123456789012345678901234567890123456789",
                    "password",
                )
                .unwrap();
            persistent_config.set_clandestine_port(3456).unwrap();
            persistent_config
                .set_past_neighbors(
                    Some(vec![
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-ropsten:QUJDREVGRw@1.2.3.4:1234",
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-ropsten:QkNERUZHSA@2.3.4.5:2345",
                        ))
                        .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
            persistent_config
                .set_blockchain_service_url("https://infura.io/ID")
                .unwrap()
        }
        let mut args_builder = ArgsBuilder::new()
            .param("--real-user", "123::")
            .param("--chain", Chain::PolyMainnet.rec().literal_identifier)
            .opt("--dump-config");
        if let Some(data_dir) = non_default_data_directory_opt {
            args_builder = args_builder.param("--data-directory", data_dir.to_str().unwrap());
        }
        let args_vec: Vec<String> = args_builder.into();
        let dirs_wrapper = mock_dirs_wrapper_opt.unwrap_or(Box::new(DirsWrapperMock {
            data_dir_result: Some(PathBuf::from("/home/booga/.local/share".to_string())),
            home_dir_result: Some(PathBuf::from("/home/booga".to_string())),
        }));
        let subject = DumpConfigRunnerReal {
            dirs_wrapper: dirs_wrapper,
        };

        let result = subject.go(&mut holder.streams(), args_vec.as_slice());

        assert!(result.is_ok());
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::default()
            .initialize(&database_path, DbInitializationConfig::panic_on_migration())
            .unwrap();
        let dao = ConfigDaoReal::new(conn);
        assert_value("blockchainServiceUrl", "https://infura.io/ID", &map);
        assert_value("clandestinePort", "3456", &map);
        assert_encrypted_value(
            "consumingWalletPrivateKey",
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            "password",
            &map,
        );
        assert_value(
            "earningWalletAddress",
            "0x0123456789012345678901234567890123456789",
            &map,
        );
        assert_value(
            "chainName",
            Chain::PolyMainnet.rec().literal_identifier,
            &map,
        );
        assert_value("gasPrice", "1", &map);
        assert_value(
            "pastNeighbors",
            &dao.get("past_neighbors").unwrap().value_opt.unwrap(),
            &map,
        );
        assert_value("neighborhoodMode", "zero-hop", &map);
        assert_value("schemaVersion", &CURRENT_SCHEMA_VERSION.to_string(), &map);
        assert_null("startBlock", &map);
        assert_value(
            "exampleEncrypted",
            &dao.get("example_encrypted").unwrap().value_opt.unwrap(),
            &map,
        );
        assert_value(
            "paymentThresholds",
            &DEFAULT_PAYMENT_THRESHOLDS.to_string(),
            &map,
        );
        assert_value("ratePack", &DEFAULT_RATE_PACK.to_string(), &map);
        assert_value("scanIntervals", &DEFAULT_SCAN_INTERVALS.to_string(), &map);
        assert!(output.ends_with("\n}\n")) //asserting that there is a blank line at the end
    }

    #[test]
    fn dump_config_dumps_existing_database_without_password_and_data_dir_specified() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database_without_password_and_data_dir_specified",
        );
        let data_dir = home_dir.join("data_dir");
        let database_path = data_dir.clone();
        let mock_dirs_wrapper_opt = None;
        let non_default_data_directory_opt = Some(data_dir);
        check_that_dump_config_dumps_existing_database_without_password(
            database_path,
            mock_dirs_wrapper_opt,
            non_default_data_directory_opt,
        );
    }

    #[test]
    fn dump_config_dumps_existing_database_without_password_and_default_data_dir() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database_without_password_and_default_data_dir",
        );
        let data_dir = home_dir.join("data_dir");
        let database_path = data_dir
            .join("MASQ")
            .join(DEFAULT_CHAIN.rec().literal_identifier);
        let mock_dirs_wrapper_opt = Some(Box::new(
            DirsWrapperMock::new()
                .data_dir_result(Some(data_dir))
                .home_dir_result(Some(home_dir)),
        ) as Box<dyn DirsWrapper>);
        let non_default_data_directory_opt = None;
        check_that_dump_config_dumps_existing_database_without_password(
            database_path,
            mock_dirs_wrapper_opt,
            non_default_data_directory_opt,
        );
    }

    #[test]
    fn dump_config_dumps_existing_database_with_correct_password() {
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database_with_correct_password",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::default()
                .initialize(
                    &data_dir,
                    DbInitializationConfig::create_or_migrate(ExternalData::new(
                        Chain::PolyMainnet,
                        NeighborhoodModeLight::ConsumeOnly,
                        None,
                    )),
                )
                .unwrap();
            let mut persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config.change_password(None, "password").unwrap();
            persistent_config
                .set_wallet_info(
                    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
                    "0x0123456789012345678901234567890123456789",
                    "password",
                )
                .unwrap();
            persistent_config.set_clandestine_port(3456).unwrap();
            persistent_config
                .set_past_neighbors(
                    Some(vec![
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://polygon-mainnet:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234",
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://polygon-mainnet:QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345",
                        ))
                        .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
            persistent_config
                .set_blockchain_service_url("https://infura.io/ID")
                .unwrap()
        }
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", Chain::PolyMainnet.rec().literal_identifier)
            .param("--db-password", "password")
            .opt("--dump-config")
            .into();
        let subject = DumpConfigRunnerReal {
            dirs_wrapper: Box::new(DirsWrapperReal::default()),
        };

        let result = subject.go(&mut holder.streams(), args_vec.as_slice());

        assert!(result.is_ok());
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, DbInitializationConfig::panic_on_migration())
            .unwrap();
        let dao = Box::new(ConfigDaoReal::new(conn));
        assert_value("blockchainServiceUrl", "https://infura.io/ID", &map);
        assert_value("clandestinePort", "3456", &map);
        assert_value(
            "consumingWalletPrivateKey",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            &map,
        );
        assert_value(
            "earningWalletAddress",
            "0x0123456789012345678901234567890123456789",
            &map,
        );
        assert_value("chainName", "polygon-mainnet", &map);
        assert_value("gasPrice", "1", &map);
        assert_value("pastNeighbors", "masq://polygon-mainnet:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234,masq://polygon-mainnet:QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345", &map);
        assert_value("neighborhoodMode", "consume-only", &map);
        assert_value("schemaVersion", &CURRENT_SCHEMA_VERSION.to_string(), &map);
        assert_null("startBlock", &map);
        let expected_ee_entry = dao.get("example_encrypted").unwrap().value_opt.unwrap();
        let expected_ee_decrypted = Bip39::decrypt_bytes(&expected_ee_entry, "password").unwrap();
        let expected_ee_string = encode_bytes(Some(expected_ee_decrypted)).unwrap().unwrap();
        assert_value("exampleEncrypted", &expected_ee_string, &map);
        assert_value(
            "paymentThresholds",
            &DEFAULT_PAYMENT_THRESHOLDS.to_string(),
            &map,
        );
        assert_value("ratePack", &DEFAULT_RATE_PACK.to_string(), &map);
        assert_value("scanIntervals", &DEFAULT_SCAN_INTERVALS.to_string(), &map);
    }

    #[test]
    fn dump_config_dumps_existing_database_with_incorrect_password() {
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database_with_incorrect_password",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::default()
                .initialize(
                    &data_dir,
                    DbInitializationConfig::create_or_migrate(ExternalData::new(
                        Chain::PolyMainnet,
                        NeighborhoodModeLight::Standard,
                        None,
                    )),
                )
                .unwrap();
            let mut persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config.change_password(None, "password").unwrap();
            persistent_config
                .set_wallet_info(
                    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
                    "0x0123456789012345678901234567890123456789",
                    "password",
                )
                .unwrap();
            persistent_config.set_clandestine_port(3456).unwrap();
            persistent_config
                .set_past_neighbors(
                    Some(vec![
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://polygon-mainnet:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234",
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://polygon-mainnet:QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345",
                        ))
                        .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
            persistent_config
                .set_blockchain_service_url("https://infura.io/ID")
                .unwrap()
        }
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", Chain::PolyMainnet.rec().literal_identifier)
            .param("--db-password", "incorrect")
            .opt("--dump-config")
            .into();
        let subject = DumpConfigRunnerReal {
            dirs_wrapper: Box::new(DirsWrapperReal::default()),
        };

        let result = subject.go(&mut holder.streams(), args_vec.as_slice());

        assert!(result.is_ok(), "we expected Ok but got: {:?}", result);
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, DbInitializationConfig::panic_on_migration())
            .unwrap();
        let dao = Box::new(ConfigDaoReal::new(conn));
        assert_value("blockchainServiceUrl", "https://infura.io/ID", &map);
        assert_value("clandestinePort", "3456", &map);
        assert_encrypted_value(
            "consumingWalletPrivateKey",
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            "password",
            &map,
        );
        assert_value(
            "earningWalletAddress",
            "0x0123456789012345678901234567890123456789",
            &map,
        );
        assert_value(
            "chainName",
            Chain::PolyMainnet.rec().literal_identifier,
            &map,
        );
        assert_value("gasPrice", "1", &map);
        assert_value(
            "pastNeighbors",
            &dao.get("past_neighbors").unwrap().value_opt.unwrap(),
            &map,
        );
        assert_value("neighborhoodMode", "standard", &map);
        assert_value("schemaVersion", &CURRENT_SCHEMA_VERSION.to_string(), &map);
        assert_null("startBlock", &map);
        assert_value(
            "exampleEncrypted",
            &dao.get("example_encrypted").unwrap().value_opt.unwrap(),
            &map,
        );
        assert_value(
            "paymentThresholds",
            &DEFAULT_PAYMENT_THRESHOLDS.to_string(),
            &map,
        );
        assert_value("ratePack", &DEFAULT_RATE_PACK.to_string(), &map);
        assert_value("scanIntervals", &DEFAULT_SCAN_INTERVALS.to_string(), &map);
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: pastNeighbors byte string 'PlainData { data: [192, 193] }' cannot be interpreted as UTF-8"
    )]
    fn decode_bytes_handles_decode_error_for_past_neighbors() {
        let cryptde = main_cryptde();
        let data = PlainData::new(&[192, 193]);

        let _ = translate_bytes("pastNeighbors", data, cryptde);
    }

    #[test]
    #[should_panic(expected = "Database is corrupt: past_neighbors cannot be decoded")]
    fn decode_bytes_handles_utf8_error_for_past_neighbors() {
        let cryptde = main_cryptde();
        let data = PlainData::new(b"invalid hex");

        let _ = translate_bytes("pastNeighbors", data, cryptde);
    }

    #[test]
    #[should_panic(expected = "Database is corrupt: past_neighbors contains bad CBOR")]
    fn decode_bytes_handles_bad_cbor_for_past_neighbors() {
        let cryptde = main_cryptde();
        let data = PlainData::new(b"AABBCC");

        let _ = translate_bytes("pastNeighbors", data, cryptde);
    }

    fn assert_value(key: &str, expected_value: &str, map: &Map<String, Value>) {
        let actual_value = match map
            .get(key)
            .unwrap_or_else(|| panic!("record for {} is missing", key))
        {
            Value::String(s) => s,
            x => panic!("Expected JSON string; found {:?}", x),
        };
        assert_eq!(actual_value, expected_value);
    }

    fn assert_null(key: &str, map: &Map<String, Value>) {
        assert!(map.contains_key(key));
        let value = map
            .get(key)
            .unwrap_or_else(|| panic!("record for {} is missing", key));
        assert!(
            value.is_null(),
            "Expecting {} to be null, but it wasn't",
            value
        )
    }

    fn assert_encrypted_value(
        key: &str,
        expected_value: &str,
        password: &str,
        map: &Map<String, Value>,
    ) {
        let encrypted_value = match map
            .get(key)
            .unwrap_or_else(|| panic!("record for {} is missing", key))
        {
            Value::String(s) => s,
            x => panic!("Expected JSON string; found {:?}", x),
        };
        let decrypted_value_bytes = Bip39::decrypt_bytes(encrypted_value, password).unwrap();
        let actual_value: String = decrypted_value_bytes.as_slice().to_hex();
        assert_eq!(actual_value.to_uppercase(), expected_value.to_uppercase());
    }
}
