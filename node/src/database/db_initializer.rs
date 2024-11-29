// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::database::rusqlite_wrappers::{ConnectionWrapper, ConnectionWrapperReal};

use crate::database::db_migrations::db_migrator::{DbMigrator, DbMigratorReal};
use crate::db_config::secure_config_layer::EXAMPLE_ENCRYPTED;
use crate::neighborhood::DEFAULT_MIN_HOPS;
use crate::sub_lib::accountant::{DEFAULT_PAYMENT_THRESHOLDS, DEFAULT_SCAN_INTERVALS};
use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use crate::sub_lib::utils::db_connection_launch_panic;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::{
    CURRENT_SCHEMA_VERSION, DEFAULT_GAS_PRICE, HIGHEST_RANDOM_CLANDESTINE_PORT,
    LOWEST_USABLE_INSECURE_PORT,
};
use masq_lib::logger::Logger;
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
use masq_lib::utils::NeighborhoodModeLight;
use rand::prelude::*;
use rusqlite::{Connection, OpenFlags};
use std::fmt::{Debug, Formatter};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::{fs, vec};
use tokio::net::TcpListener;

pub const DATABASE_FILE: &str = "node-data.db";

#[derive(Debug, PartialEq)]
pub enum InitializationError {
    Nonexistent,
    UndetectableVersion(String),
    SqliteError(rusqlite::Error),
    MigrationError(String),
    SuppressedMigration,
}

pub trait DbInitializer {
    fn initialize(
        &self,
        path: &Path,
        init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError>;

    fn initialize_to_version(
        &self,
        path: &Path,
        target_version: usize,
        init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError>;
}

#[derive(Default)]
pub struct DbInitializerReal {}

impl DbInitializer for DbInitializerReal {
    fn initialize(
        &self,
        path: &Path,
        init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        self.initialize_to_version(path, CURRENT_SCHEMA_VERSION, init_config)
    }

    fn initialize_to_version(
        &self,
        path: &Path,
        target_version: usize,
        init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        let is_creation_necessary = Self::is_creation_necessary(path);
        if !matches!(
            init_config.mode,
            InitializationMode::CreationAndMigration { .. }
        ) && is_creation_necessary
        {
            return Err(InitializationError::Nonexistent);
        }
        Self::create_data_directory_if_necessary(path);
        let db_file_path = &path.join(DATABASE_FILE);
        match Connection::open_with_flags(db_file_path, OpenFlags::SQLITE_OPEN_READ_WRITE) {
            Ok(conn) => {
                eprintln!("Opened existing database at {:?}", db_file_path);
                Self::extra_configuration(&conn, &init_config)?;
                self.check_migrations_and_return_connection(
                    conn,
                    init_config,
                    db_file_path,
                    target_version,
                    OpenFlags::SQLITE_OPEN_READ_WRITE,
                )
            }
            Err(_) => match Connection::open_with_flags(
                db_file_path,
                OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE,
            ) {
                Ok(conn) => {
                    eprintln!("Created new database at {:?}", db_file_path);
                    Self::extra_configuration(&conn, &init_config)?;
                    self.create_database_tables(&conn, ExternalData::from(init_config));
                    Ok(Box::new(ConnectionWrapperReal::new(conn)))
                }
                Err(e) => Err(InitializationError::SqliteError(e)),
            },
        }
    }
}

impl DbInitializerReal {
    fn is_creation_necessary(data_directory: &Path) -> bool {
        match fs::read_dir(data_directory) {
            Ok(_) => !data_directory.join(DATABASE_FILE).exists(),
            Err(_) => true,
        }
    }

    fn create_data_directory_if_necessary(data_directory: &Path) {
        match fs::read_dir(data_directory) {
            Ok(_) => (),
            Err(ref e) if e.kind() == ErrorKind::NotFound => fs::create_dir_all(data_directory)
                .unwrap_or_else(|_| {
                    panic!(
                        "Cannot create specified data directory at {:?}",
                        data_directory
                    )
                }),
            Err(e) => panic!(
                "Error checking data directory at {:?}: {}",
                data_directory, e
            ),
        }
    }

    fn create_database_tables(&self, conn: &Connection, external_params: ExternalData) {
        Self::create_config_table(conn);
        Self::initialize_config(conn, external_params);
        Self::create_payable_table(conn);
        Self::create_pending_payable_table(conn);
        Self::create_receivable_table(conn);
        Self::create_banned_table(conn);
    }

    pub fn create_config_table(conn: &Connection) {
        conn.execute(
            "create table if not exists config (
                    name text primary key,
                    value text,
                    encrypted integer not null
           )",
            [],
        )
        .expect("Can't create config table");
    }
    fn initialize_config(conn: &Connection, external_params: ExternalData) {
        Self::set_config_value(conn, EXAMPLE_ENCRYPTED, None, true, "example_encrypted");
        Self::set_config_value(
            conn,
            "blockchain_service_url",
            None,
            false,
            "blockchain service url to interact with the blockchain",
        );
        Self::set_config_value(
            conn,
            "chain_name",
            Some(external_params.chain.rec().literal_identifier),
            false,
            "the chain the database is created for",
        );
        Self::set_config_value(
            conn,
            "clandestine_port",
            Some(&Self::choose_clandestine_port().to_string()),
            false,
            "clandestine port",
        );
        Self::set_config_value(
            conn,
            "consuming_wallet_private_key",
            None,
            true,
            "consuming wallet private key",
        );
        Self::set_config_value(
            conn,
            "earning_wallet_address",
            None,
            false,
            "earning wallet address",
        );
        Self::set_config_value(
            conn,
            "neighborhood_mode",
            Some(&external_params.neighborhood_mode.to_string()),
            false,
            "neighborhood mode being used",
        );
        Self::set_config_value(
            conn,
            "schema_version",
            Some(&CURRENT_SCHEMA_VERSION.to_string()),
            false,
            "database version",
        );
        Self::set_config_value(
            conn,
            "start_block",
            None,
            false,
            &format!(
                "{} start block",
                external_params.chain.rec().literal_identifier
            ),
        );
        Self::set_config_value(
            conn,
            "gas_price",
            Some(&DEFAULT_GAS_PRICE.to_string()),
            false,
            "gas price",
        );
        Self::set_config_value(conn, "past_neighbors", None, true, "past neighbors");
        Self::set_config_value(
            conn,
            "mapping_protocol",
            None,
            false,
            "last successful protocol for port mapping on the router",
        );
        Self::set_config_value(
            conn,
            "min_hops",
            Some(&DEFAULT_MIN_HOPS.to_string()),
            false,
            "min hops",
        );
        Self::set_config_value(
            conn,
            "payment_thresholds",
            Some(&DEFAULT_PAYMENT_THRESHOLDS.to_string()),
            false,
            "payment thresholds",
        );
        Self::set_config_value(
            conn,
            "rate_pack",
            Some(&DEFAULT_RATE_PACK.to_string()),
            false,
            "rate pack",
        );
        Self::set_config_value(
            conn,
            "scan_intervals",
            Some(&DEFAULT_SCAN_INTERVALS.to_string()),
            false,
            "scan intervals",
        );
        Self::set_config_value(conn, "max_block_count", None, false, "maximum block count");
    }

    pub fn create_pending_payable_table(conn: &Connection) {
        conn.execute(
            "create table if not exists pending_payable (
                    rowid integer primary key,
                    transaction_hash text not null,
                    amount_high_b integer not null,
                    amount_low_b integer not null,
                    payable_timestamp integer not null,
                    attempt integer not null,
                    process_error text null
            )",
            [],
        )
        .expect("Can't create pending_payable table");
        conn.execute(
            "CREATE UNIQUE INDEX pending_payable_hash_idx ON pending_payable (transaction_hash)",
            [],
        )
        .expect("Can't create transaction hash index in pending payments");
    }

    pub fn create_payable_table(conn: &Connection) {
        conn.execute(
            "create table if not exists payable (
                    wallet_address text primary key,
                    balance_high_b integer not null,
                    balance_low_b integer not null,
                    last_paid_timestamp integer not null,
                    pending_payable_rowid integer null
            ) strict",
            [],
        )
        .expect("Can't create payable table");
    }

    pub fn create_receivable_table(conn: &Connection) {
        conn.execute(
            "create table if not exists receivable (
                    wallet_address text primary key,
                    balance_high_b integer not null,
                    balance_low_b integer not null,
                    last_received_timestamp integer not null
            ) strict",
            [],
        )
        .expect("Can't create receivable table");
    }

    pub fn create_banned_table(conn: &Connection) {
        conn.execute(
            "create table banned ( wallet_address text primary key )",
            [],
        )
        .expect("Can't create banned table");
    }

    fn extra_configuration(
        conn: &Connection,
        init_config: &DbInitializationConfig,
    ) -> Result<(), InitializationError> {
        if init_config.special_conn_configuration.is_empty() {
            Ok(())
        } else {
            match init_config
                .special_conn_configuration
                .iter()
                .try_for_each(|setup_fn| setup_fn(conn))
            {
                Ok(()) => Ok(()),
                Err(e) => Err(InitializationError::SqliteError(e)),
            }
        }
    }

    fn check_migrations_and_return_connection(
        &self,
        conn: Connection,
        init_config: DbInitializationConfig,
        db_file_path: &Path,
        target_version: usize,
        flags: OpenFlags,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        let str_sv = Self::read_current_schema_version(&conn)?;
        match (Self::is_migration_required(&str_sv)?, init_config.mode) {
            (None, _) => Ok(Box::new(ConnectionWrapperReal::new(conn))),
            (Some(_), InitializationMode::CreationBannedMigrationPanics) => {
                panic!("Broken code: Migrating database at inappropriate place")
            }
            (
                Some(mismatched_version),
                InitializationMode::CreationAndMigration { external_data },
            ) => {
                let migrator = Box::new(DbMigratorReal::new(external_data));
                self.migrate_and_return_connection(
                    conn,
                    mismatched_version,
                    target_version,
                    db_file_path,
                    flags,
                    migrator,
                )
            }
            (Some(_), InitializationMode::CreationBannedMigrationSuppressed) => {
                Ok(Box::new(ConnectionWrapperReal::new(conn)))
            }
            (Some(_), InitializationMode::CreationBannedMigrationRaisesErr) => {
                Err(InitializationError::SuppressedMigration)
            }
        }
    }

    fn read_current_schema_version(conn: &Connection) -> Result<String, InitializationError> {
        conn.prepare("select value from config where name = 'schema_version'")
            .expect("select failed")
            .query_row([], |row| row.get::<usize, String>(0))
            .map_err(|e| {
                InitializationError::UndetectableVersion(format!(
                    "Need {}, found nothing (err: {})",
                    CURRENT_SCHEMA_VERSION, e
                ))
            })
    }

    fn is_migration_required(version_read_str: &str) -> Result<Option<usize>, InitializationError> {
        let v_from_db = Self::validate_schema_version(version_read_str);
        if v_from_db == CURRENT_SCHEMA_VERSION {
            Ok(None)
        } else {
            Ok(Some(v_from_db))
        }
    }

    fn migrate_and_return_connection(
        &self,
        conn: Connection,
        mismatched_version: usize,
        target_version: usize,
        db_file_path: &Path,
        flags: OpenFlags,
        migrator: Box<dyn DbMigrator>,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        warning!(
            Logger::new("DbInitializer"),
            "Database is incompatible and its updating is necessary"
        );
        let wrapped_connection = ConnectionWrapperReal::new(conn);
        match migrator.migrate_database(
            mismatched_version,
            target_version,
            Box::new(wrapped_connection),
        ) {
            Ok(_) => {
                let wrapped_conn =
                    self.double_check_migration_result(db_file_path, flags, target_version);
                Ok(wrapped_conn)
            }
            Err(e) => Err(InitializationError::MigrationError(e)),
        }
    }

    fn double_check_migration_result(
        &self,
        db_file_path: &Path,
        opening_flags: OpenFlags,
        target_version: usize,
    ) -> Box<dyn ConnectionWrapper> {
        let conn = Connection::open_with_flags(db_file_path, opening_flags)
            .unwrap_or_else(|e| panic!("The database undoubtedly exists, but: {}", e));
        let str_schema = Self::read_current_schema_version(&conn)
            .expect("Db migration failed; cannot find the row with the schema version");
        let numeric_schema = Self::validate_schema_version(&str_schema);
        if numeric_schema == target_version {
            Box::new(ConnectionWrapperReal::new(conn))
        } else {
            panic!("DB migration failed, the resulting records are still incorrect; found schema {} but expecting {}", numeric_schema, target_version)
        }
    }

    fn validate_schema_version(obtained_s_v: &str) -> usize {
        obtained_s_v.parse::<usize>().unwrap_or_else(|_| {
            panic!(
                "Database version should be purely numeric, but was: {}",
                obtained_s_v
            )
        })
    }

    pub fn choose_clandestine_port() -> u16 {
        let mut rng = SmallRng::from_entropy();
        loop {
            let candidate_port: u16 =
                rng.gen_range(LOWEST_USABLE_INSECURE_PORT..HIGHEST_RANDOM_CLANDESTINE_PORT);
            match TcpListener::bind(&SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(0),
                candidate_port,
            ))) {
                Ok(_) => return candidate_port,
                Err(_) => continue,
            }
        }
    }

    fn set_config_value(
        conn: &Connection,
        name: &str,
        value: Option<&str>,
        encrypted: bool,
        readable: &str,
    ) {
        conn.execute(
            format!(
                "insert into config (name, value, encrypted) values ('{}', {}, {})",
                name,
                match value {
                    Some(value) => format!("'{}'", value),
                    None => "null".to_string(),
                },
                if encrypted { 1 } else { 0 }
            )
            .as_str(),
            [],
        )
        .unwrap_or_else(|e| panic!("Can't preload config table with {}: {:?}", readable, e));
    }
}

pub fn connection_or_panic(
    db_initializer: &dyn DbInitializer,
    path: &Path,
    init_config: DbInitializationConfig,
) -> Box<dyn ConnectionWrapper> {
    db_initializer
        .initialize(path, init_config)
        .unwrap_or_else(|err| db_connection_launch_panic(err, path))
}

#[derive(Clone)]
pub struct DbInitializationConfig {
    pub mode: InitializationMode,
    pub special_conn_configuration: Vec<fn(&Connection) -> rusqlite::Result<()>>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum InitializationMode {
    CreationAndMigration { external_data: ExternalData },
    CreationBannedMigrationPanics,
    CreationBannedMigrationSuppressed,
    CreationBannedMigrationRaisesErr,
}

impl DbInitializationConfig {
    pub fn add_special_conn_setup(
        mut self,
        setter: fn(&Connection) -> rusqlite::Result<()>,
    ) -> Self {
        self.special_conn_configuration.push(setter);
        self
    }

    pub fn panic_on_migration() -> Self {
        Self {
            mode: InitializationMode::CreationBannedMigrationPanics,
            special_conn_configuration: vec![],
        }
    }

    //standard way of Node to create a new db, possibly only one real occurrence ever
    pub fn create_or_migrate(external_data: ExternalData) -> Self {
        Self {
            mode: InitializationMode::CreationAndMigration { external_data },
            special_conn_configuration: vec![],
        }
    }

    //used in the config dumper
    pub fn migration_suppressed() -> Self {
        Self {
            mode: InitializationMode::CreationBannedMigrationSuppressed,
            special_conn_configuration: vec![],
        }
    }

    //it makes Daemon ignore db configuration until the Node
    //starts up and manage the migration on its own
    pub fn migration_suppressed_with_error() -> Self {
        Self {
            mode: InitializationMode::CreationBannedMigrationRaisesErr,
            special_conn_configuration: vec![],
        }
    }

    pub fn test_default() -> Self {
        Self {
            mode: InitializationMode::CreationAndMigration {
                external_data: ExternalData {
                    chain: TEST_DEFAULT_CHAIN,
                    neighborhood_mode: NeighborhoodModeLight::Standard,
                    db_password_opt: None,
                },
            },
            special_conn_configuration: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalData {
    pub chain: Chain,
    pub neighborhood_mode: NeighborhoodModeLight,
    pub db_password_opt: Option<String>,
}

impl ExternalData {
    pub fn new(
        chain: Chain,
        neighborhood_mode: NeighborhoodModeLight,
        db_password_opt: Option<String>,
    ) -> Self {
        Self {
            chain,
            neighborhood_mode,
            db_password_opt,
        }
    }
}

impl From<DbInitializationConfig> for ExternalData {
    fn from(init_config: DbInitializationConfig) -> Self {
        match init_config.mode {
            InitializationMode::CreationAndMigration { external_data } => external_data,
            _ => panic!("Attempt to create new database without proper configuration"),
        }
    }
}

impl PartialEq for DbInitializationConfig {
    fn eq(&self, other: &Self) -> bool {
        (self.mode == other.mode)
            //I'm making most of this, fn pointers cannot be compared in Rust by August 2022
            && (self.special_conn_configuration.len() == other.special_conn_configuration.len())
    }
}

impl Debug for DbInitializationConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DbInitializationConfig{{init_config: {:?}, special_conn_setup: Addresses{:?}}}",
            self.mode,
            self.special_conn_configuration
                .iter()
                //reportedly, there is no guarantee the number varies by different functions,
                //so it rather shows how many items are in than anything else
                .map(|pointer| *pointer as usize)
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::InitializationError::SqliteError;
    use crate::db_config::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::test_utils::database_utils::{
        assert_create_table_stm_contains_all_parts,
        assert_index_stm_is_coupled_with_right_parameter, assert_no_index_exists_for_table,
        assert_table_created_as_strict, bring_db_0_back_to_life_and_return_connection,
        make_external_data, retrieve_config_row, DbMigratorMock,
    };
    use itertools::Either::{Left, Right};
    use itertools::{Either, Itertools};
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_does_not_exist, ensure_node_home_directory_exists,
        TEST_DEFAULT_CHAIN,
    };
    use masq_lib::utils::NeighborhoodModeLight;
    use regex::Regex;
    use rusqlite::Error::InvalidColumnType;
    use rusqlite::{Error, OpenFlags};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::ops::Not;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(DATABASE_FILE, "node-data.db");
        assert_eq!(CURRENT_SCHEMA_VERSION, 9);
    }

    #[test]
    fn db_initialize_creates_config_table() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_creates_config_table",
        );
        let subject = DbInitializerReal::default();

        let conn = subject
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();

        let mut stmt = conn
            .prepare("select name, value, encrypted from config")
            .unwrap();
        let _ = stmt.query_map([], |_| Ok(42)).unwrap();
        let expected_key_words: &[&[&str]] = &[
            &["name", "text", "primary", "key"],
            &["value", "text"],
            &["encrypted", "integer", "not", "null"],
        ];
        assert_create_table_stm_contains_all_parts(conn.as_ref(), "config", expected_key_words);
        assert_no_index_exists_for_table(conn.as_ref(), "config")
    }

    #[test]
    fn db_initialize_creates_pending_payable_table() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_creates_pending_payable_table",
        );
        let subject = DbInitializerReal::default();

        let conn = subject
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();

        let mut stmt = conn.prepare("select rowid, transaction_hash, amount_high_b, amount_low_b, payable_timestamp, attempt, process_error from pending_payable").unwrap();
        let mut payable_contents = stmt.query_map([], |_| Ok(42)).unwrap();
        assert!(payable_contents.next().is_none());
        let expected_key_words: &[&[&str]] = &[
            &["rowid", "integer", "primary", "key"],
            &["transaction_hash", "text", "not", "null"],
            &["amount_high_b", "integer", "not", "null"],
            &["amount_low_b", "integer", "not", "null"],
            &["payable_timestamp", "integer", "not", "null"],
            &["attempt", "integer", "not", "null"],
            &["process_error", "text", "null"],
        ];
        assert_create_table_stm_contains_all_parts(&*conn, "pending_payable", expected_key_words);
        let expected_key_words: &[&[&str]] = &[&["transaction_hash"]];
        assert_index_stm_is_coupled_with_right_parameter(
            conn.as_ref(),
            "pending_payable_hash_idx",
            expected_key_words,
        )
    }

    #[test]
    fn db_initialize_creates_payable_table() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_creates_payable_table",
        );
        let subject = DbInitializerReal::default();

        let conn = subject
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();

        let mut stmt = conn.prepare ("select wallet_address, balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid from payable").unwrap ();
        let mut payable_contents = stmt.query_map([], |_| Ok(42)).unwrap();
        assert!(payable_contents.next().is_none());
        assert_table_created_as_strict(&*conn, "payable");
        let expected_key_words: &[&[&str]] = &[
            &["wallet_address", "text", "primary", "key"],
            &["balance_high_b", "integer", "not", "null"],
            &["balance_low_b", "integer", "not", "null"],
            &["last_paid_timestamp", "integer", "not", "null"],
            &["pending_payable_rowid", "integer", "null"],
        ];
        assert_create_table_stm_contains_all_parts(&*conn, "payable", expected_key_words);
        assert_no_index_exists_for_table(conn.as_ref(), "payable")
    }

    #[test]
    fn db_initialize_creates_receivable_table() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_creates_receivable_table",
        );
        let subject = DbInitializerReal::default();

        let conn = subject
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();

        let mut stmt = conn
            .prepare("select wallet_address, balance_high_b, balance_low_b, last_received_timestamp from receivable")
            .unwrap();
        let mut receivable_contents = stmt.query_map([], |_| Ok(())).unwrap();
        assert!(receivable_contents.next().is_none());
        assert_table_created_as_strict(&*conn, "receivable");
        let expected_key_words: &[&[&str]] = &[
            &["wallet_address", "text", "primary", "key"],
            &["balance_high_b", "integer", "not", "null"],
            &["balance_low_b", "integer", "not", "null"],
            &["last_received_timestamp", "integer", "not", "null"],
        ];
        assert_create_table_stm_contains_all_parts(conn.as_ref(), "receivable", expected_key_words);
        assert_no_index_exists_for_table(conn.as_ref(), "receivable")
    }

    #[test]
    fn db_initialize_creates_banned_table() {
        init_test_logging();
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_creates_banned_table",
        );
        let subject = DbInitializerReal::default();

        let conn = subject
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();

        let mut stmt = conn.prepare("select wallet_address from banned").unwrap();
        let mut banned_contents = stmt.query_map([], |_| Ok(42)).unwrap();
        assert!(banned_contents.next().is_none());
        let expected_key_words: &[&[&str]] = &[&["wallet_address", "text", "primary", "key"]];
        assert_create_table_stm_contains_all_parts(conn.as_ref(), "banned", expected_key_words);
        assert_no_index_exists_for_table(conn.as_ref(), "banned")
    }

    #[test]
    #[should_panic(expected = "The database undoubtedly exists, but: unable to open database file")]
    fn double_check_the_result_of_db_migration_panics_if_cannot_reestablish_the_connection_to_the_database(
    ) {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "double_check_the_result_of_db_migration_panics_if_cannot_reestablish_the_connection_to_the_database",
        );
        let target_version = 1;
        let subject = DbInitializerReal::default();

        let _ = subject.double_check_migration_result(
            &home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            target_version,
        );
    }

    #[test]
    #[should_panic(
        expected = "DB migration failed, the resulting records are still incorrect; found schema 0 but expecting 1"
    )]
    fn panics_because_the_data_does_not_correspond_to_target_version_after_an_allegedly_successful_migration(
    ) {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "panics_because_the_data_does_not_correspond_to_target_version_after_an_allegedly_successful_migration",
        );
        let db_file_path = home_dir.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_file_path);
        let target_version = 1;
        //schema_version equals to 0 but current schema version must be at least 1 and more

        let subject = DbInitializerReal::default();

        let _ = subject.double_check_migration_result(
            &home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            target_version,
        );
    }

    fn extract_configurations(conn: &Connection) -> HashMap<String, (Option<String>, bool)> {
        let mut stmt = conn
            .prepare("select name, value, encrypted from config")
            .unwrap();
        let query_result = stmt.query_map([], |row| {
            Ok((
                row.get(0),
                row.get(1),
                row.get(2).map(|encrypted: i64| encrypted > 0),
            ))
        });
        match query_result {
            Ok(rows) => rows,
            Err(e) => panic!("Error retrieving configuration: {}", e),
        }
        .map(|row| match row {
            Ok((Ok(name), Ok(value), Ok(encrypted))) => (name, (Some(value), encrypted)),
            Ok((Ok(name), Err(InvalidColumnType(1, _, _)), Ok(encrypted))) => {
                (name, (None, encrypted))
            }
            e => panic!("Error retrieving configuration: {:?}", e),
        })
        .collect::<HashMap<String, (Option<String>, bool)>>()
    }

    #[test]
    fn existing_database_with_correct_version_is_accepted_without_changes() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_correct_version_is_accepted_without_changes",
        );
        let subject = DbInitializerReal::default();
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        {
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
            conn.execute(
                "insert into config (name, value, encrypted) values ('preexisting', 'yes', 0)",
                [],
            )
            .unwrap();
        }

        subject
            .initialize(&home_dir, DbInitializationConfig::panic_on_migration())
            .unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let config_map = extract_configurations(&conn);
        let mut config_vec: Vec<(String, (Option<String>, bool))> =
            config_map.into_iter().collect();
        config_vec.sort_by_key(|(name, _)| name.clone());
        let verify = |cv: &mut Vec<(String, (Option<String>, bool))>,
                      name: &str,
                      value: Option<&str>,
                      encrypted: bool| {
            let actual = cv.remove(0);
            let expected = (name.to_string(), (value.map(|v| v.to_string()), encrypted));
            assert_eq!(actual, expected)
        };
        let verify_but_value = |cv: &mut Vec<(String, (Option<String>, bool))>,
                                expected_name: &str,
                                expected_encrypted: bool| {
            let (actual_name, (value, actual_encrypted)) = cv.remove(0);
            assert_eq!(actual_name, expected_name);
            assert_eq!(actual_encrypted, expected_encrypted);
            value
        };
        verify(&mut config_vec, "blockchain_service_url", None, false);
        verify(
            &mut config_vec,
            "chain_name",
            Some(TEST_DEFAULT_CHAIN.rec().literal_identifier),
            false,
        );
        let clandestine_port_str_opt = verify_but_value(&mut config_vec, "clandestine_port", false);
        let clandestine_port: u16 = clandestine_port_str_opt.unwrap().parse().unwrap();
        assert!(clandestine_port >= 1025);
        assert!(clandestine_port < 10000);
        verify(&mut config_vec, "consuming_wallet_private_key", None, true);
        verify(&mut config_vec, "earning_wallet_address", None, false);
        verify(&mut config_vec, EXAMPLE_ENCRYPTED, None, true);
        verify(
            &mut config_vec,
            "gas_price",
            Some(&DEFAULT_GAS_PRICE.to_string()),
            false,
        );
        verify(&mut config_vec, "mapping_protocol", None, false);
        verify(&mut config_vec, "max_block_count", None, false);
        verify(&mut config_vec, "min_hops", Some("3"), false);
        verify(
            &mut config_vec,
            "neighborhood_mode",
            Some("standard"),
            false,
        );
        verify(&mut config_vec, "past_neighbors", None, true);
        verify(
            &mut config_vec,
            "payment_thresholds",
            Some(&DEFAULT_PAYMENT_THRESHOLDS.to_string()),
            false,
        );
        verify(&mut config_vec, "preexisting", Some("yes"), false); // making sure we opened the preexisting database
        verify(
            &mut config_vec,
            "rate_pack",
            Some(&DEFAULT_RATE_PACK.to_string()),
            false,
        );
        verify(
            &mut config_vec,
            "scan_intervals",
            Some(&DEFAULT_SCAN_INTERVALS.to_string()),
            false,
        );
        verify(
            &mut config_vec,
            "schema_version",
            Some(&CURRENT_SCHEMA_VERSION.to_string()),
            false,
        );
        verify(&mut config_vec, "start_block", None, false);
        assert_eq!(config_vec, vec![]);
    }

    #[test]
    fn existing_database_with_no_version_is_rejected() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_no_version_is_rejected",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
            conn.execute("delete from config where name = 'schema_version'", [])
                .unwrap();
        }
        let subject = DbInitializerReal::default();

        let result = subject.initialize(&home_dir, DbInitializationConfig::panic_on_migration());

        assert_eq!(
            result.err().unwrap(),
            InitializationError::UndetectableVersion(format!(
                "Need {}, found nothing (err: Query returned no rows)",
                CURRENT_SCHEMA_VERSION
            )),
        );
    }

    #[test]
    #[should_panic(expected = "Database version should be purely numeric, but was: boooobles")]
    fn existing_database_with_junk_in_place_of_schema_version_is_caught() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_junk_in_place_of_its_schema_version_is_caught",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
            conn.execute(
                "update config set value = 'boooobles' where name = 'schema_version'",
                [],
            )
            .unwrap();
        }
        let subject = DbInitializerReal::default();

        let _ = subject.initialize(&home_dir, DbInitializationConfig::panic_on_migration());
    }

    const PRAGMA_CASE_SENSITIVE: &str = "case_sensitive_like";

    fn assert_case_sensitivity_has_been_turned_on(
        conn: Either<&Connection, &dyn ConnectionWrapper>,
    ) {
        let sql = "select 'a' like 'A'";
        let mut stm = match conn {
            Left(conn) => conn.prepare(sql).unwrap(),
            Right(wrapped_conn) => wrapped_conn.prepare(sql).unwrap(),
        };
        let is_considered_the_same = stm
            .query_row([], |row| Ok(row.get::<usize, bool>(0)))
            .unwrap();
        assert_eq!(is_considered_the_same, Ok(false));
    }

    #[test]
    fn add_special_setup_works() {
        let subject = DbInitializationConfig::test_default();
        let setup_fn = move |conn: &Connection| {
            conn.pragma_update(None, PRAGMA_CASE_SENSITIVE, true)
                .unwrap();
            Ok(())
        };
        let conn = Connection::open_in_memory().unwrap();

        let result = subject.add_special_conn_setup(setup_fn);

        result.special_conn_configuration[0](&conn).unwrap();
        assert_case_sensitivity_has_been_turned_on(Left(&conn))
    }

    #[test]
    fn extra_configuration_retrieves_first_error_encountered() {
        let fn_one = |_: &_| Ok(());
        let fn_two = |_: &_| Err(Error::ExecuteReturnedResults);
        let fn_three = |_: &_| Err(Error::GetAuxWrongType);
        let conn = Connection::open_in_memory().unwrap();
        let init_config =
            make_default_config_with_different_pointers(vec![fn_one, fn_two, fn_three]);

        let result = DbInitializerReal::extra_configuration(&conn, &init_config);

        assert_eq!(result, Err(SqliteError(Error::ExecuteReturnedResults)))
    }

    #[test]
    fn add_conn_special_setup_works_at_database_creation() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "add_conn_special_setup_works_at_database_creation",
        );
        let example_function = |conn: &Connection| {
            conn.pragma_update(None, PRAGMA_CASE_SENSITIVE, true)
                .unwrap();
            Ok(())
        };
        let init_config =
            DbInitializationConfig::test_default().add_special_conn_setup(example_function);

        let assert_conn = DbInitializerReal::default()
            .initialize(&home_dir, init_config)
            .unwrap();

        assert_case_sensitivity_has_been_turned_on(Right(assert_conn.as_ref()))
    }

    #[test]
    fn conn_special_setup_works_at_opening_existing_database() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "conn_special_setup_works_at_opening_existing_database",
        );
        DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let init_config =
            DbInitializationConfig::test_default().add_special_conn_setup(|conn: &Connection| {
                conn.pragma_update(None, PRAGMA_CASE_SENSITIVE, true)
                    .unwrap();
                Ok(())
            });

        let assert_conn = DbInitializerReal::default()
            .initialize(&home_dir, init_config)
            .unwrap();

        assert_case_sensitivity_has_been_turned_on(Right(assert_conn.as_ref()))
    }

    fn processing_special_setup_test_body(test_name: &str, pre_initialization: fn(&Path)) {
        let home_dir = ensure_node_home_directory_exists("db_initializer", test_name);
        {
            pre_initialization(home_dir.as_path())
        }
        let malformed_setup_function = |_: &_| Err(Error::GetAuxWrongType);
        let init_config =
            DbInitializationConfig::test_default().add_special_conn_setup(malformed_setup_function);

        let error = DbInitializerReal::default()
            .initialize(home_dir.as_path(), init_config)
            .unwrap_err();

        assert_eq!(
            error,
            InitializationError::SqliteError(Error::GetAuxWrongType)
        )
    }

    #[test]
    fn processing_special_setup_to_the_connection_goes_wrong_on_new_database() {
        processing_special_setup_test_body(
            "processing_special_setup_to_the_connection_goes_wrong_on_new_database",
            |path| {
                DbInitializerReal::default()
                    .initialize(path, DbInitializationConfig::test_default())
                    .unwrap();
            },
        )
    }

    #[test]
    fn processing_special_setup_to_the_connection_goes_wrong_on_existing_database() {
        processing_special_setup_test_body(
            "processing_special_setup_to_the_connection_goes_wrong_on_existing_database",
            |_path| {},
        )
    }

    #[test]
    fn database_of_old_version_comes_to_migrator_where_it_gradually_migrates_to_upper_versions() {
        init_test_logging();
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_the_wrong_version_comes_to_migrator_that_makes_it_gradually_migrate_to_upper_versions",
        );
        let updated_db_path_dir = &home_dir.join("updated");
        let from_scratch_db_path_dir = &home_dir.join("from_scratch");
        std::fs::create_dir(updated_db_path_dir).unwrap();
        std::fs::create_dir(from_scratch_db_path_dir).unwrap();
        {
            bring_db_0_back_to_life_and_return_connection(&updated_db_path_dir.join(DATABASE_FILE));
        }
        let subject = DbInitializerReal::default();

        let _ = subject
            .initialize(
                &updated_db_path_dir,
                DbInitializationConfig::create_or_migrate(ExternalData::new(
                    Chain::EthRopsten,
                    NeighborhoodModeLight::Standard,
                    Some("password".to_string()),
                )),
            )
            .unwrap();
        let _ = subject
            .initialize(
                &from_scratch_db_path_dir,
                DbInitializationConfig::test_default(),
            )
            .unwrap();

        // db_password_opt: Some("password".to_string()),
        // chain: Chain::EthRopsten,
        // neighborhood_mode: NeighborhoodModeLight::Standard,
        let conn_updated = Connection::open_with_flags(
            &updated_db_path_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let conn_from_scratch = Connection::open_with_flags(
            &from_scratch_db_path_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let extract_from_updated = extract_configurations(&conn_updated);
        let extract_from_from_scratch = extract_configurations(&conn_from_scratch);
        //please, write all rows with unpredictable values here
        let sieve = |updated_parameter: &String| updated_parameter != "clandestine_port";
        let zipped_iterators = extract_from_updated
            .iter()
            .sorted()
            .zip(extract_from_from_scratch.iter().sorted());
        //with regular values
        zipped_iterators
            .clone()
            .take_while(|((parameter_name, _), _)| sieve(parameter_name))
            .for_each(|(updated, from_scratch)| assert_eq!(updated, from_scratch));
        //with irregular values
        zipped_iterators
            .take_while(|((parameter_name, _), _)| sieve(parameter_name).not())
            .for_each(|(updated, from_scratch)| assert_eq!(updated.0, from_scratch.0));
        TestLogHandler::new().exists_log_containing(
            "WARN: DbInitializer: Database is incompatible and its updating is necessary",
        );
    }

    #[test]
    fn migrate_and_return_connection_hands_in_an_error_from_migration_operations() {
        init_test_logging();
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "migrate_and_return_connection_hands_in_an_error_from_migration_operations",
        );
        let migrate_database_params_arc = Arc::new(Mutex::new(vec![]));
        let db_file_path = home_dir.join(DATABASE_FILE);
        let conn = Connection::open(&db_file_path).unwrap();
        let subject = DbInitializerReal::default();
        let target_version = 5; //not relevant
        let migrator = Box::new(DbMigratorMock::default().inject_logger()
            .migrate_database_params(&migrate_database_params_arc)
            .migrate_database_result(Err("Migrating database from version 0 to 1 failed: Transaction couldn't be processed".to_string())));

        let result = subject.migrate_and_return_connection(
            conn,
            0,
            target_version,
            &db_file_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            migrator,
        );

        let error = match result {
            Ok(_) => panic!("expected Err got Ok"),
            Err(e) => e,
        };
        assert_eq!(
            error,
            InitializationError::MigrationError(
                "Migrating database from version 0 to 1 failed: Transaction couldn't be processed"
                    .to_string()
            )
        );
        let mut migrate_database_params = migrate_database_params_arc.lock().unwrap();
        let (obsolete_schema, target_version, _) = migrate_database_params.remove(0);
        assert_eq!(obsolete_schema, 0);
        assert_eq!(target_version, 5);
        TestLogHandler::new().exists_log_containing(
            "WARN: DbInitializer: Database is incompatible and its updating is necessary",
        );
    }

    #[test]
    fn database_migration_can_be_suppressed() {
        let data_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "database_migration_can_be_suppressed",
        );
        let conn = bring_db_0_back_to_life_and_return_connection(&data_dir.join(DATABASE_FILE));
        let dao = ConfigDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));
        let schema_version_before = dao.get("schema_version").unwrap().value_opt.unwrap();
        let subject = DbInitializerReal::default();

        let result = subject.initialize(&data_dir, DbInitializationConfig::migration_suppressed());

        let wrapped_connection = result.unwrap();
        let (schema_version_after, _) =
            retrieve_config_row(wrapped_connection.as_ref(), "schema_version");
        assert_eq!(schema_version_after.unwrap(), schema_version_before)
    }

    #[test]
    #[should_panic(expected = "Broken code: Migrating database at inappropriate place")]
    fn database_migration_causes_panic_if_not_allowed() {
        let data_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "database_migration_causes_panic_if_not_allowed",
        );
        let _ = bring_db_0_back_to_life_and_return_connection(&data_dir.join(DATABASE_FILE));
        let subject = DbInitializerReal::default();

        let _ = subject.initialize(&data_dir, DbInitializationConfig::panic_on_migration());
    }

    fn assert_new_database_was_not_created(home_dir: &Path) {
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let result = Connection::open_with_flags(home_dir.join(DATABASE_FILE), flags);
        match result.err().unwrap() {
            Error::SqliteFailure(_, _) => (),
            x => panic!("Expected SqliteFailure, got {:?}", x),
        }
    }

    fn assert_that_database_is_not_created_by_certain_initialization_configs(data_dir: &Path) {
        let subject = DbInitializerReal::default();

        [
            DbInitializationConfig::panic_on_migration(),
            DbInitializationConfig::migration_suppressed(),
            DbInitializationConfig::migration_suppressed_with_error(),
        ]
        .into_iter()
        .for_each(|init_config| {
            let result = subject.initialize(data_dir, init_config);

            assert_eq!(result.err().unwrap(), InitializationError::Nonexistent);
            assert_new_database_was_not_created(data_dir)
        })
    }

    #[test]
    fn db_initialize_does_not_create_if_directed_not_to_via_initialization_config_and_directory_does_not_exist(
    ) {
        let data_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_does_not_create_if_directed_not_to_via_initialization_config_and_directory_does_not_exist",
        );

        assert_that_database_is_not_created_by_certain_initialization_configs(&data_dir)
    }

    #[test]
    fn db_initialize_does_not_create_if_directed_not_to_via_initialization_config_and_database_file_does_not_exist(
    ) {
        let data_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "db_initialize_does_not_create_if_directed_not_to_via_initialization_config_and_database_file_does_not_exist",
        );

        assert_that_database_is_not_created_by_certain_initialization_configs(&data_dir)
    }

    #[test]
    fn database_migration_can_be_suppressed_and_give_an_initialization_error() {
        let data_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "database_migration_can_be_suppressed_and_give_an_initialization_error",
        );
        let conn = bring_db_0_back_to_life_and_return_connection(&data_dir.join(DATABASE_FILE));
        let dao = ConfigDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));
        let schema_version_before = dao.get("schema_version").unwrap().value_opt.unwrap();
        let subject = DbInitializerReal::default();

        let result = subject.initialize(
            &data_dir,
            DbInitializationConfig::migration_suppressed_with_error(),
        );

        let err = match result {
            Ok(_) => panic!("expected an Err, got Ok"),
            Err(e) => e,
        };
        assert_eq!(err, InitializationError::SuppressedMigration);
        let schema_version_after = dao.get("schema_version").unwrap().value_opt.unwrap();
        assert_eq!(schema_version_after, schema_version_before)
    }

    #[test]
    fn panic_on_migration_properly_set() {
        assert_eq!(
            DbInitializationConfig::panic_on_migration(),
            DbInitializationConfig {
                mode: InitializationMode::CreationBannedMigrationPanics,
                special_conn_configuration: vec![],
            }
        )
    }

    #[test]
    fn create_or_migrate_properly_set() {
        assert_eq!(
            DbInitializationConfig::create_or_migrate(make_external_data()),
            DbInitializationConfig {
                mode: InitializationMode::CreationAndMigration {
                    external_data: make_external_data()
                },
                special_conn_configuration: vec![],
            }
        )
    }

    #[test]
    fn migration_suppressed_properly_set() {
        assert_eq!(
            DbInitializationConfig::migration_suppressed(),
            DbInitializationConfig {
                mode: InitializationMode::CreationBannedMigrationSuppressed,
                special_conn_configuration: vec![],
            }
        )
    }

    #[test]
    fn suppressed_with_error_properly_set() {
        assert_eq!(
            DbInitializationConfig::migration_suppressed_with_error(),
            DbInitializationConfig {
                mode: InitializationMode::CreationBannedMigrationRaisesErr,
                special_conn_configuration: vec![],
            }
        )
    }

    fn make_default_config_with_different_pointers(
        pointers: Vec<fn(&Connection) -> rusqlite::Result<()>>,
    ) -> DbInitializationConfig {
        DbInitializationConfig {
            mode: InitializationMode::CreationBannedMigrationPanics,
            special_conn_configuration: pointers,
        }
    }

    fn make_config_filled_with_external_data() -> DbInitializationConfig {
        DbInitializationConfig {
            mode: InitializationMode::CreationAndMigration {
                external_data: ExternalData {
                    chain: Default::default(),
                    neighborhood_mode: NeighborhoodModeLight::Standard,
                    db_password_opt: None,
                },
            },
            special_conn_configuration: vec![|_: &_| Ok(())],
        }
    }

    #[test]
    fn partial_eq_is_implemented_for_db_initialization_config() {
        let fn_one = |_: &_| Ok(());
        let fn_two = |_: &_| Err(rusqlite::Error::GetAuxWrongType);
        let config_one = make_default_config_with_different_pointers(vec![fn_one]);
        //Rust doesn't allow differentiate between fn pointers
        let config_two = make_default_config_with_different_pointers(vec![fn_two]);
        let config_three = make_default_config_with_different_pointers(vec![]);
        let config_four = make_default_config_with_different_pointers(vec![fn_one, fn_one]);
        let config_five = DbInitializationConfig {
            mode: InitializationMode::CreationBannedMigrationSuppressed,
            special_conn_configuration: vec![fn_one],
        };
        let config_six = make_config_filled_with_external_data();

        assert_eq!(config_one, config_one);
        assert_eq!(config_one, config_two);
        //down from here, only inequality
        assert_ne!(config_one, config_three);
        assert_ne!(config_one, config_four);
        assert_ne!(config_one, config_five);
        assert_ne!(config_one, config_six)
    }

    #[test]
    fn debug_is_implemented_for_db_initialization_config() {
        let fn_one = |_: &_| Ok(());
        let fn_two = |_: &_| Err(rusqlite::Error::GetAuxWrongType);
        let config_one = make_config_filled_with_external_data();
        let config_two = make_default_config_with_different_pointers(vec![fn_one, fn_two]);

        let config_one_debug = format!("{:?}", config_one);
        let config_two_debug = format!("{:?}", config_two);

        let regex_one = Regex::new("special_conn_setup: Addresses\\[\\d+\\]").unwrap();
        let regex_two = Regex::new("special_conn_setup: Addresses\\[\\d+(, \\d+)*\\]").unwrap();
        assert!(
            config_one_debug.contains(
                    "DbInitializationConfig{init_config: CreationAndMigration { external_data: \
                     ExternalData { chain: PolyMainnet, neighborhood_mode: Standard, db_password_opt: \
                      None } }, special_conn_setup: Addresses["
                ),
            "instead, the first printed message contained: {}",
            config_one_debug
        );
        assert!(
            config_two_debug.contains(
                "DbInitializationConfig{init_config: \
             CreationBannedMigrationPanics, special_conn_setup: Addresses["
            ),
            "instead, the second printed message contained: {}",
            config_two_debug
        );
        assert!(regex_one.is_match(&config_one_debug));
        assert!(regex_two.is_match(&config_two_debug))
    }

    #[test]
    fn choose_clandestine_port_chooses_different_unused_ports_each_time() {
        let _listeners = (0..10)
            .map(|_| {
                let port = DbInitializerReal::choose_clandestine_port();
                TcpListener::bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), port)))
                    .expect(&format!("Port {} was not free", port))
            })
            .collect::<Vec<TcpListener>>();
    }

    #[test]
    fn choose_clandestine_port_chooses_ports_between_the_minimum_and_maximum() {
        let clandestine_port_value = DbInitializerReal::choose_clandestine_port();
        assert!(
            clandestine_port_value >= LOWEST_USABLE_INSECURE_PORT,
            "clandestine_port_value should have been > 1024, but was {}",
            clandestine_port_value
        );
        assert!(
            clandestine_port_value <= HIGHEST_RANDOM_CLANDESTINE_PORT,
            "clandestine_port_value should have been < 10000, but was {}",
            clandestine_port_value
        );
    }

    #[test]
    fn nonexistent_directory_is_created_when_possible() {
        let data_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "nonexistent_directory_is_created_when_possible",
        );

        DbInitializerReal::create_data_directory_if_necessary(&data_dir);

        // If .unwrap() succeeds, test passes!(If not, it gives a better failure message than .is_ok())
        fs::read_dir(data_dir).unwrap();
    }

    #[test]
    fn directory_is_unmolested_if_present() {
        let data_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "directory_is_unmolested_if_present",
        );
        {
            let mut file = File::create(data_dir.join("booga.txt")).unwrap();
            file.write_all(b"unmolested").unwrap();
        }

        DbInitializerReal::create_data_directory_if_necessary(&data_dir);

        let mut file = File::open(data_dir.join("booga.txt")).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(String::from("unmolested"), contents);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic(expected = "Cannot create specified data directory at ")]
    fn linux_panic_if_directory_is_nonexistent_and_cant_be_created() {
        panic_if_directory_is_nonexistent_and_cant_be_created(&create_read_only_directory())
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[should_panic(expected = "Cannot create specified data directory at ")]
    fn macos_panic_if_directory_is_nonexistent_and_cant_be_created() {
        panic_if_directory_is_nonexistent_and_cant_be_created(&create_read_only_directory())
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic(expected = "Cannot create specified data directory at ")]
    fn windows_panic_if_directory_is_nonexistent_and_cant_be_created() {
        let base_path = PathBuf::from("M:\\nonexistent");
        panic_if_directory_is_nonexistent_and_cant_be_created(&base_path);
    }

    fn panic_if_directory_is_nonexistent_and_cant_be_created(base_path: &PathBuf) {
        DbInitializerReal::create_data_directory_if_necessary(&base_path.join("home"));
    }

    #[cfg(not(target_os = "windows"))]
    fn create_read_only_directory() -> PathBuf {
        let parent_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "panic_if_directory_is_nonexistent_and_cant_be_created",
        );
        let data_dir = parent_dir.join("uncreatable");
        match fs::metadata(&parent_dir) {
            Err(_) => (),
            Ok(metadata) => {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                fs::set_permissions(&parent_dir, permissions).unwrap();
            }
        }
        let mut permissions = fs::metadata(&parent_dir).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&parent_dir, permissions).unwrap();
        data_dir
    }
}
