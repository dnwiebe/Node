// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::db_access_objects::utils::DaoFactoryReal;
use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionSafeWrapper};
use masq_lib::utils::to_string;
use rusqlite::types::ToSql;
use rusqlite::{Row, Rows, Statement};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfigDaoError {
    NotPresent,
    TransactionError,
    DatabaseError(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfigDaoRecord {
    pub name: String,
    pub value_opt: Option<String>,
    pub encrypted: bool,
}

impl ConfigDaoRecord {
    pub fn new(name: &str, value: Option<&str>, encrypted: bool) -> Self {
        Self {
            name: name.to_string(),
            value_opt: value.map(to_string),
            encrypted,
        }
    }

    pub fn new_owned(name: String, value_opt: Option<String>, encrypted: bool) -> Self {
        Self {
            name,
            value_opt,
            encrypted,
        }
    }
}

pub trait ConfigDao {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError>;
    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError>;
    fn set(&self, name: &str, value: Option<String>) -> Result<(), ConfigDaoError>;
    fn set_by_guest_transaction(
        &self,
        txn: &mut TransactionSafeWrapper,
        name: &str,
        value: Option<String>,
    ) -> Result<(), ConfigDaoError>;
}

pub struct ConfigDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl ConfigDao for ConfigDaoReal {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        let stmt = self
            .conn
            .prepare("select name, value, encrypted from config")
            .expect("Schema error: couldn't compose query for config table");
        get_all(stmt)
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        let stmt = self
            .conn
            .prepare("select name, value, encrypted from config where name = ?")
            .expect("Schema error: couldn't compose query for config table");
        get(stmt, name)
    }

    fn set(&self, name: &str, value: Option<String>) -> Result<(), ConfigDaoError> {
        let prepare_stm = |stm: &str| self.conn.prepare(stm);
        Self::set_value(prepare_stm, name, value)
    }

    fn set_by_guest_transaction(
        &self,
        txn: &mut TransactionSafeWrapper,
        name: &str,
        value: Option<String>,
    ) -> Result<(), ConfigDaoError> {
        let prepare_stm = |stm: &str| txn.prepare(stm);
        Self::set_value(prepare_stm, name, value)
    }
}

impl ConfigDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ConfigDaoReal {
        ConfigDaoReal { conn }
    }

    fn set_value<'a, P>(
        prepare_stmt: P,
        name: &str,
        value: Option<String>,
    ) -> Result<(), ConfigDaoError>
    where
        P: FnOnce(&str) -> Result<Statement<'a>, rusqlite::Error> + 'a,
    {
        let mut stmt = match prepare_stmt("update config set value = ? where name = ?") {
            Ok(stmt) => stmt,
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        let params: &[&dyn ToSql] = &[&value, &name];
        handle_update_execution(stmt.execute(params))
    }
}

pub trait ConfigDaoFactory {
    fn make(&self) -> Box<dyn ConfigDao>;
}

impl ConfigDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn ConfigDao> {
        Box::new(ConfigDaoReal::new(self.make_connection()))
    }
}

fn handle_update_execution(result: rusqlite::Result<usize>) -> Result<(), ConfigDaoError> {
    match result {
        Ok(0) => Err(ConfigDaoError::NotPresent),
        Ok(_) => Ok(()),
        // The following line is untested, because we don't know how to trigger it.
        Err(e) => Err(ConfigDaoError::DatabaseError(format!("{}", e))),
    }
}

fn get_all(mut stmt: Statement) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
    let mut rows: Rows = stmt
        .query([])
        .expect("Schema error: couldn't dump config table");
    let mut results = Vec::new();
    loop {
        match rows.next() {
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
            Ok(Some(row)) => {
                let name: String = row.get(0).expect("Schema error: no name column");
                let value_opt: Option<String> = row.get(1).expect("Schema error: no value column");
                let encrypted: i32 = row.get(2).expect("Schema error: no encrypted column");
                match value_opt {
                    Some(s) => results.push(ConfigDaoRecord::new(
                        &name,
                        Some(s.as_str()),
                        encrypted != 0,
                    )),
                    None => results.push(ConfigDaoRecord::new(&name, None, encrypted != 0)),
                }
            }
            Ok(None) => break,
        }
    }
    Ok(results)
}

fn get(mut stmt: Statement, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
    match stmt.query_row(&[name], |row| Ok(row_to_config_dao_record(row))) {
        Ok(record) => Ok(record),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(ConfigDaoError::NotPresent),
        // The following line is untested, because we don't know how to trigger it.
        Err(e) => Err(ConfigDaoError::DatabaseError(format!("{}", e))),
    }
}

fn row_to_config_dao_record(row: &Row) -> ConfigDaoRecord {
    let name: String = row.get(0).expect("Schema error: no name column");
    let value_opt: Option<String> = row.get(1).expect("Schema error: no value column");
    let encrypted_int: i32 = row.get(2).expect("Schema error: no encrypted column");
    match value_opt {
        Some(value) => ConfigDaoRecord::new(&name, Some(&value), encrypted_int != 0),
        None => ConfigDaoRecord::new(&name, None, encrypted_int != 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::DbInitializationConfig;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::test_utils::ConnectionWrapperMock;
    use crate::test_utils::assert_contains;
    use masq_lib::constants::CURRENT_SCHEMA_VERSION;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection;
    use std::path::Path;

    #[test]
    fn get_all_returns_multiple_results() {
        let home_dir =
            ensure_node_home_directory_exists("config_dao", "get_all_returns_multiple_results");
        let subject = make_subject(&home_dir);

        let result = subject.get_all().unwrap();

        assert_contains(
            &result,
            &ConfigDaoRecord::new(
                "schema_version",
                Some(&CURRENT_SCHEMA_VERSION.to_string()),
                false,
            ),
        );
        assert_contains(&result, &ConfigDaoRecord::new("start_block", None, false));
        assert_contains(
            &result,
            &ConfigDaoRecord::new("consuming_wallet_private_key", None, true),
        );
    }

    #[test]
    fn get_returns_not_present_if_row_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dao",
            "get_returns_not_present_if_row_doesnt_exist",
        );
        let subject = make_subject(&home_dir);

        let result = subject.get("booga");

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn set_and_get_work() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "set_and_get_work");
        let subject = make_subject(&home_dir);
        let modified_value = ConfigDaoRecord::new(
            "consuming_wallet_private_key",
            Some("Two wrongs don't make a right, but two Wrights make an airplane"),
            true,
        );

        subject
            .set(
                "consuming_wallet_private_key",
                Some("Two wrongs don't make a right, but two Wrights make an airplane".to_string()),
            )
            .unwrap();
        let subject_get_all = subject.get_all().unwrap();
        let subject_get = subject.get("consuming_wallet_private_key").unwrap();

        assert_contains(&subject_get_all, &modified_value);
        assert_eq!(subject_get, modified_value);
    }

    #[test]
    fn setting_nonexistent_value_returns_not_present() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dao",
            "setting_nonexistent_value_returns_not_present",
        );
        let subject = make_subject(&home_dir);

        let result = subject.set("booga", Some("bigglesworth".to_string()));

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn setting_value_to_none_removes_value_but_not_row() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dao",
            "setting_value_to_none_removes_value_but_not_row",
        );
        let subject = make_subject(&home_dir);

        subject.set("schema_version", None).unwrap();

        let result = subject.get("schema_version").unwrap();
        assert_eq!(result, ConfigDaoRecord::new("schema_version", None, false));
    }

    #[test]
    fn test_handle_update_execution() {
        let result = handle_update_execution(Err(rusqlite::Error::ExecuteReturnedResults));

        assert_eq!(
            result,
            Err(ConfigDaoError::DatabaseError(
                "Execute returned results - did you mean to call query?".to_string()
            ))
        )
    }

    #[test]
    fn set_by_guest_transaction_works() {
        let home_dir =
            ensure_node_home_directory_exists("config_dao", "set_by_guest_transaction_works");
        // We give a useless "Connection" to the DAO object, making it more obvious it was the guest
        // connection that did all the job
        let subject = ConfigDaoReal::new(Box::new(ConnectionWrapperMock::default()));
        // Here we create a database, undoubtedly with the schema same as CURRENT_SCHEMA_VERSION
        let mut conn = initialize_conn(&home_dir);
        let mut txn = conn.transaction().unwrap();
        let different_than_current_schema_version = CURRENT_SCHEMA_VERSION + 3;
        let dif_schema_version_str = different_than_current_schema_version.to_string();

        subject
            .set_by_guest_transaction(
                &mut txn,
                "schema_version",
                Some(dif_schema_version_str.clone()),
            )
            .unwrap();

        let assert_dao = make_subject(&home_dir);
        let result_before_commit = assert_dao.get("schema_version").unwrap();
        assert_eq!(
            result_before_commit,
            ConfigDaoRecord::new(
                "schema_version",
                Some(&CURRENT_SCHEMA_VERSION.to_string()),
                false
            )
        );
        txn.commit().unwrap();
        let result_after_commit = assert_dao.get("schema_version").unwrap();
        assert_eq!(
            result_after_commit,
            ConfigDaoRecord::new("schema_version", Some(&dif_schema_version_str), false)
        );
    }

    #[test]
    fn set_value_handles_error() {
        let conn = Connection::open_in_memory().unwrap();
        let prepare_stm = |stm: &str| conn.prepare(stm);

        let result = ConfigDaoReal::set_value(prepare_stm, "bubbles", None);

        assert_eq!(
            result,
            Err(ConfigDaoError::DatabaseError(
                "no such table: config".to_string()
            ))
        )
    }

    fn make_subject(home_dir: &Path) -> ConfigDaoReal {
        ConfigDaoReal::new(initialize_conn(home_dir))
    }

    fn initialize_conn(home_dir: &Path) -> Box<dyn ConnectionWrapper> {
        DbInitializerReal::default()
            .initialize(home_dir, DbInitializationConfig::test_default())
            .unwrap()
    }
}
