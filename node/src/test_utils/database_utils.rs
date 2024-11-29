// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::utils::VigilantRusqliteFlatten;
use crate::database::db_initializer::ExternalData;
use crate::database::rusqlite_wrappers::ConnectionWrapper;

use crate::database::db_migrations::db_migrator::DbMigrator;
use masq_lib::logger::Logger;
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
use masq_lib::utils::{to_string, NeighborhoodModeLight};
use rusqlite::{Connection, Error};
use std::cell::RefCell;
use std::env::current_dir;
use std::fs::{remove_file, File};
use std::io::Read;
use std::iter::once;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub fn bring_db_0_back_to_life_and_return_connection(db_path: &Path) -> Connection {
    match remove_file(db_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!("Unexpected but serious error: {}", e),
        _ => (),
    };
    let conn = Connection::open(&db_path).unwrap();
    let file_path = current_dir()
        .unwrap()
        .join("src")
        .join("test_utils")
        .join("database_version_0_sql.txt");
    let mut file = File::open(file_path).unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    buffer.lines().for_each(|stm| {
        conn.execute(stm, []).unwrap();
    });
    conn
}

#[derive(Default)]
pub struct DbMigratorMock {
    logger: Option<Logger>,
    migrate_database_result: RefCell<Vec<Result<(), String>>>,
    migrate_database_params: Arc<Mutex<Vec<(usize, usize, Box<dyn ConnectionWrapper>)>>>,
}

impl DbMigratorMock {
    pub fn migrate_database_result(self, result: Result<(), String>) -> Self {
        self.migrate_database_result.borrow_mut().push(result);
        self
    }
    pub fn migrate_database_params(
        mut self,
        params: &Arc<Mutex<Vec<(usize, usize, Box<dyn ConnectionWrapper>)>>>,
    ) -> Self {
        self.migrate_database_params = params.clone();
        self
    }

    pub fn inject_logger(mut self) -> Self {
        self.logger = Some(Logger::new("DbMigrator"));
        self
    }
}

impl DbMigrator for DbMigratorMock {
    fn migrate_database(
        &self,
        outdated_schema: usize,
        target_version: usize,
        conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String> {
        self.migrate_database_params
            .lock()
            .unwrap()
            .push((outdated_schema, target_version, conn));
        self.migrate_database_result.borrow_mut().pop().unwrap()
    }
}

pub fn retrieve_config_row(conn: &dyn ConnectionWrapper, name: &str) -> (Option<String>, bool) {
    let sql = "select value, encrypted from config where name = ?";
    let mut statement = conn.prepare(sql).unwrap();
    statement
        .query_row([name], |r| {
            let value_opt: Option<String> = r.get(0).unwrap();
            let encrypted_num: u64 = r.get(1).unwrap();
            let encrypted_flag = match encrypted_num {
                0 => false,
                1 => true,
                x => panic!("Encrypted flag must be 0 or 1, not {}", x),
            };
            Ok((value_opt, encrypted_flag))
        })
        .unwrap_or_else(|e| {
            panic!(
                "panicked at {} for statement: {} on parameter '{}'",
                e, sql, name
            )
        })
}

pub fn assert_table_does_not_exist(conn: &dyn ConnectionWrapper, table_name: &str) {
    let error_stm = conn
        .prepare(&format!("select * from {}", table_name))
        .unwrap_err();
    let error_msg = match error_stm {
        Error::SqliteFailure(_, Some(msg)) => msg,
        x => panic!("we expected SqliteFailure but we got: {:?}", x),
    };
    assert_eq!(error_msg, format!("no such table: {}", table_name))
}

pub fn assert_create_table_stm_contains_all_parts(
    conn: &dyn ConnectionWrapper,
    table_name: &str,
    expected_sql_chopped: ExpectedLinesOfSQLChoppedIntoWords,
) {
    assert_sql_lines_contain_parts_exhaustive(
        parse_sql_to_pieces(&fetch_table_sql(conn, table_name)),
        expected_sql_chopped,
    )
}

pub fn assert_index_stm_is_coupled_with_right_parameter(
    conn: &dyn ConnectionWrapper,
    index_name: &str,
    expected_sql_chopped: ExpectedLinesOfSQLChoppedIntoWords,
) {
    assert_sql_lines_contain_parts_exhaustive(
        parse_sql_to_pieces(&fetch_index_sql(conn, index_name)),
        expected_sql_chopped,
    )
}

pub fn assert_no_index_exists_for_table(conn: &dyn ConnectionWrapper, table_name: &str) {
    let table_name = isolated_name(table_name);
    query_specific_schema_information(conn, "index")
        .iter()
        .for_each(|index_stm| {
            assert!(
                !index_stm.contains(&table_name),
                "unexpected index on this table: {}",
                index_stm
            )
        })
}

pub fn assert_table_created_as_strict(conn: &dyn ConnectionWrapper, table_name: &str) {
    let payable_creation_sql = fetch_table_sql(conn, table_name);
    let last_word_reversed = payable_creation_sql
        .chars()
        .rev()
        .skip_while(|char| char.is_whitespace())
        .take_while(|char| !char.is_whitespace())
        .collect::<String>();
    let last_word = last_word_reversed.chars().rev().collect::<String>();
    assert_eq!(
        last_word, "strict",
        "we expected the 'strict' key word but got: {}",
        last_word
    )
}

fn zippered<'a>(
    actual: &'a Vec<Vec<String>>,
    expected: ExpectedLinesOfSQLChoppedIntoWords,
) -> Vec<(SQLLinesChoppedIntoWords, &'a Vec<String>)> {
    once(prepare_expected_vectors_of_words_including_sorting(
        expected,
    ))
    .cycle()
    .zip(actual.iter())
    .collect()
}

fn assert_sql_lines_contain_parts_exhaustive(
    actual: SQLLinesChoppedIntoWords,
    expected: ExpectedLinesOfSQLChoppedIntoWords,
) {
    zippered(&actual, expected)
        .iter()
        .for_each(|(left, right)| contains_particular_list_of_key_words(left, right))
}

fn contains_particular_list_of_key_words(
    expected_words: &SQLLinesChoppedIntoWords,
    single_actual_line_of_words: &[String],
) {
    let mut found = 0_u16;
    expected_words.iter().for_each(|vec_of_words_expected| {
        if single_actual_line_of_words == vec_of_words_expected {
            found += 1
        }
    });
    assert_eq!(found, 1, "We found {} occurrences of the searched line in the tested sql although only a one is considered correct", found)
}

fn prepare_expected_vectors_of_words_including_sorting(
    expected: ExpectedLinesOfSQLChoppedIntoWords,
) -> SQLLinesChoppedIntoWords {
    expected
        .into_iter()
        .map(|slice_of_strs| {
            let mut one_line = slice_of_strs
                .into_iter()
                .map(to_string)
                .collect::<Vec<String>>();
            one_line.sort();
            one_line
        })
        .collect()
}

type SQLLinesChoppedIntoWords = Vec<Vec<String>>;

type ExpectedLinesOfSQLChoppedIntoWords<'a> = &'a [&'a [&'a str]];

//prepares collections of isolated key words from a column declaration, by lines
fn parse_sql_to_pieces(sql: &str) -> SQLLinesChoppedIntoWords {
    let body: String = sql
        .chars()
        .skip_while(|char| char != &'(')
        .skip(1)
        .take_while(|char| char != &')')
        .collect();
    let lines = body.split(',');
    lines
        .map(|sql_line| {
            let mut vec_of_words = sql_line
                .split(|char: char| char.is_whitespace())
                .filter(|chunk| !chunk.is_empty())
                .map(to_string)
                .collect::<Vec<String>>();
            vec_of_words.sort();
            vec_of_words
        })
        .collect()
}

fn fetch_table_sql(conn: &dyn ConnectionWrapper, specific_table: &str) -> String {
    let found_table_sqls = query_specific_schema_information(conn, "table");
    select_desired_sql_element(found_table_sqls, &isolated_name(specific_table))
}

fn fetch_index_sql(conn: &dyn ConnectionWrapper, index_name: &str) -> String {
    let found_indexes = query_specific_schema_information(conn, "index");
    select_desired_sql_element(found_indexes, &isolated_name(index_name))
}

fn isolated_name(name: &str) -> String {
    format!(" {} ", name)
}

fn query_specific_schema_information(
    conn: &dyn ConnectionWrapper,
    query_object: &str,
) -> Vec<String> {
    let mut table_stm = conn
        .prepare(&format!(
            "SELECT sql FROM sqlite_master WHERE type='{}'",
            query_object
        ))
        .unwrap();
    table_stm
        .query_map([], |row| Ok(row.get::<usize, Option<String>>(0).unwrap()))
        .unwrap()
        .vigilant_flatten()
        .flatten()
        .collect()
}

fn select_desired_sql_element(found_elements: Vec<String>, searched_element_name: &str) -> String {
    let mut searched_element: Vec<String> = found_elements
        .into_iter()
        .flat_map(|element| {
            let introducing_part: String =
                element.chars().take_while(|char| char != &'(').collect();
            if introducing_part.contains(searched_element_name) {
                Some(element.to_lowercase())
            } else {
                None
            }
        })
        .collect();
    if searched_element.len() != 1 {
        panic!(
            "search failed, we should've found one matching element but got {}",
            searched_element.len()
        )
    }
    searched_element.remove(0)
}

pub fn make_external_data() -> ExternalData {
    ExternalData {
        chain: TEST_DEFAULT_CHAIN,
        neighborhood_mode: NeighborhoodModeLight::Standard,
        db_password_opt: None,
    }
}
