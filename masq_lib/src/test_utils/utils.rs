// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use crate::test_utils::environment_guard::EnvironmentGuard;
use serde_derive::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const TEST_DEFAULT_CHAIN: Chain = Chain::EthRopsten;
pub const TEST_DEFAULT_MULTINODE_CHAIN: Chain = Chain::Dev;
pub const BASE_TEST_DIR: &str = "generated/test";
const MASQ_SOURCE_CODE_UNAVAILABLE: &str = "MASQ_SOURCE_CODE_UNAVAILABLE";

#[derive(Serialize)]
pub struct LogObject {
    // Strings are all hexadecimal
    pub removed: bool,
    #[serde(rename = "logIndex")]
    pub log_index: Option<String>,
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<String>,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<String>,
    #[serde(rename = "blockHash")]
    pub block_hash: Option<String>,
    #[serde(rename = "blockNumber")]
    pub block_number: Option<String>,
    pub address: String,
    pub data: String,
    pub topics: Vec<String>,
}

pub fn node_home_directory(module: &str, name: &str) -> PathBuf {
    let home_dir_string = format!("{}/{}/{}/home", BASE_TEST_DIR, module, name);
    PathBuf::from(home_dir_string.as_str())
}

pub fn ensure_node_home_directory_does_not_exist(module: &str, name: &str) -> PathBuf {
    let home_dir = node_home_directory(module, name);
    let _ = fs::remove_dir_all(&home_dir);
    home_dir
}

pub fn ensure_node_home_directory_exists(module: &str, name: &str) -> PathBuf {
    let home_dir = node_home_directory(module, name);
    let _ = fs::remove_dir_all(&home_dir);
    let _ = fs::create_dir_all(&home_dir);
    home_dir
}

pub fn is_running_under_github_actions() -> bool {
    is_env_variable_set("GITHUB_ACTIONS", "true")
}

pub fn is_test_generated_data_allowed_to_escape_project_dir() -> bool {
    is_env_variable_set("ALLOW_TEST_DATA_ESCAPE_PROJECT_DIR", "true")
}

fn is_env_variable_set(var_name: &str, searched_value: &str) -> bool {
    if let Ok(value) = std::env::var(var_name) {
        value == searched_value
    } else {
        false
    }
}

pub trait UrlHolder {
    fn url(&self) -> String;
}

#[derive(PartialEq, Eq)]
pub enum ShouldWeRunTheTest {
    GoAhead,
    Skip,
}

pub fn check_if_source_code_is_attached(current_dir: &Path) -> ShouldWeRunTheTest {
    let _guard = EnvironmentGuard::new();
    if current_dir.join("src").exists() && current_dir.join("Cargo.toml").exists() {
        ShouldWeRunTheTest::GoAhead
    } else if std::env::var(MASQ_SOURCE_CODE_UNAVAILABLE).is_ok() {
        eprintln!(
            "Trying to run a test dependent on reading the source code which wasn't \
             found. Nevertheless, MASQ_SOURCE_CODE_UNAVAILABLE environment variable has been \
              supplied; skipping this test."
        );
        ShouldWeRunTheTest::Skip
    } else {
        panic!(
            "Test depending on interaction with the source code, but it was not found at \
             {:?}. If that does not surprise you, set the environment variable \
              MASQ_SOURCE_CODE_UNAVAILABLE to some non-blank value and run the tests again.",
            current_dir
        )
    }
}

pub fn to_millis(dur: &Duration) -> u64 {
    (dur.as_secs() * 1000) + (u64::from(dur.subsec_nanos()) / 1_000_000)
}

#[cfg(not(feature = "no_test_share"))]
pub struct MutexIncrementInset(pub usize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(TEST_DEFAULT_CHAIN, Chain::EthRopsten);
        assert_eq!(TEST_DEFAULT_MULTINODE_CHAIN, Chain::Dev);
        assert_eq!(BASE_TEST_DIR, "generated/test");
    }
}
