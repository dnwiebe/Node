// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::{CURRENT_LOGFILE_NAME, DEFAULT_CHAIN, DEFAULT_UI_PORT};
use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, node_home_directory};
use masq_lib::utils::{add_masq_and_chain_directories, localhost};
use node_lib::database::db_initializer::{
    DbInitializationConfig, DbInitializer, DbInitializerReal,
};
use node_lib::database::rusqlite_wrappers::ConnectionWrapper;
use node_lib::test_utils::await_value;
use regex::{Captures, Regex};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::env;
use std::io;
use std::iter::once;
use std::net::SocketAddr;
use std::ops::{Drop, Not};
use std::path::{Path, PathBuf};
use std::process;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(Debug)]
pub struct MASQNode {
    pub data_dir: PathBuf,
    child: Option<process::Child>,
    output: Option<Output>,
}

#[derive(Clone, Debug)]
pub struct CommandConfig {
    pub args: Vec<String>,
}

impl CommandConfig {
    pub fn new() -> CommandConfig {
        CommandConfig { args: vec![] }
    }

    #[allow(dead_code)]
    pub fn opt(mut self, option: &str) -> CommandConfig {
        self.args.push(option.to_string());
        self
    }

    pub fn pair(mut self, option: &str, value: &str) -> CommandConfig {
        self.args.push(option.to_string());
        self.args.push(value.to_string());
        self
    }

    pub fn value_of(&self, parameter: &str) -> Option<String> {
        for n in 0..self.args.len() {
            if self.args[n] == parameter {
                if (n + 1) >= self.args.len() {
                    return None;
                }
                return Some(self.args[n + 1].clone());
            }
        }
        None
    }
}

impl Drop for MASQNode {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

impl MASQNode {
    pub fn path_to_logfile(data_dir: &Path) -> Box<Path> {
        data_dir.join(CURRENT_LOGFILE_NAME).into_boxed_path()
    }

    pub fn path_to_database(data_dir: &PathBuf) -> Box<Path> {
        data_dir.join("node-data.db").into_boxed_path()
    }

    #[allow(dead_code)]
    pub fn output(&mut self) -> Option<Output> {
        self.output.take()
    }

    pub fn start_daemon(
        test_name: &str,
        config_opt: Option<CommandConfig>,
        sterile_database: bool,
        sterile_logfile: bool,
        piped_output: bool,
        ensure_start: bool,
    ) -> MASQNode {
        Self::start_something(
            test_name,
            config_opt,
            sterile_database,
            sterile_logfile,
            piped_output,
            ensure_start,
            Self::make_daemon_command,
        )
    }

    #[allow(dead_code)]
    pub fn start_standard(
        test_name: &str,
        config_opt: Option<CommandConfig>,
        sterile_database: bool,
        sterile_logfile: bool,
        piped_output: bool,
        ensure_start: bool,
    ) -> MASQNode {
        Self::start_something(
            test_name,
            config_opt,
            sterile_database,
            sterile_logfile,
            piped_output,
            ensure_start,
            Self::make_node_command,
        )
    }

    #[allow(dead_code)]
    pub fn start_with_blank_config(
        test_name: &str,
        config_opt: Option<CommandConfig>,
        sterile_database: bool,
        sterile_logfile: bool,
        piped_output: bool,
        ensure_start: bool,
    ) -> MASQNode {
        Self::start_something(
            test_name,
            config_opt,
            sterile_database,
            sterile_logfile,
            piped_output,
            ensure_start,
            Self::make_node_without_initial_config,
        )
    }

    #[allow(dead_code)]
    pub fn run_dump_config(
        test_name: &str,
        config_opt: Option<CommandConfig>,
        sterile_database: bool,
        sterile_logfile: bool,
        piped_output: bool,
        ensure_start: bool,
    ) -> MASQNode {
        Self::start_something(
            test_name,
            config_opt,
            sterile_database,
            sterile_logfile,
            piped_output,
            ensure_start,
            Self::make_dump_config_command,
        )
    }

    #[allow(dead_code)]
    pub fn wait_for_log(&mut self, regex_pattern: &str, limit_ms: Option<u64>) {
        Self::wait_for_match_at_directory(regex_pattern, &self.data_dir.as_path(), limit_ms);
    }

    pub fn wait_for_match_at_directory(pattern: &str, logfile_dir: &Path, limit_ms: Option<u64>) {
        let logfile_path = Self::path_to_logfile(logfile_dir);
        let log_output_processor = |log_output: &str, regex: &Regex| -> Option<()> {
            regex.is_match(log_output).then(|| ())
        };
        Self::wait_for_log_at_directory(
            pattern,
            logfile_path.as_ref(),
            log_output_processor,
            limit_ms,
        )
    }

    //fetches all captures by given requirements;
    //you can specify how many times you require to apply the regex and get separate captures (outer vector);
    //also allows to define more than just one capture group and fetch them all at once (inner vector)
    pub fn capture_pieces_of_log_at_directory(
        pattern: &str,
        logfile_dir: &Path,
        required_repetition: usize,
        limit_ms: Option<u64>,
    ) -> Vec<Vec<String>> {
        let logfile_path = Self::path_to_logfile(logfile_dir);

        let log_output_processor = |log_output: &str, regex: &Regex| {
            Self::collect_captures_with_repetition(log_output, regex, required_repetition)
        };

        Self::wait_for_log_at_directory(
            pattern,
            logfile_path.as_ref(),
            log_output_processor,
            limit_ms,
        )
    }

    fn collect_captures_with_repetition(
        log_output: &str,
        regex: &Regex,
        required_repetition: usize,
    ) -> Option<Vec<Vec<String>>> {
        let captures = regex.captures_iter(log_output).collect::<Vec<Captures>>();
        if captures.len() < required_repetition {
            return None;
        }
        let structured_captures = captures
            .into_iter()
            .map(|groups| {
                groups
                    .iter()
                    .flat_map(|group_opt| {
                        group_opt.map(|particular_group_match| {
                            particular_group_match.as_str().to_string()
                        })
                    })
                    .collect::<Vec<String>>()
            })
            .collect::<Vec<Vec<String>>>();
        Some(structured_captures)
    }

    fn wait_for_log_at_directory<T, F>(
        pattern: &str,
        path_to_logfile: &Path,
        log_output_processor: F,
        limit_ms: Option<u64>,
    ) -> T
    where
        F: Fn(&str, &Regex) -> Option<T>,
    {
        let regex = regex::Regex::new(pattern).unwrap();
        let real_limit_ms = limit_ms.unwrap_or(0xFFFFFFFF);
        let started_at = Instant::now();
        let mut read_content_opt = None;
        loop {
            match std::fs::read_to_string(&path_to_logfile) {
                Ok(contents) => {
                    read_content_opt = Some(contents.clone());
                    if let Some(result) = log_output_processor(&contents, &regex) {
                        break result;
                    }
                }
                Err(e) => {
                    eprintln!("Could not read logfile at {:?}: {:?}", path_to_logfile, e);
                }
            };
            assert!(
                MASQNode::millis_since(started_at) < real_limit_ms,
                "Timeout: waited for more than {}ms without finding '{}' in these logs:\n{}\n",
                real_limit_ms,
                pattern,
                match read_content_opt {
                    Some(rc) => rc,
                    None => "None".to_string(),
                }
            );
            thread::sleep(Duration::from_millis(200));
        }
    }

    #[allow(dead_code)]
    pub fn wait_for_exit(&mut self) -> Option<Output> {
        // TODO Put the body of this function in a background thread and wait on the thread for a few
        // seconds. If the thread doesn't terminate, leak the thread and return None.
        let child_opt = self.child.take();
        let output_opt = self.output.take();
        match (child_opt, output_opt) {
            (None, Some(output)) => {
                self.output = Some(output);
                self.output.clone()
            }
            (Some(child), None) => match child.wait_with_output() {
                Ok(output) => Some(output),
                Err(e) => panic!("{:?}", e),
            },
            (Some(_), Some(_)) => panic!("Internal error: Inconsistent MASQ Node state"),
            (None, None) => None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn kill(&mut self) -> Result<process::ExitStatus, io::Error> {
        let child_opt = self.child.take();
        let output_opt = self.output.take();
        Ok(match (child_opt, output_opt) {
            (Some(mut child), None) => {
                child.kill()?;
                let result = child.wait()?;
                self.output = Some(Output {
                    status: result,
                    stdout: vec![],
                    stderr: vec![],
                });
                result
            }
            (None, Some(output)) => {
                let result = output.status.clone();
                self.output = Some(output);
                result
            }
            (Some(_), Some(_)) => panic!("Internal error: Inconsistent MASQ Node state"),
            (None, None) => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        })
    }

    #[cfg(target_os = "windows")]
    pub fn kill(&mut self) -> Result<process::ExitStatus, io::Error> {
        let mut command = process::Command::new("taskkill");
        command.args(&["/IM", "MASQNode.exe", "/F"]);
        let process_output = command
            .output()
            .unwrap_or_else(|e| panic!("Couldn't kill MASQNode.exe: {}", e));
        self.child.take();
        Ok(process_output.status)
    }

    pub fn remove_logfile(data_dir: &PathBuf) -> Box<Path> {
        let logfile_path = Self::path_to_logfile(data_dir);
        match std::fs::remove_file(&logfile_path) {
            Ok(_) => (),
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(ref e) => panic!("{:?}", e),
        }
        logfile_path
    }

    pub fn remove_database(data_dir: &PathBuf, chain: Chain) {
        let data_dir_chain_path = add_masq_and_chain_directories(chain, data_dir);
        let database = Self::path_to_database(&data_dir_chain_path);
        match std::fs::remove_file(&database) {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => panic!(
                "Couldn't remove preexisting database at {:?}: {}",
                database, e
            ),
        }
    }

    fn start_something<F: FnOnce(&PathBuf, Option<CommandConfig>, bool) -> process::Command>(
        test_name: &str,
        config_opt: Option<CommandConfig>,
        sterile_database: bool,
        sterile_logfile: bool,
        piped_streams: bool,
        ensure_start: bool,
        command_getter: F,
    ) -> MASQNode {
        let data_dir = if sterile_database {
            ensure_node_home_directory_exists("integration", test_name)
        } else {
            node_home_directory("integration", test_name)
        };
        if sterile_logfile {
            let _ = Self::remove_logfile(&data_dir);
        }
        let ui_port = Self::ui_port_from_config_opt(&config_opt);
        let mut command = command_getter(&data_dir, config_opt, sterile_database);
        eprintln!("Launching MASQNode with this command: {:?}", command);
        let command = if piped_streams {
            command.stdout(Stdio::piped()).stderr(Stdio::piped())
        } else {
            &mut command
        };
        let mut result = Self::spawn_process(command, data_dir.to_owned());
        if ensure_start {
            result.wait_for_node(ui_port).unwrap();
        }
        result
    }

    fn spawn_process(cmd: &mut Command, data_dir: PathBuf) -> MASQNode {
        let child = cmd.spawn().unwrap();
        MASQNode {
            data_dir,
            child: Some(child),
            output: None,
        }
    }

    fn get_chain_from_config(config_opt: &Option<CommandConfig>) -> Chain {
        match config_opt {
            Some(config) => match config.value_of("--chain") {
                Some(chain_str) => Chain::from(chain_str.as_str()),
                None => DEFAULT_CHAIN,
            },
            None => DEFAULT_CHAIN,
        }
    }

    fn millis_since(started_at: Instant) -> u64 {
        let interval = Instant::now().duration_since(started_at);
        let second_milliseconds = interval.as_secs() * 1000;
        let nanosecond_milliseconds = (interval.subsec_nanos() as u64) / 1000000;
        second_milliseconds + nanosecond_milliseconds
    }

    fn make_daemon_command(
        data_dir: &PathBuf,
        config_opt: Option<CommandConfig>,
        remove_database: bool,
    ) -> process::Command {
        let chain = Self::get_chain_from_config(&config_opt);
        let args = Self::daemon_args();
        let args = Self::extend_args_without_duplication(
            args,
            match config_opt {
                Some(c) => c.args,
                None => vec![],
            },
        );
        Self::start_with_args_extension(chain, data_dir, args, remove_database)
    }

    fn make_node_command(
        data_dir: &PathBuf,
        config_opt: Option<CommandConfig>,
        remove_database: bool,
    ) -> process::Command {
        let chain = Self::get_chain_from_config(&config_opt);
        let args = Self::standard_args();
        let args =
            Self::extend_args_without_duplication(args, Self::get_extra_args(data_dir, config_opt));
        Self::start_with_args_extension(chain, data_dir, args, remove_database)
    }

    fn make_node_without_initial_config(
        data_dir: &PathBuf,
        config_opt: Option<CommandConfig>,
        remove_database: bool,
    ) -> process::Command {
        let chain = Self::get_chain_from_config(&config_opt);
        let args = Self::get_extra_args(data_dir, config_opt);
        Self::start_with_args_extension(chain, data_dir, args, remove_database)
    }

    fn make_dump_config_command(
        data_dir: &PathBuf,
        config_opt: Option<CommandConfig>,
        remove_database: bool,
    ) -> process::Command {
        let chain = Self::get_chain_from_config(&config_opt);
        let mut args = Self::dump_config_args();
        args.extend(Self::get_extra_args(data_dir, config_opt));
        Self::start_with_args_extension(chain, data_dir, args, remove_database)
    }

    fn start_with_args_extension(
        chain: Chain,
        data_dir: &PathBuf,
        additional_args: Vec<String>,
        remove_database: bool,
    ) -> process::Command {
        if remove_database {
            Self::remove_database(data_dir, chain)
        }
        let mut command = command_to_start();
        command.args(apply_prefix_parameters());
        command.args(additional_args);
        command
    }

    fn daemon_args() -> Vec<String> {
        CommandConfig::new().opt("--initialization").args
    }

    fn standard_args() -> Vec<String> {
        CommandConfig::new()
            .pair("--neighborhood-mode", "zero-hop")
            .pair(
                "--consuming-private-key",
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            )
            .pair("--log-level", "trace")
            .pair("--blockchain-service-url", "https://example.com")
            .args
    }

    #[allow(dead_code)]
    fn dump_config_args() -> Vec<String> {
        CommandConfig::new().opt("--dump-config").args
    }

    fn get_extra_args(data_dir: &PathBuf, config_opt: Option<CommandConfig>) -> Vec<String> {
        let mut args = config_opt.unwrap_or(CommandConfig::new()).args;
        if !args.contains(&"--data-directory".to_string()) {
            args.push("--data-directory".to_string());
            args.push(data_dir.to_string_lossy().to_string());
        }
        args
    }

    fn virtual_arg_pairs_with_remembered_position(
        args: Vec<String>,
    ) -> Vec<(String, PositionedArg)> {
        let shifted_by_one = {
            let with_the_first_cut = args.clone().into_iter().map(Some).skip(1);
            let none_added_for_end_param_without_value = with_the_first_cut.chain(once(None));
            none_added_for_end_param_without_value
        };
        let params_and_yet_suspected_args = {
            let zipped = args.into_iter().zip(shifted_by_one.enumerate());
            let ignored_anomalies_with_value_at_the_first_position =
                zipped.filter(|(param, _)| param.starts_with("--"));
            ignored_anomalies_with_value_at_the_first_position
        };
        params_and_yet_suspected_args
            .map(|(param_name, (original_position, suspected_arg_opt))| {
                let construct_positioned_arg = |val_opt| {
                    (
                        param_name,
                        PositionedArg {
                            arg_opt: val_opt,
                            remembered_position: original_position,
                        },
                    )
                };

                match suspected_arg_opt {
                    Some(suspected_arg) => {
                        if suspected_arg.starts_with("--") {
                            construct_positioned_arg(None)
                        } else {
                            construct_positioned_arg(Some(suspected_arg))
                        }
                    }
                    //just to handle the end parameter if it has no value
                    None => construct_positioned_arg(None),
                }
            })
            .collect()
    }

    fn extend_args_without_duplication(
        default_args: Vec<String>,
        config_args: Vec<String>,
    ) -> Vec<String> {
        fn retain_unconfigured_default_args(
            default_args: Vec<String>,
            config_args: &HashMap<String, PositionedArg>,
        ) -> HashMap<String, PositionedArg> {
            MASQNode::virtual_arg_pairs_with_remembered_position(default_args)
                .into_iter()
                .flat_map(|(arg_name, value)| {
                    config_args
                        .keys()
                        .contains(&&arg_name)
                        .not()
                        .then_some((arg_name, value))
                })
                .collect()
        }
        fn hash_map_with_panic_on_duplicated_params(
            config_args_as_tuples: Vec<(String, PositionedArg)>,
        ) -> HashMap<String, PositionedArg> {
            let mut dedup_assert_hashmap = HashMap::new();
            let duplicates: Vec<(String, PositionedArg)> = vec![];
            let duplicates = config_args_as_tuples.into_iter().fold(
                duplicates,
                |mut so_far, (param_name, value)| {
                    match dedup_assert_hashmap.entry(param_name) {
                        Entry::Occupied(occupied_entry) => {
                            so_far.push((occupied_entry.key().to_string(), value))
                        }
                        Entry::Vacant(vacant) => {
                            let _ = vacant.insert(value);
                        }
                    };
                    so_far
                },
            );
            assert!(
                duplicates.is_empty(),
                "You supplied additional arguments with some of \
                them duplicated, use each only once! Duplicates: {:?}",
                duplicates
            );
            dedup_assert_hashmap
        }

        let config_args_as_tuples = Self::virtual_arg_pairs_with_remembered_position(config_args);
        let config_args: HashMap<String, PositionedArg> =
            hash_map_with_panic_on_duplicated_params(config_args_as_tuples);
        let default_args_to_keep = retain_unconfigured_default_args(default_args, &config_args);
        default_args_to_keep
            .into_iter()
            .chain(config_args)
            .sorted_by(|(_, positioned_arg_a), (_, positioned_arg_b)| {
                Ord::cmp(
                    &positioned_arg_a.remembered_position,
                    &positioned_arg_b.remembered_position,
                )
            })
            .flat_map(|(arg_name, positioned_arg)| {
                [Some(arg_name), positioned_arg.arg_opt]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<String>>()
            })
            .collect()
    }

    fn wait_for_node(&mut self, ui_port: u16) -> Result<(), String> {
        let result = await_value(Some((600, 6000)), || {
            let address = SocketAddr::new(localhost(), ui_port);
            match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
                Ok(stream) => {
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    Ok(())
                }
                Err(e) => Err(format!("Can't connect yet on port {}: {:?}", ui_port, e)),
            }
        });
        if result.is_err() {
            self.kill().map_err(|e| format!("{:?}", e))?;
        };
        result
    }

    fn ui_port_from_config_opt(config_opt: &Option<CommandConfig>) -> u16 {
        match config_opt {
            None => DEFAULT_UI_PORT,
            Some(config) => match config.value_of("--ui-port") {
                None => DEFAULT_UI_PORT,
                Some(ui_port_string) => ui_port_string.parse::<u16>().unwrap(),
            },
        }
    }
}

#[derive(Debug)]
struct PositionedArg {
    arg_opt: Option<String>,
    remembered_position: usize,
}

#[cfg(target_os = "windows")]
fn command_to_start() -> process::Command {
    process::Command::new("cmd")
}

#[cfg(not(target_os = "windows"))]
fn command_to_start() -> process::Command {
    let test_command = env::args().next().unwrap();
    let debug_or_release = test_command
        .split("/")
        .skip_while(|s| s != &"target")
        .skip(1)
        .next()
        .unwrap();
    let bin_dir = &format!("target/{}", debug_or_release);
    let command_to_start = &format!("{}/MASQNode", bin_dir);
    process::Command::new(command_to_start)
}

#[cfg(target_os = "windows")]
fn apply_prefix_parameters() -> Vec<String> {
    CommandConfig::new().pair("/c", &node_command()).args
}

#[cfg(not(target_os = "windows"))]
fn apply_prefix_parameters() -> Vec<String> {
    vec![]
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn node_command() -> String {
    let test_command = env::args().next().unwrap();
    let debug_or_release = test_command
        .split("\\")
        .skip_while(|s| s != &"target")
        .skip(1)
        .next()
        .unwrap();
    let bin_dir = &format!("target\\{}", debug_or_release);
    format!("{}\\MASQNode.exe", bin_dir)
}

pub fn make_conn(home_dir: &Path) -> Box<dyn ConnectionWrapper> {
    DbInitializerReal::default()
        .initialize(home_dir, DbInitializationConfig::panic_on_migration())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::MASQNode;
    use masq_lib::utils::slice_of_strs_to_vec_of_strings;

    #[test]
    fn extend_without_duplication_replaces_default_params_with_additionally_supplied_values() {
        let default_args = slice_of_strs_to_vec_of_strings(&[
            "--arg-without-val",
            "--whatever-arg",
            "12345",
            "--different-arg",
            "hello",
            "--final-arg",
            "true",
        ]);
        let args_extension = slice_of_strs_to_vec_of_strings(&[
            "--whatever-arg",
            "789",
            "--unique-arg",
            "blah",
            "--final-arg",
            "false",
        ]);

        let result = MASQNode::extend_args_without_duplication(default_args, args_extension);

        let expected_args = slice_of_strs_to_vec_of_strings(&[
            "--arg-without-val",
            "--whatever-arg",
            "789",
            "--unique-arg",
            "blah",
            "--different-arg",
            "hello",
            "--final-arg",
            "false",
        ]);
        assert_eq!(result, expected_args)
    }

    #[test]
    fn extend_without_duplication_handles_ending_parameter_with_no_value() {
        let default_args = slice_of_strs_to_vec_of_strings(&["--arg1", "value1"]);
        let args_extension = slice_of_strs_to_vec_of_strings(&["--arg2", "value2", "--arg3"]);

        let result = MASQNode::extend_args_without_duplication(default_args, args_extension);

        let expected_args =
            slice_of_strs_to_vec_of_strings(&["--arg1", "value1", "--arg2", "value2", "--arg3"]);
        assert_eq!(result, expected_args)
    }

    #[test]
    #[should_panic(
        expected = "You supplied additional arguments with some of them duplicated, \
    use each only once! Duplicates: [(\"--unique-arg\", PositionedArg { arg_opt: Some(\"booga\"), \
     remembered_position: 6 })]"
    )]
    fn extend_without_duplication_catches_duplicated_config_arg() {
        let default_args =
            slice_of_strs_to_vec_of_strings(&["--default-arg", "val-of-default-arg"]);
        let args_extension = slice_of_strs_to_vec_of_strings(&[
            "--whatever-arg",
            "789",
            "--unique-arg",
            "blah",
            "--final-arg",
            "false",
            "--unique-arg",
            "booga",
        ]);

        let _ = MASQNode::extend_args_without_duplication(default_args, args_extension);
    }
}
