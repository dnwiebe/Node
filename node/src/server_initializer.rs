// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use super::bootstrapper::Bootstrapper;
use super::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::bootstrapper::RealUser;
use crate::entry_dns::dns_socket_server::DnsSocketServer;
use crate::node_configurator::node_configurator_standard::server_initializer_collected_params;
use crate::node_configurator::unprivileged_parse_args_configuration::has_user_specified;
use crate::node_configurator::{DirsWrapper, DirsWrapperReal};
use crate::run_modes_factories::{RunModeResult, ServerInitializer};
use crate::sub_lib::socket_server::ConfiguredByPrivilege;
use backtrace::Backtrace;
use clap::value_t;
use flexi_logger::{
    Cleanup, Criterion, DeferredNow, Duplicate, LevelFilter, LogSpecBuilder, Logger, Naming, Record,
};
use futures::try_ready;
use lazy_static::lazy_static;
use log::{log, Level};
use masq_lib::command::StdStreams;
use masq_lib::logger;
use masq_lib::logger::{real_format_function, POINTER_TO_FORMAT_FUNCTION};
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::ConfiguratorError;
use std::any::Any;
use std::io;
use std::panic::{Location, PanicInfo};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use time::OffsetDateTime;
use tokio::prelude::{Async, Future};

pub struct ServerInitializerReal {
    #[allow(dead_code)]
    dns_socket_server: Box<dyn ConfiguredByPrivilege<Item = (), Error = ()>>,
    bootstrapper: Box<dyn ConfiguredByPrivilege<Item = (), Error = ()>>,
    privilege_dropper: Box<dyn PrivilegeDropper>,
    dirs_wrapper: Box<dyn DirsWrapper>,
    is_entry_dns_enabled: bool,
}

impl ServerInitializer for ServerInitializerReal {
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &[String]) -> RunModeResult {
        let multi_config = server_initializer_collected_params(self.dirs_wrapper.as_ref(), args)?;
        self.is_entry_dns_enabled = has_user_specified(&multi_config, "entry-dns");

        let privileged_result = self.initialize_privileged(&multi_config);
        self.drop_privileges(&multi_config);
        let unprivileged_result = self.initialize_unprivileged(&multi_config, streams);

        privileged_result.combine_results(unprivileged_result)
    }

    as_any_ref_in_trait_impl!();
}

impl ServerInitializerReal {
    fn drop_privileges(&self, multi_config: &MultiConfig) {
        let real_user = value_m!(multi_config, "real-user", RealUser)
            .expect("ServerInitializer: Real user not present in Multi Config");
        let data_directory = value_m!(multi_config, "data-directory", String)
            .expect("ServerInitializer: Data directory not present in Multi Config");

        self.privilege_dropper
            .chown(Path::new(data_directory.as_str()), &real_user);
        self.privilege_dropper.drop_privileges(&real_user);
    }

    fn initialize_privileged(&mut self, multi_config: &MultiConfig) -> RunModeResult {
        let result = match self.is_entry_dns_enabled {
            true => self
                .dns_socket_server
                .as_mut()
                .initialize_as_privileged(multi_config),
            false => Ok(()),
        };

        result.combine_results(
            self.bootstrapper
                .as_mut()
                .initialize_as_privileged(multi_config),
        )
    }

    fn initialize_unprivileged(
        &mut self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams<'_>,
    ) -> RunModeResult {
        let result = match self.is_entry_dns_enabled {
            true => self
                .dns_socket_server
                .as_mut()
                .initialize_as_unprivileged(multi_config, streams),
            false => Ok(()),
        };

        result.combine_results(
            self.bootstrapper
                .as_mut()
                .initialize_as_unprivileged(multi_config, streams),
        )
    }
}

impl Future for ServerInitializerReal {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        match self.is_entry_dns_enabled {
            true => {
                try_ready!(self
                    .dns_socket_server
                    .as_mut()
                    .join(self.bootstrapper.as_mut())
                    .poll());
            }
            false => try_ready!(self.bootstrapper.as_mut().poll()),
        }
        Ok(Async::Ready(()))
    }
}

impl Default for ServerInitializerReal {
    fn default() -> ServerInitializerReal {
        ServerInitializerReal {
            dns_socket_server: Box::new(DnsSocketServer::new()),
            bootstrapper: Box::new(Bootstrapper::new(Box::new(LoggerInitializerWrapperReal {}))),
            privilege_dropper: Box::new(PrivilegeDropperReal::new()),
            dirs_wrapper: Box::new(DirsWrapperReal::default()),
            is_entry_dns_enabled: false,
        }
    }
}

trait ResultsCombiner {
    fn combine_results(self, additional: Self) -> Self;
}

impl ResultsCombiner for RunModeResult {
    fn combine_results(self, additional: Self) -> Self {
        match (self, additional) {
            (Ok(_), Ok(_)) => Ok(()),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), Ok(_)) => Err(e),
            (Err(e1), Err(e2)) => Err(ConfiguratorError::new(
                e1.param_errors
                    .into_iter()
                    .chain(e2.param_errors.into_iter())
                    .collect(),
            )),
        }
    }
}

lazy_static! {
    pub static ref LOGFILE_NAME: Mutex<PathBuf> = Mutex::new(PathBuf::from("uninitialized"));
}

pub trait LoggerInitializerWrapper {
    fn init(
        &mut self,
        file_path: PathBuf,
        real_user: &RealUser,
        log_level: LevelFilter,
        discriminant_opt: Option<&str>,
    );
}

pub struct LoggerInitializerWrapperReal;

impl LoggerInitializerWrapper for LoggerInitializerWrapperReal {
    fn init(
        &mut self,
        file_path: PathBuf,
        real_user: &RealUser,
        log_level: LevelFilter,
        discriminant_opt: Option<&str>,
    ) {
        let mut logger = Logger::with(
            LogSpecBuilder::new()
                .default(log_level)
                .module("tokio", LevelFilter::Off)
                .module("mio", LevelFilter::Off)
                .build(),
        )
        .log_to_file()
        .directory(file_path.clone())
        .print_message()
        .duplicate_to_stderr(Duplicate::Info)
        .suppress_timestamp()
        .format(format_function)
        .rotate(
            Criterion::Size(100_000_000),
            Naming::Numbers,
            Cleanup::KeepZipFiles(50),
        );
        if let Some(discriminant) = discriminant_opt {
            logger = logger.discriminant(discriminant);
        }
        logger.start().expect("Logging subsystem failed to start");
        let privilege_dropper = PrivilegeDropperReal::new();
        let logfile_name = file_path.join(format!(
            "MASQNode_{}rCURRENT.log",
            match discriminant_opt {
                Some(discriminant) => format!("{}_", discriminant),
                None => "".to_string(),
            }
        ));
        privilege_dropper.chown(&logfile_name, real_user);
        *(Self::logfile_name_guard()) = logfile_name;
        std::panic::set_hook(Box::new(|panic_info| {
            panic_hook(AltPanicInfo::from(panic_info))
        }));

        // Info level is not shown within the log
        log!(Level::Info, "{}", logger::Logger::log_file_heading());

        unsafe {
            // This resets the format function after specialized formatting for the log heading is used.
            POINTER_TO_FORMAT_FUNCTION = real_format_function;
        }
    }
}

impl LoggerInitializerWrapperReal {
    pub fn get_logfile_name() -> PathBuf {
        let path: &Path = &(*(Self::logfile_name_guard()).clone());
        path.to_path_buf()
    }

    #[cfg(test)]
    pub fn set_logfile_name(logfile_name: PathBuf) {
        *(Self::logfile_name_guard()) = logfile_name;
    }

    fn logfile_name_guard<'a>() -> MutexGuard<'a, PathBuf> {
        match LOGFILE_NAME.lock() {
            Ok(guard) => guard,
            Err(poison_err) => poison_err.into_inner(),
        }
    }
}

struct AltLocation {
    file: String,
    line: u32,
    col: u32,
}

// Location can't be constructed in a test; therefore this implementation is untestable
impl<'a> From<&'a Location<'a>> for AltLocation {
    fn from(location: &Location) -> Self {
        AltLocation {
            file: location.file().to_string(),
            line: location.line(),
            col: location.column(),
        }
    }
}

struct AltPanicInfo<'a> {
    payload: &'a (dyn Any + Send),
    location: Option<AltLocation>,
}

// PanicInfo can't be constructed in a test; therefore this implementation is untestable
impl<'a> From<&'a PanicInfo<'a>> for AltPanicInfo<'a> {
    fn from(panic_info: &'a PanicInfo) -> Self {
        AltPanicInfo {
            payload: panic_info.payload(),
            location: panic_info.location().map(AltLocation::from),
        }
    }
}

fn panic_hook(panic_info: AltPanicInfo) {
    let location = match panic_info.location {
        None => "<unknown location>".to_string(),
        Some(location) => format!("{}:{}:{}", location.file, location.line, location.col),
    };
    let message = if let Some(s) = panic_info.payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic_info.payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<message indecipherable>".to_string()
    };
    let logger = masq_lib::logger::Logger::new("PanicHandler");
    error!(logger, "{} - {}", location, message);
    let backtrace = Backtrace::new();
    error!(logger, "{:?}", backtrace);
}

// DeferredNow can't be constructed in a test; therefore this function is untestable.
fn format_function(
    write: &mut dyn io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), io::Error> {
    let pointer_to_format_function = unsafe { POINTER_TO_FORMAT_FUNCTION };
    pointer_to_format_function(write, OffsetDateTime::now_utc(), record)
}

#[cfg(test)]
pub mod test_utils {
    use crate::bootstrapper::RealUser;
    use crate::privilege_drop::PrivilegeDropper;
    use crate::server_initializer::LoggerInitializerWrapper;
    use log::LevelFilter;
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    pub struct PrivilegeDropperMock {
        drop_privileges_params: Arc<Mutex<Vec<RealUser>>>,
        chown_params: Arc<Mutex<Vec<(PathBuf, RealUser)>>>,
        expect_privilege_params: Arc<Mutex<Vec<bool>>>,
        expect_privilege_results: RefCell<Vec<bool>>,
    }

    impl PrivilegeDropper for PrivilegeDropperMock {
        fn drop_privileges(&self, real_user: &RealUser) {
            self.drop_privileges_params
                .lock()
                .unwrap()
                .push(real_user.clone());
        }

        fn chown(&self, file: &Path, real_user: &RealUser) {
            self.chown_params
                .lock()
                .unwrap()
                .push((file.to_path_buf(), real_user.clone()));
        }

        fn expect_privilege(&self, privilege_expected: bool) -> bool {
            self.expect_privilege_params
                .lock()
                .unwrap()
                .push(privilege_expected);
            self.expect_privilege_results.borrow_mut().remove(0)
        }
    }

    impl PrivilegeDropperMock {
        pub fn new() -> Self {
            Self {
                drop_privileges_params: Arc::new(Mutex::new(vec![])),
                chown_params: Arc::new(Mutex::new(vec![])),
                expect_privilege_params: Arc::new(Mutex::new(vec![])),
                expect_privilege_results: RefCell::new(vec![]),
            }
        }

        pub fn drop_privileges_params(mut self, params: &Arc<Mutex<Vec<RealUser>>>) -> Self {
            self.drop_privileges_params = params.clone();
            self
        }

        pub fn chown_params(mut self, params: &Arc<Mutex<Vec<(PathBuf, RealUser)>>>) -> Self {
            self.chown_params = params.clone();
            self
        }

        pub fn expect_privilege_params(mut self, params: &Arc<Mutex<Vec<bool>>>) -> Self {
            self.expect_privilege_params = params.clone();
            self
        }

        pub fn expect_privilege_result(self, result: bool) -> Self {
            self.expect_privilege_results.borrow_mut().push(result);
            self
        }
    }

    pub struct LoggerInitializerWrapperMock {
        init_parameters: Arc<Mutex<Vec<(PathBuf, RealUser, LevelFilter, Option<String>)>>>,
    }

    impl LoggerInitializerWrapper for LoggerInitializerWrapperMock {
        fn init(
            &mut self,
            file_path: PathBuf,
            real_user: &RealUser,
            log_level: LevelFilter,
            name_segment: Option<&str>,
        ) {
            self.init_parameters.lock().unwrap().push((
                file_path,
                real_user.clone(),
                log_level,
                match name_segment {
                    Some(s) => Some(s.to_string()),
                    None => None,
                },
            ));
        }
    }

    impl LoggerInitializerWrapperMock {
        pub fn new() -> LoggerInitializerWrapperMock {
            LoggerInitializerWrapperMock {
                init_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn init_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(PathBuf, RealUser, LevelFilter, Option<String>)>>>,
        ) -> Self {
            self.init_parameters = parameters.clone();
            self
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::bootstrapper::BootstrapperConfig;
    use crate::crash_test_dummy::CrashTestDummy;
    use crate::node_test_utils::DirsWrapperMock;
    use crate::server_initializer::test_utils::PrivilegeDropperMock;
    use crate::test_utils::logfile_name_guard::LogfileNameGuard;
    use crate::test_utils::unshared_test_utils::make_pre_populated_mocked_directory_wrapper;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::crash_point::CrashPoint;
    use masq_lib::multi_config::MultiConfig;
    use masq_lib::shared_schema::{ConfiguratorError, ParamError};
    use masq_lib::test_utils::fake_stream_holder::{
        ByteArrayReader, ByteArrayWriter, FakeStreamHolder,
    };
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::utils::slice_of_strs_to_vec_of_strings;
    use std::cell::RefCell;
    use std::ops::Not;
    use std::sync::{Arc, Mutex};

    impl<C: Send + 'static> ConfiguredByPrivilege for CrashTestDummy<C> {
        fn initialize_as_privileged(
            &mut self,
            _multi_config: &MultiConfig,
        ) -> Result<(), ConfiguratorError> {
            Ok(())
        }

        fn initialize_as_unprivileged(
            &mut self,
            _multi_config: &MultiConfig,
            _streams: &mut StdStreams<'_>,
        ) -> Result<(), ConfiguratorError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct ConfiguredByPrivilegeMock {
        queried_values_from_multi_config: RefCell<Vec<String>>,
        initialize_as_privileged_params: Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        initialize_as_privileged_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
        initialize_as_unprivileged_params: Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        initialize_as_unprivileged_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
    }

    impl Future for ConfiguredByPrivilegeMock {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
            intentionally_blank!()
        }
    }

    pub fn ingest_values_from_multi_config(
        requested_params: &RefCell<Vec<String>>,
        resulting_values: &Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        multi_config: &MultiConfig,
    ) {
        if requested_params.borrow().is_empty().not() {
            resulting_values.lock().unwrap().push(
                MultiConfigExtractedValues::default()
                    .ingest_entries_on_demand(&requested_params.borrow(), multi_config),
            )
        };
    }

    impl<'a> ConfiguredByPrivilege for ConfiguredByPrivilegeMock {
        fn initialize_as_privileged(
            &mut self,
            multi_config: &MultiConfig,
        ) -> Result<(), ConfiguratorError> {
            ingest_values_from_multi_config(
                &self.queried_values_from_multi_config,
                &self.initialize_as_privileged_params,
                multi_config,
            );
            self.initialize_as_privileged_results.borrow_mut().remove(0)
        }

        fn initialize_as_unprivileged(
            &mut self,
            multi_config: &MultiConfig,
            _streams: &mut StdStreams,
        ) -> Result<(), ConfiguratorError> {
            ingest_values_from_multi_config(
                &self.queried_values_from_multi_config,
                &self.initialize_as_unprivileged_params,
                multi_config,
            );
            self.initialize_as_unprivileged_results
                .borrow_mut()
                .remove(0)
        }
    }

    impl ConfiguredByPrivilegeMock {
        pub fn define_demanded_values_from_multi_config(self, mut values: Vec<String>) -> Self {
            self.queried_values_from_multi_config
                .borrow_mut()
                .append(&mut values);
            self
        }

        pub fn initialize_as_privileged_params(
            mut self,
            params: &Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        ) -> Self {
            self.initialize_as_privileged_params = params.clone();
            self
        }

        pub fn initialize_as_privileged_result(
            self,
            result: Result<(), ConfiguratorError>,
        ) -> Self {
            self.initialize_as_privileged_results
                .borrow_mut()
                .push(result);
            self
        }

        pub fn initialize_as_unprivileged_params(
            mut self,
            params: &Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        ) -> Self {
            self.initialize_as_unprivileged_params = params.clone();
            self
        }

        pub fn initialize_as_unprivileged_result(
            self,
            result: Result<(), ConfiguratorError>,
        ) -> Self {
            self.initialize_as_unprivileged_results
                .borrow_mut()
                .push(result);
            self
        }
    }

    #[derive(Default)]
    pub struct MultiConfigExtractedValues {
        pub arg_matches_requested_entries: Vec<String>,
    }

    impl MultiConfigExtractedValues {
        pub fn ingest_entries_on_demand(
            mut self,
            required: &[String],
            multi_config: &MultiConfig,
        ) -> Self {
            self.arg_matches_requested_entries = required
                .iter()
                .map(|key| {
                    multi_config
                        .arg_matches_ref()
                        .value_of(key)
                        .unwrap()
                        .to_string()
                })
                .collect();
            self
        }
    }

    #[test]
    fn combine_results_combines_success_and_success() {
        let initial_success: RunModeResult = Ok(());
        let additional_success: RunModeResult = Ok(());

        let result = initial_success.combine_results(additional_success);

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn combine_results_combines_success_and_failure() {
        let initial_success: RunModeResult = Ok(());
        let additional_failure: RunModeResult = Err(ConfiguratorError::new(vec![
            ParamError::new("param-one", "Reason One"),
            ParamError::new("param-two", "Reason Two"),
        ]));

        let result = initial_success.combine_results(additional_failure);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![
                ParamError::new("param-one", "Reason One"),
                ParamError::new("param-two", "Reason Two"),
            ]))
        );
    }

    #[test]
    fn combine_results_combines_failure_and_success() {
        let initial_failure: RunModeResult = Err(ConfiguratorError::new(vec![
            ParamError::new("param-one", "Reason One"),
            ParamError::new("param-two", "Reason Two"),
        ]));
        let additional_success: RunModeResult = Ok(());

        let result = initial_failure.combine_results(additional_success);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![
                ParamError::new("param-one", "Reason One"),
                ParamError::new("param-two", "Reason Two"),
            ]))
        );
    }

    #[test]
    fn combine_results_combines_failure_and_failure() {
        let initial_failure: RunModeResult = Err(ConfiguratorError::new(vec![
            ParamError::new("param-one", "Reason One"),
            ParamError::new("param-two", "Reason Two"),
        ]));
        let additional_failure: RunModeResult = Err(ConfiguratorError::new(vec![
            ParamError::new("param-two", "Reason Three"),
            ParamError::new("param-three", "Reason Four"),
        ]));

        let result = initial_failure.combine_results(additional_failure);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![
                ParamError::new("param-one", "Reason One"),
                ParamError::new("param-two", "Reason Two"),
                ParamError::new("param-two", "Reason Three"),
                ParamError::new("param-three", "Reason Four"),
            ]))
        );
    }

    #[test]
    fn panic_hook_handles_missing_location_and_unprintable_payload() {
        init_test_logging();
        let panic_info = AltPanicInfo {
            payload: &ConfiguredByPrivilegeMock::default(), // not a String or a &str
            location: None,
        };

        panic_hook(panic_info);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            "ERROR: PanicHandler: <unknown location> - <message indecipherable>",
        );
    }

    #[test]
    fn panic_hook_handles_existing_location_and_string_payload() {
        init_test_logging();
        let panic_info = AltPanicInfo {
            payload: &"I am a full-fledged String".to_string(),
            location: Some(AltLocation {
                file: "file.txt".to_string(),
                line: 24,
                col: 42,
            }),
        };

        panic_hook(panic_info);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            "ERROR: PanicHandler: file.txt:24:42 - I am a full-fledged String",
        );
        // TODO: Make this assertion work. Suggestion: isolate it in a test file so that it only sees its own logs.
        //tlh.exists_log_containing("panic_hook_handles_existing_location_and_string_payload");
    }

    #[test]
    fn panic_hook_handles_existing_location_and_string_slice_payload() {
        init_test_logging();
        let panic_info = AltPanicInfo {
            payload: &"I'm just a string slice",
            location: Some(AltLocation {
                file: "file.txt".to_string(),
                line: 24,
                col: 42,
            }),
        };

        panic_hook(panic_info);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("ERROR: PanicHandler: file.txt:24:42 - I'm just a string slice");
    }

    #[test]
    fn go_updates_entry_dns_flag() {
        let _ = LogfileNameGuard::new(&PathBuf::from("go_updates_entry_dns_flag"));
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = make_pre_populated_mocked_directory_wrapper();
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dirs_wrapper: Box::new(dirs_wrapper),
            is_entry_dns_enabled: false,
        };

        let _ = subject.go(
            &mut StdStreams {
                stdin: &mut ByteArrayReader::new(&[0; 0]),
                stdout: &mut ByteArrayWriter::new(),
                stderr: &mut ByteArrayWriter::new(),
            },
            &slice_of_strs_to_vec_of_strings(&["MASQNode", "--entry-dns"]),
        );

        assert!(subject.is_entry_dns_enabled);
    }

    #[test]
    fn go_maintains_entry_dns_flag_disabled_if_absent_in_args() {
        let _ = LogfileNameGuard::new(&PathBuf::from(
            "go_maintains_entry_dns_flag_disabled_if_absent_in_args",
        ));
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = make_pre_populated_mocked_directory_wrapper();
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dirs_wrapper: Box::new(dirs_wrapper),
            is_entry_dns_enabled: false,
        };

        let _ = subject.go(
            &mut StdStreams {
                stdin: &mut ByteArrayReader::new(&[0; 0]),
                stdout: &mut ByteArrayWriter::new(),
                stderr: &mut ByteArrayWriter::new(),
            },
            &slice_of_strs_to_vec_of_strings(&["MASQNode"]), //  "--entry-dns" is absent
        );

        assert!(!subject.is_entry_dns_enabled);
    }

    #[test]
    fn exits_after_all_socket_servers_exit() {
        let _ = LogfileNameGuard::new(&PathBuf::from("exits_after_all_socket_servers_exit"));
        let dns_socket_server = CrashTestDummy::new(CrashPoint::Error, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::Error, BootstrapperConfig::new());
        let dirs_wrapper = make_pre_populated_mocked_directory_wrapper();
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dirs_wrapper: Box::new(dirs_wrapper),
            is_entry_dns_enabled: false,
        };
        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };
        subject
            .go(streams, &slice_of_strs_to_vec_of_strings(&["MASQNode"]))
            .unwrap();
        let res = subject.wait();

        assert!(res.is_err());
    }

    #[test]
    fn server_initializer_as_a_future() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = DirsWrapperMock::new();

        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dirs_wrapper: Box::new(dirs_wrapper),
            is_entry_dns_enabled: false,
        };

        let result = subject.poll();
        assert_eq!(result, Ok(Async::Ready(())))
    }

    #[test]
    #[should_panic(expected = "EntryDnsServerMock was instructed to panic")]
    fn server_initializer_dns_socket_server_panics() {
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = DirsWrapperMock::new();

        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(CrashTestDummy::panic(
                "EntryDnsServerMock was instructed to panic".to_string(),
                (),
            )),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dirs_wrapper: Box::new(dirs_wrapper),
            is_entry_dns_enabled: true,
        };

        let _ = subject.poll();
    }

    #[test]
    #[should_panic(expected = "BootstrapperMock was instructed to panic")]
    fn server_initializer_bootstrapper_panics() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = DirsWrapperMock::new();
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(CrashTestDummy::panic(
                "BootstrapperMock was instructed to panic".to_string(),
                BootstrapperConfig::new(),
            )),
            privilege_dropper: Box::new(privilege_dropper),
            dirs_wrapper: Box::new(dirs_wrapper),
            is_entry_dns_enabled: false,
        };

        let _ = subject.poll();
    }

    #[test]
    fn go_should_drop_privileges() {
        let _ = LogfileNameGuard::new(&PathBuf::from("go_should_drop_privileges"));
        let bootstrapper_init_privileged_params_arc = Arc::new(Mutex::new(vec![]));
        let bootstrapper_init_unprivileged_params_arc = Arc::new(Mutex::new(vec![]));
        let dns_socket_server_privileged_params_arc = Arc::new(Mutex::new(vec![]));
        let dns_socket_server_unprivileged_params_arc = Arc::new(Mutex::new(vec![]));
        let bootstrapper = ConfiguredByPrivilegeMock::default()
            .initialize_as_privileged_result(Ok(()))
            .initialize_as_unprivileged_result(Ok(()))
            .initialize_as_privileged_params(&bootstrapper_init_privileged_params_arc)
            .initialize_as_unprivileged_params(&bootstrapper_init_unprivileged_params_arc)
            .define_demanded_values_from_multi_config(slice_of_strs_to_vec_of_strings(&[
                "dns-servers",
                "real-user",
            ]));
        let dns_socket_server = ConfiguredByPrivilegeMock::default()
            .initialize_as_privileged_result(Ok(()))
            .initialize_as_unprivileged_result(Ok(()))
            .initialize_as_privileged_params(&dns_socket_server_privileged_params_arc)
            .initialize_as_unprivileged_params(&dns_socket_server_unprivileged_params_arc)
            .define_demanded_values_from_multi_config(slice_of_strs_to_vec_of_strings(&[
                "dns-servers",
                "real-user",
            ]));
        let dirs_wrapper = make_pre_populated_mocked_directory_wrapper();
        let drop_privileges_params_arc = Arc::new(Mutex::new(vec![]));
        let chown_params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .drop_privileges_params(&drop_privileges_params_arc)
            .chown_params(&chown_params_arc);
        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dirs_wrapper: Box::new(dirs_wrapper),
            is_entry_dns_enabled: false,
        };

        let result = subject.go(
            streams,
            &slice_of_strs_to_vec_of_strings(&[
                "MASQNode",
                "--real-user",
                "123:456:/home/alice",
                "--dns-servers",
                "5.5.6.6",
                "--entry-dns",
            ]),
        );

        assert!(result.is_ok());
        let real_user = RealUser::new(Some(123), Some(456), Some("/home/alice".into()));
        let chown_params = chown_params_arc.lock().unwrap();
        assert_eq!(
            *chown_params,
            vec![(
                PathBuf::from(format!(
                    "/home/alice/mock_directory/MASQ/{}",
                    DEFAULT_CHAIN.rec().literal_identifier
                )),
                real_user.clone()
            )]
        );
        let drop_privileges_params = drop_privileges_params_arc.lock().unwrap();
        assert_eq!(*drop_privileges_params, vec![real_user]);
        let params_for_assertion_on_multi_config = vec!["5.5.6.6", "123:456:/home/alice"];
        [
            bootstrapper_init_privileged_params_arc,
            bootstrapper_init_unprivileged_params_arc,
            dns_socket_server_privileged_params_arc,
            dns_socket_server_unprivileged_params_arc,
        ]
        .iter()
        .for_each(|arc_params| {
            let param_vec = arc_params.lock().unwrap();
            assert_eq!(
                *param_vec[0].arg_matches_requested_entries,
                params_for_assertion_on_multi_config
            )
        })
    }

    #[test]
    fn go_should_combine_errors() {
        let _ = LogfileNameGuard::new(&PathBuf::from("go_should_combine_errors"));
        let dns_socket_server = ConfiguredByPrivilegeMock::default()
            .initialize_as_privileged_result(Err(ConfiguratorError::required(
                "dns-iap",
                "dns-iap-reason",
            )))
            .initialize_as_unprivileged_result(Err(ConfiguratorError::required(
                "dns-iau",
                "dns-iau-reason",
            )));
        let bootstrapper = ConfiguredByPrivilegeMock::default()
            .initialize_as_privileged_result(Err(ConfiguratorError::required(
                "boot-iap",
                "boot-iap-reason",
            )))
            .initialize_as_unprivileged_result(Err(ConfiguratorError::required(
                "boot-iau",
                "boot-iau-reason",
            )));
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dirs_wrapper: Box::new(make_pre_populated_mocked_directory_wrapper()),
            is_entry_dns_enabled: false,
        };
        let args = slice_of_strs_to_vec_of_strings(&[
            "MASQNode",
            "--real-user",
            "123:123:/home/alice",
            "--entry-dns",
        ]);
        let stderr = ByteArrayWriter::new();
        let mut holder = FakeStreamHolder::new();
        holder.stderr = stderr;

        let result = subject.go(&mut holder.streams(), &args);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![
                ParamError::new("dns-iap", "dns-iap-reason"),
                ParamError::new("boot-iap", "boot-iap-reason"),
                ParamError::new("dns-iau", "dns-iau-reason"),
                ParamError::new("boot-iau", "boot-iau-reason"),
            ]))
        );
    }
}
