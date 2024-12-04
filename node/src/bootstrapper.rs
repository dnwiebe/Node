// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::DEFAULT_PENDING_TOO_LONG_SEC;
use crate::actor_system_factory::ActorSystemFactory;
use crate::actor_system_factory::ActorSystemFactoryReal;
use crate::actor_system_factory::{ActorFactoryReal, ActorSystemFactoryToolsReal};
use crate::crash_test_dummy::CrashTestDummy;
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::discriminator::DiscriminatorFactory;
use crate::json_discriminator_factory::JsonDiscriminatorFactory;
use crate::listener_handler::ListenerHandler;
use crate::listener_handler::ListenerHandlerFactory;
use crate::listener_handler::ListenerHandlerFactoryReal;
use crate::neighborhood::DEFAULT_MIN_HOPS;
use crate::node_configurator::node_configurator_standard::{
    NodeConfiguratorStandardPrivileged, NodeConfiguratorStandardUnprivileged,
};
use crate::node_configurator::{initialize_database, DirsWrapper, NodeConfigurator};
use crate::privilege_drop::{IdWrapper, IdWrapperReal};
use crate::server_initializer::LoggerInitializerWrapper;
use crate::stream_handler_pool::StreamHandlerPoolSubs;
use crate::sub_lib::accountant;
use crate::sub_lib::accountant::{PaymentThresholds, ScanIntervals};
use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::cryptde_real::CryptDEReal;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::neighborhood::{NeighborhoodConfig, NeighborhoodMode};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::socket_server::ConfiguredByPrivilege;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::utils::db_connection_launch_panic;
use crate::sub_lib::wallet::Wallet;
use futures::try_ready;
use itertools::Itertools;
use log::LevelFilter;
use masq_lib::blockchains::chains::Chain;
use masq_lib::command::StdStreams;
use masq_lib::constants::DEFAULT_UI_PORT;
use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
use masq_lib::utils::AutomapProtocol;
use std::collections::HashMap;
use std::env::var;
use std::fmt;
use std::fmt::{Debug, Display, Error, Formatter};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::vec::Vec;
use tokio::prelude::stream::futures_unordered::FuturesUnordered;
use tokio::prelude::Async;
use tokio::prelude::Future;
use tokio::prelude::Stream;

static mut MAIN_CRYPTDE_BOX_OPT: Option<Box<dyn CryptDE>> = None;
static mut ALIAS_CRYPTDE_BOX_OPT: Option<Box<dyn CryptDE>> = None;

fn main_cryptde_ref<'a>() -> &'a dyn CryptDE {
    unsafe {
        MAIN_CRYPTDE_BOX_OPT
            .as_ref()
            .expect("Internal error: Main CryptDE uninitialized")
            .as_ref()
    }
}

fn alias_cryptde_ref<'a>() -> &'a dyn CryptDE {
    unsafe {
        ALIAS_CRYPTDE_BOX_OPT
            .as_ref()
            .expect("Internal error: Alias CryptDE uninitialized")
            .as_ref()
    }
}

impl Clone for CryptDEPair {
    fn clone(&self) -> Self {
        Self {
            main: self.main,
            alias: self.alias,
        }
    }
}

#[derive(Copy)]
pub struct CryptDEPair {
    // This has the public key by which this Node is known to other Nodes on the network
    pub main: &'static dyn CryptDE,
    // This has the public key with which this Node instructs exit Nodes to encrypt responses.
    // In production, it is unrelated to the main public key to prevent the exit Node from
    // identifying the originating Node. In tests using --fake-public-key, the alias public key
    // is the main public key reversed.
    pub alias: &'static dyn CryptDE,
}

impl Default for CryptDEPair {
    fn default() -> Self {
        CryptDEPair {
            main: main_cryptde_ref(),
            alias: alias_cryptde_ref(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortConfiguration {
    pub discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    pub is_clandestine: bool,
}

impl PortConfiguration {
    pub fn new(
        discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
        is_clandestine: bool,
    ) -> PortConfiguration {
        PortConfiguration {
            discriminator_factories,
            is_clandestine,
        }
    }
}

pub trait EnvironmentWrapper: Send {
    fn var(&self, key: &str) -> Option<String>;
}

pub struct EnvironmentWrapperReal;

impl EnvironmentWrapper for EnvironmentWrapperReal {
    fn var(&self, key: &str) -> Option<String> {
        match var(key) {
            Ok(s) => Some(s),
            Err(_) => None,
        }
    }
}

pub struct RealUser {
    environment_wrapper: Box<dyn EnvironmentWrapper>,
    pub uid_opt: Option<i32>,
    pub gid_opt: Option<i32>,
    pub home_dir_opt: Option<PathBuf>,
}

impl Debug for RealUser {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(
            f,
            "uid: {:?}, gid: {:?}, home_dir: {:?}",
            self.uid_opt, self.gid_opt, self.home_dir_opt
        )
    }
}

impl PartialEq for RealUser {
    fn eq(&self, other: &Self) -> bool {
        self.uid_opt == other.uid_opt
            && self.gid_opt == other.gid_opt
            && self.home_dir_opt == other.home_dir_opt
    }
}

impl Default for RealUser {
    fn default() -> Self {
        RealUser::null()
    }
}

impl Clone for RealUser {
    fn clone(&self) -> Self {
        RealUser::new(self.uid_opt, self.gid_opt, self.home_dir_opt.clone())
    }
}

impl FromStr for RealUser {
    type Err = ();

    fn from_str(triple: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = triple.splitn(3, ':').collect_vec();
        // validator should have ensured that there are exactly three parts,
        // and that the first two are empty or numeric
        if parts.len() < 3 {
            return Err(());
        }
        let real_user = RealUser::new(
            match &parts[0] {
                s if s.is_empty() => None,
                s => match s.parse() {
                    Ok(uid) => Some(uid),
                    Err(_) => return Err(()),
                },
            },
            match &parts[1] {
                s if s.is_empty() => None,
                s => match s.parse() {
                    Ok(gid) => Some(gid),
                    Err(_) => return Err(()),
                },
            },
            match &parts[2] {
                s if s.is_empty() => None,
                s => Some(s.into()),
            },
        );
        Ok(real_user)
    }
}

impl RealUser {
    pub fn new(
        uid_opt: Option<i32>,
        gid_opt: Option<i32>,
        home_dir_opt: Option<PathBuf>,
    ) -> RealUser {
        let mut result = RealUser {
            environment_wrapper: Box::new(EnvironmentWrapperReal),
            uid_opt: None,
            gid_opt: None,
            home_dir_opt,
        };
        result.initialize_ids(Box::new(IdWrapperReal {}), uid_opt, gid_opt);
        result
    }

    pub fn null() -> RealUser {
        RealUser {
            environment_wrapper: Box::new(EnvironmentWrapperReal),
            uid_opt: None,
            gid_opt: None,
            home_dir_opt: None,
        }
    }

    pub fn populate(&self, dirs_wrapper: &dyn DirsWrapper) -> RealUser {
        let uid = Self::first_present(vec![self.uid_opt, self.id_from_env("SUDO_UID")]);
        let gid = Self::first_present(vec![self.gid_opt, self.id_from_env("SUDO_GID")]);
        let home_dir = Self::first_present(vec![
            self.home_dir_opt.clone(),
            self.sudo_home_from_sudo_user_and_home(),
            dirs_wrapper.home_dir(),
        ]);
        RealUser::new(Some(uid), Some(gid), Some(home_dir))
    }

    #[cfg(not(target_os = "windows"))]
    fn sudo_home_from_sudo_user_and_home(&self) -> Option<PathBuf> {
        self.environment_wrapper
            .var("SUDO_USER")
            .map(Self::home_dir_from_sudo_user)
    }

    #[cfg(target_os = "windows")]
    fn sudo_home_from_sudo_user_and_home(&self) -> Option<PathBuf> {
        None
    }

    #[cfg(target_os = "linux")]
    fn home_dir_from_sudo_user(sudo_user: String) -> PathBuf {
        format!("/home/{}", sudo_user).into()
    }

    #[cfg(target_os = "macos")]
    fn home_dir_from_sudo_user(sudo_user: String) -> PathBuf {
        format!("/Users/{}", sudo_user).into()
    }

    fn id_from_env(&self, name: &str) -> Option<i32> {
        match self.environment_wrapper.var(name) {
            Some(s) => match s.parse::<i32>() {
                Ok(n) => Some(n),
                Err(_) => None,
            },
            None => None,
        }
    }

    fn first_present<T>(candidates: Vec<Option<T>>) -> T {
        candidates
            .into_iter()
            .find(|t_opt| t_opt.is_some())
            .expect("Nothing was present")
            .expect("Internal error")
    }

    fn initialize_ids(
        &mut self,
        id_wrapper: Box<dyn IdWrapper>,
        uid_opt: Option<i32>,
        gid_opt: Option<i32>,
    ) {
        self.uid_opt = Some(uid_opt.unwrap_or_else(|| {
            self.id_from_env("SUDO_UID")
                .unwrap_or_else(|| id_wrapper.getuid())
        }));
        self.gid_opt = Some(gid_opt.unwrap_or_else(|| {
            self.id_from_env("SUDO_GID")
                .unwrap_or_else(|| id_wrapper.getgid())
        }));
    }
}

impl Display for RealUser {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            match self.uid_opt {
                Some(uid) => format!("{}", uid),
                None => "".to_string(),
            },
            match self.gid_opt {
                Some(gid) => format!("{}", gid),
                None => "".to_string(),
            },
            match &self.home_dir_opt {
                Some(home_dir) => home_dir.to_string_lossy().to_string(),
                None => "".to_string(),
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct BootstrapperConfig {
    // These fields can be set while privileged without penalty
    pub log_level: LevelFilter,
    pub dns_servers: Vec<SocketAddr>,
    pub scan_intervals_opt: Option<ScanIntervals>,
    pub suppress_initial_scans: bool,
    pub when_pending_too_long_sec: u64,
    pub crash_point: CrashPoint,
    pub clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    pub ui_gateway_config: UiGatewayConfig,
    pub blockchain_bridge_config: BlockchainBridgeConfig,
    pub port_configurations: HashMap<u16, PortConfiguration>,
    pub data_directory: PathBuf,
    pub node_descriptor: NodeDescriptor,
    pub main_cryptde_null_opt: Option<CryptDENull>,
    pub alias_cryptde_null_opt: Option<CryptDENull>,
    pub mapping_protocol_opt: Option<AutomapProtocol>,
    pub real_user: RealUser,
    pub payment_thresholds_opt: Option<PaymentThresholds>,

    // These fields must be set without privilege: otherwise the database will be created as root
    pub db_password_opt: Option<String>,
    pub clandestine_port_opt: Option<u16>,
    pub consuming_wallet_opt: Option<Wallet>,
    pub earning_wallet: Wallet,
    pub neighborhood_config: NeighborhoodConfig,
}

impl Default for BootstrapperConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapperConfig {
    pub fn new() -> BootstrapperConfig {
        BootstrapperConfig {
            // These fields can be set while privileged without penalty
            log_level: LevelFilter::Off,
            dns_servers: vec![],
            scan_intervals_opt: None,
            suppress_initial_scans: false,
            crash_point: CrashPoint::None,
            clandestine_discriminator_factories: vec![],
            ui_gateway_config: UiGatewayConfig {
                ui_port: DEFAULT_UI_PORT,
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            data_directory: PathBuf::new(),
            node_descriptor: NodeDescriptor::default(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: None,
            real_user: RealUser::new(None, None, None),
            payment_thresholds_opt: Default::default(),

            // These fields must be set without privilege: otherwise the database will be created as root
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: accountant::DEFAULT_EARNING_WALLET.clone(),
            consuming_wallet_opt: None,
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop,
                min_hops: DEFAULT_MIN_HOPS,
            },
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
        }
    }

    pub fn merge_unprivileged(&mut self, unprivileged: BootstrapperConfig) {
        self.blockchain_bridge_config.gas_price = unprivileged.blockchain_bridge_config.gas_price;
        self.blockchain_bridge_config.blockchain_service_url_opt = unprivileged
            .blockchain_bridge_config
            .blockchain_service_url_opt;
        self.clandestine_port_opt = unprivileged.clandestine_port_opt;
        self.neighborhood_config = unprivileged.neighborhood_config;
        self.earning_wallet = unprivileged.earning_wallet;
        self.consuming_wallet_opt = unprivileged.consuming_wallet_opt;
        self.db_password_opt = unprivileged.db_password_opt;
        self.scan_intervals_opt = unprivileged.scan_intervals_opt;
        self.suppress_initial_scans = unprivileged.suppress_initial_scans;
        self.payment_thresholds_opt = unprivileged.payment_thresholds_opt;
        self.when_pending_too_long_sec = unprivileged.when_pending_too_long_sec;
    }

    pub fn exit_service_rate(&self) -> u64 {
        self.neighborhood_config.mode.rate_pack().exit_service_rate
    }

    pub fn exit_byte_rate(&self) -> u64 {
        self.neighborhood_config.mode.rate_pack().exit_byte_rate
    }

    pub fn routing_service_rate(&self) -> u64 {
        self.neighborhood_config
            .mode
            .rate_pack()
            .routing_service_rate
    }

    pub fn routing_byte_rate(&self) -> u64 {
        self.neighborhood_config.mode.rate_pack().routing_byte_rate
    }
}

pub struct Bootstrapper {
    listener_handler_factory: Box<dyn ListenerHandlerFactory>,
    listener_handlers: FuturesUnordered<Box<dyn ListenerHandler<Item = (), Error = ()>>>,
    actor_system_factory: Box<dyn ActorSystemFactory>,
    logger_initializer: Box<dyn LoggerInitializerWrapper>,
    config: BootstrapperConfig,
}

impl Future for Bootstrapper {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        try_ready!(CrashTestDummy::new(self.config.crash_point, BootstrapperConfig::new()).poll());
        try_ready!(self.listener_handlers.poll());
        Ok(Async::Ready(()))
    }
}

impl ConfiguredByPrivilege for Bootstrapper {
    fn initialize_as_privileged(
        &mut self,
        multi_config: &MultiConfig,
    ) -> Result<(), ConfiguratorError> {
        self.config = NodeConfiguratorStandardPrivileged::new().configure(multi_config)?;
        self.logger_initializer.init(
            self.config.data_directory.clone(),
            &self.config.real_user,
            self.config.log_level,
            None,
        );
        self.listener_handlers =
            FuturesUnordered::<Box<dyn ListenerHandler<Item = (), Error = ()>>>::new();
        let port_configurations = self.config.port_configurations.clone();
        port_configurations
            .iter()
            .for_each(|(port, port_configuration)| {
                let mut listener_handler = self.listener_handler_factory.make();
                if let Err(e) =
                    listener_handler.bind_port_and_configuration(*port, port_configuration.clone())
                {
                    panic!("Could not listen on port {}: {}", port, e)
                }
                self.listener_handlers.push(listener_handler);
            });
        Ok(())
    }

    fn initialize_as_unprivileged(
        &mut self,
        multi_config: &MultiConfig,
        _: &mut StdStreams,
    ) -> Result<(), ConfiguratorError> {
        // NOTE: The following line of code is not covered by unit tests
        fdlimit::raise_fd_limit();
        let unprivileged_config =
            NodeConfiguratorStandardUnprivileged::new(&self.config).configure(multi_config)?;
        self.config.merge_unprivileged(unprivileged_config);
        let _ = self.set_up_clandestine_port();
        let (alias_cryptde_null_opt, main_cryptde_null_opt) = self.null_cryptdes_as_trait_objects();
        let cryptdes = Bootstrapper::initialize_cryptdes(
            &main_cryptde_null_opt,
            &alias_cryptde_null_opt,
            self.config.blockchain_bridge_config.chain,
        );
        let node_descriptor = Bootstrapper::make_local_descriptor(
            cryptdes.main,
            self.config.neighborhood_config.mode.node_addr_opt(),
            self.config.blockchain_bridge_config.chain,
        );
        self.config.node_descriptor = node_descriptor;
        // Before you remove local-descriptor reporting for non-Standard neighborhood modes, make
        // sure you modify the multinode tests so that they can tell A) when a Node has started up,
        // and B) what its public key is.
        match &self.config.neighborhood_config.mode {
            NeighborhoodMode::Standard(node_addr, _, _)
                if node_addr.ip_addr() == Ipv4Addr::new(0, 0, 0, 0) => {} // node_addr still coming
            _ => Bootstrapper::report_local_descriptor(cryptdes.main, &self.config.node_descriptor), // here or not coming
        }
        let stream_handler_pool_subs = self.start_actors_and_return_shp_subs();
        self.listener_handlers
            .iter_mut()
            .for_each(|f| f.bind_subs(stream_handler_pool_subs.add_sub.clone()));
        Ok(())
    }
}

impl Bootstrapper {
    pub fn new(logger_initializer: Box<dyn LoggerInitializerWrapper>) -> Bootstrapper {
        Bootstrapper {
            listener_handler_factory: Box::new(ListenerHandlerFactoryReal::new()),
            listener_handlers:
                FuturesUnordered::<Box<dyn ListenerHandler<Item = (), Error = ()>>>::new(),
            actor_system_factory: Box::new(ActorSystemFactoryReal::new(Box::new(
                ActorSystemFactoryToolsReal::new(),
            ))),
            logger_initializer,
            config: BootstrapperConfig::new(),
        }
    }

    #[cfg(test)] // The real ones are private, but ActorSystemFactory needs to use them for testing
    pub fn pub_initialize_cryptdes_for_testing(
        main_cryptde_null_opt: &Option<&dyn CryptDE>,
        alias_cryptde_null_opt: &Option<&dyn CryptDE>,
    ) -> CryptDEPair {
        Self::initialize_cryptdes(
            main_cryptde_null_opt,
            alias_cryptde_null_opt,
            masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN,
        )
    }

    fn initialize_cryptdes(
        main_cryptde_null_opt: &Option<&dyn CryptDE>,
        alias_cryptde_null_opt: &Option<&dyn CryptDE>,
        chain: Chain,
    ) -> CryptDEPair {
        unsafe {
            Self::initialize_single_cryptde(main_cryptde_null_opt, &mut MAIN_CRYPTDE_BOX_OPT, chain)
        };
        unsafe {
            Self::initialize_single_cryptde(
                alias_cryptde_null_opt,
                &mut ALIAS_CRYPTDE_BOX_OPT,
                chain,
            )
        }
        CryptDEPair::default()
    }

    fn initialize_single_cryptde(
        cryptde_null_opt: &Option<&dyn CryptDE>,
        boxed_cryptde: &mut Option<Box<dyn CryptDE>>,
        chain: Chain,
    ) {
        match cryptde_null_opt {
            Some(cryptde) => {
                let _ = boxed_cryptde.replace(Box::new(<&CryptDENull>::from(*cryptde).clone()));
            }
            None => {
                let _ = boxed_cryptde.replace(Box::new(CryptDEReal::new(chain)));
            }
        }
    }

    fn make_local_descriptor(
        cryptde: &dyn CryptDE,
        node_addr_opt: Option<NodeAddr>,
        chain: Chain,
    ) -> NodeDescriptor {
        match node_addr_opt {
            Some(node_addr) => {
                NodeDescriptor::from((cryptde.public_key(), &node_addr, chain, cryptde))
            }
            None => {
                let mut result = NodeDescriptor::from((
                    cryptde.public_key(),
                    &NodeAddr::default(),
                    chain,
                    cryptde,
                ));
                result.node_addr_opt = None;
                result
            }
        }
    }

    fn start_actors_and_return_shp_subs(&self) -> StreamHandlerPoolSubs {
        self.actor_system_factory.make_and_start_actors(
            self.config.clone(),
            Box::new(ActorFactoryReal::new()),
            initialize_database(
                &self.config.data_directory,
                DbInitializationConfig::panic_on_migration(),
            ),
        )
    }

    pub fn report_local_descriptor(cryptde: &dyn CryptDE, descriptor: &NodeDescriptor) {
        let descriptor_msg = format!(
            "MASQ Node local descriptor: {}",
            descriptor.to_string(cryptde)
        );
        info!(Logger::new("Bootstrapper"), "{}", descriptor_msg);
    }

    fn set_up_clandestine_port(&mut self) -> Option<u16> {
        let clandestine_port_opt =
            if let NeighborhoodMode::Standard(node_addr, neighbor_configs, rate_pack) =
                &self.config.neighborhood_config.mode
            {
                let conn = DbInitializerReal::default()
                    .initialize(
                        &self.config.data_directory,
                        DbInitializationConfig::panic_on_migration(),
                    )
                    .unwrap_or_else(|err| {
                        db_connection_launch_panic(err, &self.config.data_directory)
                    });
                let config_dao = ConfigDaoReal::new(conn);
                let mut persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
                let clandestine_port = self.establish_clandestine_port(&mut persistent_config);
                let mut listener_handler = self.listener_handler_factory.make();
                listener_handler
                    .bind_port_and_configuration(
                        clandestine_port,
                        PortConfiguration {
                            discriminator_factories: vec![
                                Box::new(JsonDiscriminatorFactory::new()),
                            ],
                            is_clandestine: true,
                        },
                    )
                    .expect("Failed to bind ListenerHandler to clandestine port");
                self.listener_handlers.push(listener_handler);
                self.config.neighborhood_config.mode = NeighborhoodMode::Standard(
                    NodeAddr::new(&node_addr.ip_addr(), &[clandestine_port]),
                    neighbor_configs.clone(),
                    *rate_pack,
                );
                Some(clandestine_port)
            } else {
                None
            };
        self.config
            .clandestine_discriminator_factories
            .push(Box::new(JsonDiscriminatorFactory::new()));
        clandestine_port_opt
    }

    fn establish_clandestine_port(
        &self,
        persistent_config: &mut dyn PersistentConfiguration,
    ) -> u16 {
        if let Some(clandestine_port) = self.config.clandestine_port_opt {
            match persistent_config.set_clandestine_port(clandestine_port) {
                Ok(_) => (),
                Err(pce) => panic!(
                    "Database is corrupt: error setting clandestine port: {:?}",
                    pce
                ),
            }
        }
        match persistent_config.clandestine_port() {
            Ok(clandestine_port) => clandestine_port,
            Err(pce) => panic!(
                "Database is corrupt: error reading clandestine port: {:?}",
                pce
            ),
        }
    }

    fn null_cryptdes_as_trait_objects(&self) -> (Option<&dyn CryptDE>, Option<&dyn CryptDE>) {
        (
            self.config
                .alias_cryptde_null_opt
                .as_ref()
                .map(|cryptde_null| cryptde_null as &dyn CryptDE),
            self.config
                .main_cryptde_null_opt
                .as_ref()
                .map(|cryptde_null| cryptde_null as &dyn CryptDE),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::DEFAULT_PENDING_TOO_LONG_SEC;
    use crate::actor_system_factory::{ActorFactory, ActorSystemFactory};
    use crate::bootstrapper::{
        main_cryptde_ref, Bootstrapper, BootstrapperConfig, EnvironmentWrapper, PortConfiguration,
        RealUser,
    };
    use crate::database::db_initializer::DbInitializationConfig;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::db_config::config_dao::ConfigDaoReal;
    use crate::db_config::persistent_configuration::{
        PersistentConfigError, PersistentConfiguration, PersistentConfigurationReal,
    };
    use crate::discriminator::Discriminator;
    use crate::discriminator::UnmaskedChunk;
    use crate::listener_handler::{ListenerHandler, ListenerHandlerFactory};
    use crate::node_test_utils::{extract_log, DirsWrapperMock, IdWrapperMock};
    use crate::node_test_utils::{make_stream_handler_pool_subs_from_recorder, TestLogOwner};
    use crate::server_initializer::test_utils::LoggerInitializerWrapperMock;
    use crate::server_initializer::LoggerInitializerWrapper;
    use crate::stream_handler_pool::StreamHandlerPoolSubs;
    use crate::stream_messages::AddStreamMsg;
    use crate::sub_lib::accountant::ScanIntervals;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::cryptde::{CryptDE, PlainData};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::neighborhood::{
        NeighborhoodConfig, NeighborhoodMode, NodeDescriptor, DEFAULT_RATE_PACK,
    };
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::socket_server::ConfiguredByPrivilege;
    use crate::sub_lib::stream_connector::ConnectionInfo;
    use crate::test_utils::neighborhood_test_utils::MIN_HOPS_FOR_TEST;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::RecordAwaiter;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use crate::test_utils::unshared_test_utils::{
        assert_on_initialization_with_panic_on_migration, make_simplified_multi_config,
    };
    use crate::test_utils::{assert_contains, rate_pack};
    use crate::test_utils::{main_cryptde, make_wallet};
    use actix::System;
    use actix::{Actor, Recipient};
    use crossbeam_channel::unbounded;
    use futures::Future;
    use lazy_static::lazy_static;
    use log::LevelFilter;
    use log::LevelFilter::Off;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::logger::Logger;
    use masq_lib::logger::TEST_LOG_RECIPIENT_GUARD;
    use masq_lib::test_utils::environment_guard::ClapGuard;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::test_utils::logging::{init_test_logging, TestLog, TestLogHandler};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::{find_free_port, to_string};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io;
    use std::io::ErrorKind;
    use std::marker::Sync;
    use std::net::{IpAddr, SocketAddr};
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tokio;
    use tokio::executor::current_thread::CurrentThread;
    use tokio::prelude::stream::FuturesUnordered;
    use tokio::prelude::Async;

    lazy_static! {
        pub static ref INITIALIZATION: Mutex<bool> = Mutex::new(false);
    }

    struct ListenerHandlerFactoryMock {
        log: TestLog,
        mocks: RefCell<Vec<Box<dyn ListenerHandler<Item = (), Error = ()>>>>,
    }

    unsafe impl Sync for ListenerHandlerFactoryMock {}

    impl ListenerHandlerFactory for ListenerHandlerFactoryMock {
        fn make(&self) -> Box<dyn ListenerHandler<Item = (), Error = ()>> {
            self.log.log(String::from("make ()"));
            self.mocks.borrow_mut().remove(0)
        }
    }

    impl ListenerHandlerFactoryMock {
        fn new() -> ListenerHandlerFactoryMock {
            ListenerHandlerFactoryMock {
                log: TestLog::new(),
                mocks: RefCell::new(vec![]),
            }
        }

        fn add(&mut self, mock: Box<dyn ListenerHandler<Item = (), Error = ()>>) {
            self.mocks.borrow_mut().push(mock)
        }
    }

    #[derive(Default)]
    struct PollingSetting {
        counter: usize,
        how_many_attempts_wanted_opt: Option<usize>, //None for infinite
    }

    struct ListenerHandlerNull {
        log: Arc<Mutex<TestLog>>,
        bind_port_and_discriminator_factories_result: Option<io::Result<()>>,
        port_configuration_parameter: Option<PortConfiguration>,
        add_stream_sub: Option<Recipient<AddStreamMsg>>,
        add_stream_msgs: Arc<Mutex<Vec<AddStreamMsg>>>,
        _listen_results: Vec<Box<dyn ListenerHandler<Item = (), Error = ()>>>,
        //to be able to eliminate hanging and the need of a background thread in the test
        polling_setting: PollingSetting,
    }

    impl ListenerHandler for ListenerHandlerNull {
        fn bind_port_and_configuration(
            &mut self,
            port: u16,
            discriminator_factories: PortConfiguration,
        ) -> io::Result<()> {
            self.log.lock().unwrap().log(format!(
                "bind_port_and_configuration ({}, PortConfiguration {{is_clandestine: {}, ...}})",
                port, discriminator_factories.is_clandestine
            ));
            self.port_configuration_parameter = Some(discriminator_factories);
            self.bind_port_and_discriminator_factories_result
                .take()
                .unwrap()
        }

        fn bind_subs(&mut self, add_stream_sub: Recipient<AddStreamMsg>) {
            let logger = Logger::new("ListenerHandler");
            error!(logger, "bind_subscribers (add_stream_sub)");

            self.add_stream_sub = Some(add_stream_sub);
        }
    }

    impl Future for ListenerHandlerNull {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
            self.log.lock().unwrap().log(String::from("poll (...)"));
            let mut add_stream_msgs = self.add_stream_msgs.lock().unwrap();
            let add_stream_sub = self.add_stream_sub.as_ref().unwrap();
            while add_stream_msgs.len() > 0 {
                let add_stream_msg = add_stream_msgs.remove(0);
                add_stream_sub
                    .try_send(add_stream_msg)
                    .expect("StreamHandlerPool is dead");
            }
            if let Some(desired_number) = self.polling_setting.how_many_attempts_wanted_opt {
                self.polling_setting.counter += 1;
                if self.polling_setting.counter == desired_number {
                    return Ok(Async::Ready(())); //breaking the infinite looping
                }
            }
            Ok(Async::NotReady)
        }
    }

    impl TestLogOwner for ListenerHandlerNull {
        fn get_test_log(&self) -> Arc<Mutex<TestLog>> {
            self.log.clone()
        }
    }

    impl ListenerHandlerNull {
        fn new(add_stream_msgs: Vec<AddStreamMsg>) -> ListenerHandlerNull {
            ListenerHandlerNull {
                log: Arc::new(Mutex::new(TestLog::new())),
                bind_port_and_discriminator_factories_result: None,
                port_configuration_parameter: None,
                add_stream_sub: None,
                add_stream_msgs: Arc::new(Mutex::new(add_stream_msgs)),
                _listen_results: vec![],
                polling_setting: PollingSetting::default(),
            }
        }

        fn bind_port_result(mut self, result: io::Result<()>) -> ListenerHandlerNull {
            self.bind_port_and_discriminator_factories_result = Some(result);
            self
        }

        fn stop_polling_after_prepared_messages_exhausted(mut self) -> ListenerHandlerNull {
            self.polling_setting.how_many_attempts_wanted_opt =
                Some(self.add_stream_msgs.lock().unwrap().len());
            self
        }
    }

    struct EnvironmentWrapperMock {
        sudo_uid: Option<String>,
        sudo_gid: Option<String>,
        sudo_user: Option<String>,
    }

    impl EnvironmentWrapper for EnvironmentWrapperMock {
        fn var(&self, key: &str) -> Option<String> {
            match key {
                "SUDO_UID" => self.sudo_uid.clone(),
                "SUDO_GID" => self.sudo_gid.clone(),
                "SUDO_USER" => self.sudo_user.clone(),
                _ => None,
            }
        }
    }

    impl EnvironmentWrapperMock {
        fn new(
            sudo_uid: Option<&str>,
            sudo_gid: Option<&str>,
            sudo_user: Option<&str>,
        ) -> EnvironmentWrapperMock {
            EnvironmentWrapperMock {
                sudo_uid: sudo_uid.map(to_string),
                sudo_gid: sudo_gid.map(to_string),
                sudo_user: sudo_user.map(to_string),
            }
        }
    }

    #[test]
    fn real_user_from_blank() {
        let result = RealUser::from_str("").err().unwrap();

        assert_eq!(result, ());
    }

    #[test]
    fn real_user_from_one_colon() {
        let result = RealUser::from_str(":").err().unwrap();

        assert_eq!(result, ());
    }

    #[test]
    fn real_user_from_nonnumeric_uid() {
        let result = RealUser::from_str("booga:1234:").err().unwrap();

        assert_eq!(result, ());
    }

    #[test]
    fn real_user_from_nonnumeric_gid() {
        let result = RealUser::from_str("1234:booga:").err().unwrap();

        assert_eq!(result, ());
    }

    #[test]
    fn real_user_from_two_colons() {
        let subject = RealUser::from_str("::").unwrap();

        assert_eq!(subject, RealUser::new(None, None, None))
    }

    #[test]
    fn real_user_from_many_colons() {
        let subject = RealUser::from_str("::::::").unwrap();

        assert_eq!(subject, RealUser::new(None, None, Some("::::".into())))
    }

    #[test]
    fn real_user_from_uid_only() {
        let subject = RealUser::from_str("123::").unwrap();

        assert_eq!(subject, RealUser::new(Some(123), None, None))
    }

    #[test]
    fn real_user_from_gid_only() {
        let subject = RealUser::from_str(":456:").unwrap();

        assert_eq!(subject, RealUser::new(None, Some(456), None))
    }

    #[test]
    fn real_user_from_home_dir_only() {
        let subject = RealUser::from_str("::booga").unwrap();

        assert_eq!(subject, RealUser::new(None, None, Some("booga".into())))
    }

    #[test]
    fn real_user_from_all_parts() {
        let subject = RealUser::from_str("123:456:booga").unwrap();

        assert_eq!(
            subject,
            RealUser::new(Some(123), Some(456), Some("booga".into()))
        )
    }

    #[test]
    fn full_real_user_to_string() {
        let subject = RealUser::from_str("123:456:booga").unwrap();

        let result = subject.to_string();

        assert_eq!(result, "123:456:booga".to_string());
    }

    #[test]
    fn empty_real_user_to_string() {
        let subject = RealUser::null();

        let result = subject.to_string();

        assert_eq!(result, "::".to_string());
    }

    #[test]
    fn initialize_ids_handles_full_parameters() {
        let id_wrapper = Box::new(IdWrapperMock::new());
        let environment_wrapper = EnvironmentWrapperMock::new(None, None, None);
        let mut subject = RealUser::null();
        subject.environment_wrapper = Box::new(environment_wrapper);

        subject.initialize_ids(id_wrapper, Some(1234), Some(4321));

        assert_eq!(subject.uid_opt, Some(1234));
        assert_eq!(subject.gid_opt, Some(4321));
    }

    #[test]
    fn initialize_ids_handles_empty_parameters() {
        let id_wrapper = Box::new(IdWrapperMock::new().getuid_result(1234).getgid_result(4321));
        let environment_wrapper = EnvironmentWrapperMock::new(None, None, None);
        let mut subject = RealUser::null();
        subject.environment_wrapper = Box::new(environment_wrapper);

        subject.initialize_ids(id_wrapper, None, None);

        assert_eq!(subject.uid_opt, Some(1234));
        assert_eq!(subject.gid_opt, Some(4321));
    }

    #[test]
    fn initialize_as_privileged_with_no_args_binds_http_and_tls_ports() {
        let _lock = INITIALIZATION.lock();
        let (first_handler, first_handler_log) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let (second_handler, second_handler_log) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let (third_handler, third_handler_log) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(first_handler))
            .add_listener_handler(Box::new(second_handler))
            .add_listener_handler(Box::new(third_handler))
            .build();

        subject
            .initialize_as_privileged(&make_simplified_multi_config([]))
            .unwrap();

        let mut all_calls = vec![];
        all_calls.extend(first_handler_log.lock().unwrap().dump());
        all_calls.extend(second_handler_log.lock().unwrap().dump());
        all_calls.extend(third_handler_log.lock().unwrap().dump());
        assert!(
            all_calls.contains(&String::from(
                "bind_port_and_configuration (80, PortConfiguration {is_clandestine: false, ...})"
            )),
            "{:?}",
            all_calls
        );
        assert!(
            all_calls.contains(&String::from(
                "bind_port_and_configuration (443, PortConfiguration {is_clandestine: false, ...})"
            )),
            "{:?}",
            all_calls
        );
        assert_eq!(all_calls.len(), 2, "{:?}", all_calls);
    }

    #[test]
    fn initialize_as_privileged_in_zero_hop_mode_produces_empty_clandestine_discriminator_factories_vector(
    ) {
        let _lock = INITIALIZATION.lock();
        let first_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let second_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(first_handler)
            .add_listener_handler(second_handler)
            .build();

        subject
            .initialize_as_privileged(&make_simplified_multi_config([
                "--neighborhood-mode",
                "zero-hop",
            ]))
            .unwrap();

        let config = subject.config;
        assert_eq!(
            config.neighborhood_config.mode.node_addr_opt().is_none(),
            true
        );
        assert_eq!(config.clandestine_discriminator_factories.is_empty(), true);
    }

    #[test]
    fn initialize_as_privileged_points_logger_initializer_at_data_directory() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_privileged_points_logger_initializer_at_data_directory",
        );
        let init_params_arc = Arc::new(Mutex::new(vec![]));
        let logger_initializer =
            LoggerInitializerWrapperMock::new().init_parameters(&init_params_arc);
        let mut listener_handler_factory = ListenerHandlerFactoryMock::new();
        listener_handler_factory.add(Box::new(
            ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
        ));
        listener_handler_factory.add(Box::new(
            ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
        ));
        let mut subject = Bootstrapper::new(Box::new(logger_initializer));
        subject.listener_handler_factory = Box::new(listener_handler_factory);

        subject
            .initialize_as_privileged(&make_simplified_multi_config([
                "--data-directory",
                data_dir.to_str().unwrap(),
                "--ip",
                "2.2.2.2",
                "--real-user",
                "123:456:/home/booga",
                "--chain",
                "polygon-amoy",
            ]))
            .unwrap();

        let init_params = init_params_arc.lock().unwrap();
        assert_eq!(
            *init_params,
            vec![(
                data_dir,
                RealUser::new(Some(123), Some(456), Some("/home/booga".into())),
                LevelFilter::Warn,
                None,
            )]
        )
    }

    #[test]
    fn initialize_as_unprivileged_with_ip_passes_node_descriptor_to_ui_config_and_reports_it() {
        let _lock = INITIALIZATION.lock();
        init_test_logging();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_with_ip_passes_node_descriptor_to_ui_config_and_reports_it",
        );
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        config.data_directory = data_dir.clone();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .config(config)
            .build();

        subject
            .initialize_as_unprivileged(
                &make_simplified_multi_config([
                    "--ip",
                    "1.2.3.4",
                    "--clandestine-port",
                    "5123",
                    "--data-directory",
                    data_dir.to_str().unwrap(),
                ]),
                &mut FakeStreamHolder::new().streams(),
            )
            .unwrap();

        let config = subject.config;
        assert_eq!(
            config.node_descriptor,
            NodeDescriptor::from((
                main_cryptde_ref().public_key(),
                &NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[5123]),
                Chain::EthRopsten,
                main_cryptde_ref()
            ))
        );
        TestLogHandler::new().exists_log_matching("INFO: Bootstrapper: MASQ Node local descriptor: masq://eth-ropsten:.+@1\\.2\\.3\\.4:5123");
    }

    #[test]
    fn merging_unprivileged_config_picks_correct_items() {
        let mut privileged_config = BootstrapperConfig::new();
        let mut port_configuration = HashMap::new();
        port_configuration.insert(
            555,
            PortConfiguration {
                discriminator_factories: vec![],
                is_clandestine: true,
            },
        );
        privileged_config.port_configurations = port_configuration;
        privileged_config.log_level = Off;
        privileged_config.dns_servers =
            vec![SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), 1111)];
        let mut unprivileged_config = BootstrapperConfig::new();
        //values from unprivileged config
        let gas_price = 123;
        let blockchain_url_opt = Some("some.service@earth.abc".to_string());
        let clandestine_port_opt = Some(44444);
        let neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::OriginateOnly(vec![], rate_pack(9)),
            min_hops: MIN_HOPS_FOR_TEST,
        };
        let earning_wallet = make_wallet("earning wallet");
        let consuming_wallet_opt = Some(make_wallet("consuming wallet"));
        let db_password_opt = Some("password".to_string());
        unprivileged_config.blockchain_bridge_config.gas_price = gas_price;
        unprivileged_config
            .blockchain_bridge_config
            .blockchain_service_url_opt = blockchain_url_opt.clone();
        unprivileged_config.clandestine_port_opt = clandestine_port_opt;
        unprivileged_config.neighborhood_config = neighborhood_config.clone();
        unprivileged_config.earning_wallet = earning_wallet.clone();
        unprivileged_config.consuming_wallet_opt = consuming_wallet_opt.clone();
        unprivileged_config.db_password_opt = db_password_opt.clone();
        unprivileged_config.scan_intervals_opt = Some(ScanIntervals::default());
        unprivileged_config.suppress_initial_scans = false;
        unprivileged_config.when_pending_too_long_sec = DEFAULT_PENDING_TOO_LONG_SEC;

        privileged_config.merge_unprivileged(unprivileged_config);

        //merged arguments
        assert_eq!(
            privileged_config.blockchain_bridge_config.gas_price,
            gas_price
        );
        assert_eq!(
            privileged_config
                .blockchain_bridge_config
                .blockchain_service_url_opt,
            blockchain_url_opt
        );
        assert_eq!(privileged_config.clandestine_port_opt, clandestine_port_opt);
        assert_eq!(privileged_config.neighborhood_config, neighborhood_config);
        assert_eq!(privileged_config.earning_wallet, earning_wallet);
        assert_eq!(privileged_config.consuming_wallet_opt, consuming_wallet_opt);
        assert_eq!(privileged_config.db_password_opt, db_password_opt);
        assert_eq!(
            privileged_config.scan_intervals_opt,
            Some(ScanIntervals::default())
        );
        assert_eq!(privileged_config.suppress_initial_scans, false);
        assert_eq!(
            privileged_config.when_pending_too_long_sec,
            DEFAULT_PENDING_TOO_LONG_SEC
        );
        //some values from the privileged config
        assert_eq!(privileged_config.log_level, Off);
        assert_eq!(
            privileged_config.dns_servers,
            vec![SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), 1111)]
        );
        let port_config = privileged_config.port_configurations.get(&555).unwrap();
        assert!(port_config.discriminator_factories.is_empty());
        assert_eq!(port_config.is_clandestine, true)
    }

    #[test]
    fn initialize_as_unprivileged_passes_node_descriptor_to_ui_config() {
        init_test_logging();
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_passes_node_descriptor_to_ui_config",
        );
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        config.data_directory = data_dir.clone();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .config(config)
            .build();

        subject
            .initialize_as_unprivileged(
                &make_simplified_multi_config(["--ip", "1.2.3.4", "--clandestine-port", "5123"]),
                &mut FakeStreamHolder::new().streams(),
            )
            .unwrap();

        let config = subject.config;
        assert_eq!(
            config.node_descriptor,
            NodeDescriptor::from((
                main_cryptde_ref().public_key(),
                &NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[5123]),
                Chain::EthRopsten,
                main_cryptde_ref()
            ))
        );
        TestLogHandler::new().exists_log_matching("INFO: Bootstrapper: MASQ Node local descriptor: masq://eth-ropsten:.+@1\\.2\\.3\\.4:5123");
    }

    #[test]
    fn initialize_as_unprivileged_does_not_report_descriptor_when_ip_is_not_supplied_in_standard_mode(
    ) {
        init_test_logging();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_does_not_report_descriptor_when_ip_is_not_supplied_in_standard_mode",
        );
        let mut holder = FakeStreamHolder::new();
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        config.data_directory = data_dir.clone();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .config(config)
            .build();

        subject
            .initialize_as_unprivileged(
                &make_simplified_multi_config([
                    "--data-directory",
                    data_dir.to_str().unwrap(),
                    "--clandestine-port",
                    "5124",
                ]),
                &mut holder.streams(),
            )
            .unwrap();

        let config = subject.config;
        assert_eq!(
            config.node_descriptor.node_addr_opt,
            Some(NodeAddr::new(
                &IpAddr::from_str("0.0.0.0").unwrap(),
                &vec![5124]
            ))
        );
        TestLogHandler::new().exists_no_log_containing("@0.0.0.0:5124");
    }

    #[test]
    fn initialize_as_unprivileged_sets_gas_price_on_blockchain_config() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_sets_gas_price_on_blockchain_config",
        );
        let mut config = BootstrapperConfig::new();
        config.data_directory = data_dir.clone();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .config(config)
            .build();

        subject
            .initialize_as_unprivileged(
                &make_simplified_multi_config(["--ip", "1.2.3.4", "--gas-price", "11"]),
                &mut FakeStreamHolder::new().streams(),
            )
            .unwrap();

        let config = subject.config;
        assert_eq!(config.blockchain_bridge_config.gas_price, 11);
    }

    #[test]
    fn initialize_as_unprivileged_implements_panic_on_migration_for_make_and_start_actors() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_implements_panic_on_migration_for_make_and_start_actors",
        );

        let act = |data_dir: &Path| {
            let mut config = BootstrapperConfig::new();
            config.data_directory = data_dir.to_path_buf();
            let subject = BootstrapperBuilder::new().config(config).build();
            subject.start_actors_and_return_shp_subs();
        };

        assert_on_initialization_with_panic_on_migration(&data_dir, &act);
    }

    #[test]
    fn initialize_with_clandestine_port_produces_expected_clandestine_discriminator_factories_vector(
    ) {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_with_clandestine_port_produces_expected_clandestine_discriminator_factories_vector",
        );
        let first_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let second_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let third_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(first_handler)
            .add_listener_handler(second_handler)
            .add_listener_handler(third_handler)
            .build();
        let args = [
            "--neighborhood-mode",
            "zero-hop",
            "--clandestine-port",
            "1234",
            "--data-directory",
            data_dir.to_str().unwrap(),
        ];
        let mut holder = FakeStreamHolder::new();
        let multi_config = make_simplified_multi_config(args);

        subject.initialize_as_privileged(&multi_config).unwrap();
        subject
            .initialize_as_unprivileged(&multi_config, &mut holder.streams())
            .unwrap();

        let config = subject.config;
        assert!(config.neighborhood_config.mode.node_addr_opt().is_none());
        assert_eq!(config.clandestine_port_opt, Some(1234u16));
    }

    #[test]
    fn init_as_privileged_stores_dns_servers_and_passes_them_to_actor_system_factory_for_proxy_client_in_init_as_unprivileged(
    ) {
        let _guard = TEST_LOG_RECIPIENT_GUARD.lock().unwrap(); // protection to interfering with 'prepare_initial_messages_initiates_global_log_recipient'
        let _lock = INITIALIZATION.lock();
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "init_as_privileged_stores_dns_servers_and_passes_them_to_actor_system_factory_for_proxy_client_in_init_as_unprivileged",
        );
        let args = [
            "--dns-servers",
            "1.2.3.4,2.3.4.5",
            "--ip",
            "111.111.111.111",
            "--clandestine-port",
            "1234",
            "--data-directory",
            data_dir.to_str().unwrap(),
        ];
        let mut holder = FakeStreamHolder::new();
        let actor_system_factory = ActorSystemFactoryActiveMock::new();
        let make_and_start_actor_params_arc =
            actor_system_factory.make_and_start_actors_params.clone();
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();
        let multi_config = make_simplified_multi_config(args);

        subject.initialize_as_privileged(&multi_config).unwrap();
        subject
            .initialize_as_unprivileged(&multi_config, &mut holder.streams())
            .unwrap();

        let mut make_and_start_actor_params = make_and_start_actor_params_arc.lock().unwrap();
        let (bootstrapper_config, _, _) = make_and_start_actor_params.remove(0);
        assert!(make_and_start_actor_params.is_empty());
        assert_eq!(
            bootstrapper_config.dns_servers,
            vec![
                SocketAddr::from_str("1.2.3.4:53").unwrap(),
                SocketAddr::from_str("2.3.4.5:53").unwrap()
            ]
        )
    }

    #[test]
    #[should_panic(expected = "Could not listen on port")]
    fn initialize_as_privileged_panics_if_tcp_listener_doesnt_bind() {
        let _lock = INITIALIZATION.lock();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![])
                    .bind_port_result(Err(io::Error::from(ErrorKind::AddrInUse))),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();

        subject
            .initialize_as_privileged(&make_simplified_multi_config(["--ip", "111.111.111.111"]))
            .unwrap();
    }

    #[test]
    fn initialize_cryptde_without_cryptde_null_uses_cryptde_real() {
        let _lock = INITIALIZATION.lock();
        let cryptdes = Bootstrapper::initialize_cryptdes(&None, &None, TEST_DEFAULT_CHAIN);

        assert_eq!(main_cryptde_ref().public_key(), cryptdes.main.public_key());
        // Brittle assertion: this may not be true forever
        let cryptde_null = main_cryptde();
        assert!(cryptdes.main.public_key().len() > cryptde_null.public_key().len());
    }

    #[test]
    fn initialize_cryptde_with_cryptde_null_uses_cryptde_null() {
        let _lock = INITIALIZATION.lock();
        let cryptde_null = main_cryptde().clone();
        let cryptde_null_public_key = cryptde_null.public_key().clone();

        let cryptdes =
            Bootstrapper::initialize_cryptdes(&Some(cryptde_null), &None, TEST_DEFAULT_CHAIN);

        assert_eq!(cryptdes.main.public_key(), &cryptde_null_public_key);
        assert_eq!(main_cryptde_ref().public_key(), cryptdes.main.public_key());
    }

    #[test]
    fn initialize_cryptde_and_report_local_descriptor_with_ip_address() {
        let _lock = INITIALIZATION.lock();
        init_test_logging();
        let node_addr = NodeAddr::new(
            &IpAddr::from_str("2.3.4.5").expect("Couldn't create IP address"),
            &[3456u16, 4567u16],
        );
        let cryptde_ref = {
            let cryptdes = Bootstrapper::initialize_cryptdes(&None, &None, TEST_DEFAULT_CHAIN);
            let descriptor = Bootstrapper::make_local_descriptor(
                cryptdes.main,
                Some(node_addr),
                TEST_DEFAULT_CHAIN,
            );
            Bootstrapper::report_local_descriptor(cryptdes.main, &descriptor);

            cryptdes.main
        };
        let expected_descriptor = format!(
            "masq://eth-ropsten:{}@2.3.4.5:3456/4567",
            cryptde_ref.public_key_to_descriptor_fragment(cryptde_ref.public_key())
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "INFO: Bootstrapper: MASQ Node local descriptor: {}",
                expected_descriptor
            )
            .as_str(),
        );

        let expected_data = PlainData::new(b"ho'q ;iaerh;frjhvs;lkjerre");
        let crypt_data = cryptde_ref
            .encode(&cryptde_ref.public_key(), &expected_data)
            .expect(&format!(
                "Couldn't encrypt data {:?} with key {:?}",
                expected_data,
                cryptde_ref.public_key()
            ));
        let decrypted_data = cryptde_ref.decode(&crypt_data).expect(&format!(
            "Couldn't decrypt data {:?} to key {:?}",
            crypt_data,
            cryptde_ref.public_key()
        ));
        assert_eq!(decrypted_data, expected_data)
    }

    #[test]
    fn initialize_cryptdes_and_report_local_descriptor_without_ip_address() {
        let _lock = INITIALIZATION.lock();
        init_test_logging();
        let cryptdes = {
            let cryptdes = Bootstrapper::initialize_cryptdes(&None, &None, TEST_DEFAULT_CHAIN);
            let descriptor =
                Bootstrapper::make_local_descriptor(cryptdes.main, None, TEST_DEFAULT_CHAIN);
            Bootstrapper::report_local_descriptor(cryptdes.main, &descriptor);

            cryptdes
        };
        let expected_descriptor = format!(
            "masq://eth-ropsten:{}@:",
            cryptdes
                .main
                .public_key_to_descriptor_fragment(cryptdes.main.public_key())
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "INFO: Bootstrapper: MASQ Node local descriptor: {}",
                expected_descriptor
            )
            .as_str(),
        );

        let assert_round_trip = |cryptde_ref: &dyn CryptDE| {
            let expected_data = PlainData::new(b"ho'q ;iaerh;frjhvs;lkjerre");
            let crypt_data = cryptde_ref
                .encode(&cryptde_ref.public_key(), &expected_data)
                .expect(&format!(
                    "Couldn't encrypt data {:?} with key {:?}",
                    expected_data,
                    cryptde_ref.public_key()
                ));
            let decrypted_data = cryptde_ref.decode(&crypt_data).expect(&format!(
                "Couldn't decrypt data {:?} to key {:?}",
                crypt_data,
                cryptde_ref.public_key()
            ));
            assert_eq!(decrypted_data, expected_data)
        };
        assert_round_trip(cryptdes.main);
        assert_round_trip(cryptdes.alias);
    }

    #[test]
    fn initialize_as_unprivileged_binds_clandestine_port() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_binds_clandestine_port",
        );
        let (one_listener_handler, _) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let (another_listener_handler, _) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let (clandestine_listener_handler, clandestine_listener_handler_log_arc) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .add_listener_handler(Box::new(clandestine_listener_handler))
            .build();
        let mut holder = FakeStreamHolder::new();
        subject
            .initialize_as_privileged(&make_simplified_multi_config([
                "--data-directory",
                data_dir.to_str().unwrap(),
            ]))
            .unwrap();

        subject
            .initialize_as_unprivileged(
                &make_simplified_multi_config([
                    "--clandestine-port",
                    "1234",
                    "--ip",
                    "1.2.3.4",
                    "--data-directory",
                    data_dir.to_str().unwrap(),
                ]),
                &mut holder.streams(),
            )
            .unwrap();

        let calls = clandestine_listener_handler_log_arc.lock().unwrap().dump();
        assert_eq!(
            calls,
            vec![
                "bind_port_and_configuration (1234, PortConfiguration {is_clandestine: true, ...})"
                    .to_string()
            ],
        );
    }

    #[test]
    fn initialize_as_unprivileged_moves_streams_from_listener_handlers_to_stream_handler_pool() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists("bootstrapper", "initialize_as_unprivileged_moves_streams_from_listener_handlers_to_stream_handler_pool");
        init_test_logging();
        let args = [
            "--ip",
            "111.111.111.111",
            "--data-directory",
            data_dir.to_str().unwrap(),
        ];
        let mut holder = FakeStreamHolder::new();
        let one_listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let another_listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let yet_another_listener_handler =
            ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let actor_system_factory = ActorSystemFactoryActiveMock::new();
        let mut config = BootstrapperConfig::new();
        config.data_directory = data_dir.clone();
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .add_listener_handler(Box::new(yet_another_listener_handler))
            .config(config)
            .build();
        let multi_config = &make_simplified_multi_config(args);
        subject.initialize_as_privileged(&multi_config).unwrap();

        subject
            .initialize_as_unprivileged(&multi_config, &mut holder.streams())
            .unwrap();

        // Checking log message cause I don't know how to get at add_stream_sub
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            "bind_subscribers (add_stream_sub)",
            "bind_subscribers (add_stream_sub)",
        ]);
    }

    #[test]
    fn bootstrapper_as_future_polls_listener_handler_futures() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "bootstrapper_as_future_polls_listener_handler_futures",
        );
        let mut holder = FakeStreamHolder::new();
        let connection_info1 = ConnectionInfo {
            reader: Box::new(ReadHalfWrapperMock::new()),
            writer: Box::new(WriteHalfWrapperMock::new()),
            local_addr: SocketAddr::from_str("1.1.1.1:80").unwrap(),
            peer_addr: SocketAddr::from_str("1.1.1.1:40").unwrap(),
        };
        let connection_info2 = ConnectionInfo {
            reader: Box::new(ReadHalfWrapperMock::new()),
            writer: Box::new(WriteHalfWrapperMock::new()),
            local_addr: SocketAddr::from_str("2.2.2.2:80").unwrap(),
            peer_addr: SocketAddr::from_str("2.2.2.2:40").unwrap(),
        };
        let connection_info3 = ConnectionInfo {
            reader: Box::new(ReadHalfWrapperMock::new()),
            writer: Box::new(WriteHalfWrapperMock::new()),
            local_addr: SocketAddr::from_str("3.3.3.3:80").unwrap(),
            peer_addr: SocketAddr::from_str("3.3.3.3:40").unwrap(),
        };
        let first_message = AddStreamMsg {
            connection_info: connection_info1,
            origin_port: Some(80),
            port_configuration: PortConfiguration::new(vec![], false),
        };
        let second_message = AddStreamMsg {
            connection_info: connection_info2,
            origin_port: None,
            port_configuration: PortConfiguration::new(vec![], false),
        };
        let third_message = AddStreamMsg {
            connection_info: connection_info3,
            origin_port: Some(443),
            port_configuration: PortConfiguration::new(vec![], false),
        };
        let one_listener_handler = ListenerHandlerNull::new(vec![first_message, second_message])
            .bind_port_result(Ok(()))
            .stop_polling_after_prepared_messages_exhausted();
        let another_listener_handler = ListenerHandlerNull::new(vec![third_message])
            .bind_port_result(Ok(()))
            .stop_polling_after_prepared_messages_exhausted();
        let mut actor_system_factory = ActorSystemFactoryActiveMock::new();
        let awaiter = actor_system_factory
            .stream_handler_pool_cluster
            .awaiter
            .take()
            .unwrap();
        let recording_arc = actor_system_factory
            .stream_handler_pool_cluster
            .recording
            .take()
            .unwrap();
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .build();
        let args = [
            "--neighborhood-mode",
            "zero-hop",
            "--data-directory",
            data_dir.to_str().unwrap(),
        ];
        let multi_config = make_simplified_multi_config(args);

        subject.initialize_as_privileged(&multi_config).unwrap();
        subject
            .initialize_as_unprivileged(&multi_config, &mut holder.streams())
            .unwrap();

        CurrentThread::new().block_on(subject).unwrap();

        let number_of_expected_messages = 3;
        awaiter.await_message_count(number_of_expected_messages);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), number_of_expected_messages);
        let actual_ports: Vec<String> = (0..number_of_expected_messages)
            .map(|i| {
                let record = recording.get_record::<AddStreamMsg>(i);
                format!("{:?}", record.origin_port)
            })
            .collect();
        assert_contains(&actual_ports, &String::from("Some(80)"));
        assert_contains(&actual_ports, &String::from("None"));
        assert_contains(&actual_ports, &String::from("Some(443)"));
    }

    #[test]
    fn set_up_clandestine_port_handles_specified_port_in_standard_mode() {
        let port = find_free_port();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "set_up_clandestine_port_handles_specified_port_in_standard_mode",
        );
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, DbInitializationConfig::test_default())
            .unwrap();
        let cryptde_actual = CryptDENull::from(&PublicKey::new(&[1, 2, 3, 4]), TEST_DEFAULT_CHAIN);
        let cryptde: &dyn CryptDE = &cryptde_actual;
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[4321]),
                vec![NodeDescriptor::from((
                    cryptde.public_key(),
                    &NodeAddr::new(
                        &IpAddr::from_str("1.2.3.4").unwrap(),
                        &[1234], //this port number comes from the neighbor
                    ),
                    Chain::EthMainnet,
                    cryptde,
                ))],
                rate_pack(100),
            ),
            min_hops: MIN_HOPS_FOR_TEST,
        };
        config.data_directory = data_dir.clone();
        config.clandestine_port_opt = Some(port);
        let listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .config(config)
            .build();

        let result = subject.set_up_clandestine_port();

        assert_eq!(result, Some(port));
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        assert_eq!(persistent_config.clandestine_port().unwrap(), port);
        assert_eq!(
            subject
                .config
                .neighborhood_config
                .mode
                .node_addr_opt()
                .unwrap()
                .ports(),
            vec![port],
        );
        assert_eq!(1, subject.listener_handlers.len());

        let config = subject.config;
        let mut clandestine_discriminators = config
            .clandestine_discriminator_factories
            .into_iter()
            .map(|factory| factory.make())
            .collect::<Vec<Discriminator>>();
        let mut discriminator = clandestine_discriminators.remove(0);
        discriminator.add_data(&b"{\"component\": \"NBHD\", \"bodyText\": \"Booga\"}"[..]);
        assert_eq!(
            Some(UnmaskedChunk {
                chunk: b"Booga".to_vec(),
                last_chunk: true,
                sequenced: false,
            }),
            discriminator.take_chunk(),
        );
        assert_eq!(0, clandestine_discriminators.len()); // Used to be 1, now 0 after removal
    }

    #[test]
    fn set_up_clandestine_port_handles_unspecified_port_in_standard_mode() {
        let cryptde_actual = CryptDENull::from(&PublicKey::new(&[1, 2, 3, 4]), TEST_DEFAULT_CHAIN);
        let cryptde: &dyn CryptDE = &cryptde_actual;
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "set_up_clandestine_port_handles_unspecified_port_in_standard_mode",
        );
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, DbInitializationConfig::test_default())
            .unwrap();
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[]),
                vec![NodeDescriptor::from((
                    cryptde.public_key(),
                    &NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[1234]),
                    Chain::EthRopsten,
                    cryptde,
                ))],
                rate_pack(100),
            ),
            min_hops: MIN_HOPS_FOR_TEST,
        };
        config.data_directory = data_dir.clone();
        config.clandestine_port_opt = None;
        let listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .config(config)
            .build();

        let result = subject.set_up_clandestine_port();

        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        let clandestine_port = persistent_config.clandestine_port().unwrap();
        assert_eq!(result, Some(clandestine_port));
        assert_eq!(
            subject
                .config
                .neighborhood_config
                .mode
                .node_addr_opt()
                .unwrap()
                .ports(),
            vec![clandestine_port],
        );
    }

    #[test]
    fn set_up_clandestine_port_handles_originate_only() {
        let cryptde_actual = CryptDENull::from(&PublicKey::new(&[1, 2, 3, 4]), TEST_DEFAULT_CHAIN);
        let cryptde: &dyn CryptDE = &cryptde_actual;
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "set_up_clandestine_port_handles_originate_only",
        );
        let mut config = BootstrapperConfig::new();
        config.data_directory = data_dir.clone();
        config.clandestine_port_opt = None;
        config.neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::OriginateOnly(
                vec![NodeDescriptor::from((
                    cryptde.public_key(),
                    &NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[1234]),
                    Chain::EthRopsten,
                    cryptde,
                ))],
                rate_pack(100),
            ),
            min_hops: MIN_HOPS_FOR_TEST,
        };
        let listener_handler = ListenerHandlerNull::new(vec![]);
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .config(config)
            .build();

        let result = subject.set_up_clandestine_port();

        assert_eq!(result, None);
        assert!(subject
            .config
            .neighborhood_config
            .mode
            .node_addr_opt()
            .is_none());
    }

    #[test]
    fn set_up_clandestine_port_handles_consume_only() {
        let cryptde_actual = CryptDENull::from(&PublicKey::new(&[1, 2, 3, 4]), TEST_DEFAULT_CHAIN);
        let cryptde: &dyn CryptDE = &cryptde_actual;
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "set_up_clandestine_port_handles_consume_only",
        );
        let mut config = BootstrapperConfig::new();
        config.data_directory = data_dir.clone();
        config.clandestine_port_opt = None;
        config.neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::ConsumeOnly(vec![NodeDescriptor::from((
                cryptde.public_key(),
                &NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[1234]),
                Chain::EthRopsten,
                cryptde,
            ))]),
            min_hops: MIN_HOPS_FOR_TEST,
        };
        let listener_handler = ListenerHandlerNull::new(vec![]);
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .config(config)
            .build();

        let result = subject.set_up_clandestine_port();

        assert_eq!(result, None);
        assert!(subject
            .config
            .neighborhood_config
            .mode
            .node_addr_opt()
            .is_none());
    }

    #[test]
    fn set_up_clandestine_port_handles_zero_hop() {
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "set_up_clandestine_port_handles_zero_hop",
        );
        let mut config = BootstrapperConfig::new();
        config.data_directory = data_dir.clone();
        config.clandestine_port_opt = None;
        config.neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::ZeroHop,
            min_hops: MIN_HOPS_FOR_TEST,
        };
        let listener_handler = ListenerHandlerNull::new(vec![]);
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .config(config)
            .build();

        let result = subject.set_up_clandestine_port();

        assert_eq!(result, None);
        assert!(subject
            .config
            .neighborhood_config
            .mode
            .node_addr_opt()
            .is_none());
    }

    #[test]
    fn set_up_clandestine_port_panics_on_migration() {
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "set_up_clandestine_port_panics_on_migration",
        );

        let act = |data_dir: &Path| {
            let mut config = BootstrapperConfig::new();
            config.data_directory = data_dir.to_path_buf();
            config.neighborhood_config = NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(NodeAddr::default(), vec![], DEFAULT_RATE_PACK),
                min_hops: MIN_HOPS_FOR_TEST,
            };
            let mut subject = BootstrapperBuilder::new().config(config).build();
            subject.set_up_clandestine_port();
        };

        assert_on_initialization_with_panic_on_migration(&data_dir, &act);
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: error setting clandestine port: TransactionError"
    )]
    fn establish_clandestine_port_handles_error_setting_port() {
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_clandestine_port_result(Err(PersistentConfigError::TransactionError));
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        let subject = BootstrapperBuilder::new().config(config).build();

        let _ = subject.establish_clandestine_port(&mut persistent_config);
    }

    #[test]
    #[should_panic(expected = "Database is corrupt: error reading clandestine port: NotPresent")]
    fn establish_clandestine_port_handles_error_reading_port() {
        let mut persistent_config = PersistentConfigurationMock::new()
            .clandestine_port_result(Err(PersistentConfigError::NotPresent));
        let subject = BootstrapperBuilder::new().build();

        let _ = subject.establish_clandestine_port(&mut persistent_config);
    }

    #[test]
    fn real_user_null() {
        let subject = RealUser::null();

        assert_eq!(subject.uid_opt, None);
        assert_eq!(subject.gid_opt, None);
        assert_eq!(subject.home_dir_opt, None);
    }

    #[test]
    fn configurator_beats_all() {
        let environment_wrapper =
            EnvironmentWrapperMock::new(Some("123"), Some("456"), Some("booga"));
        let mut from_configurator = RealUser::new(Some(1), Some(2), Some("three".into()));
        from_configurator.environment_wrapper = Box::new(environment_wrapper);

        let result = from_configurator.populate(&DirsWrapperMock::new());

        assert_eq!(result, from_configurator);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn environment_beats_id_wrapper() {
        let id_wrapper = IdWrapperMock::new().getuid_result(111).getgid_result(222);
        let environment_wrapper =
            EnvironmentWrapperMock::new(Some("123"), Some("456"), Some("username"));
        let mut from_configurator = RealUser::null();
        from_configurator.environment_wrapper = Box::new(environment_wrapper);
        from_configurator.initialize_ids(Box::new(id_wrapper), None, None);

        let result = from_configurator
            .populate(&DirsWrapperMock::new().home_dir_result(Some("/root".into())));

        assert_eq!(
            result,
            RealUser::new(Some(123), Some(456), Some(PathBuf::from("/home/username")))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn environment_beats_id_wrapper() {
        let id_wrapper = IdWrapperMock::new().getuid_result(111).getgid_result(222);
        let environment_wrapper =
            EnvironmentWrapperMock::new(Some("123"), Some("456"), Some("username"));
        let mut from_configurator = RealUser::null();
        from_configurator.environment_wrapper = Box::new(environment_wrapper);
        from_configurator.initialize_ids(Box::new(id_wrapper), None, None);

        let result = from_configurator
            .populate(&DirsWrapperMock::new().home_dir_result(Some("/var/root".into())));

        assert_eq!(
            result,
            RealUser::new(Some(123), Some(456), Some(PathBuf::from("/Users/username")))
        );
    }

    #[test]
    fn unmodified_is_last_ditch() {
        let environment_wrapper = EnvironmentWrapperMock::new(None, None, None);
        let id_wrapper = IdWrapperMock::new().getuid_result(123).getgid_result(456);
        let mut from_configurator = RealUser::null();
        from_configurator.initialize_ids(Box::new(id_wrapper), None, None);
        from_configurator.environment_wrapper = Box::new(environment_wrapper);

        let result = from_configurator
            .populate(&DirsWrapperMock::new().home_dir_result(Some("/wibble/whop/ooga".into())));

        assert_eq!(
            result,
            RealUser::new(
                Some(123),
                Some(456),
                Some(PathBuf::from("/wibble/whop/ooga"))
            )
        );
    }

    struct StreamHandlerPoolCluster {
        recording: Option<Arc<Mutex<Recording>>>,
        awaiter: Option<RecordAwaiter>,
        subs: StreamHandlerPoolSubs,
    }

    struct ActorSystemFactoryActiveMock {
        stream_handler_pool_cluster: StreamHandlerPoolCluster,
        make_and_start_actors_params: Arc<
            Mutex<
                Vec<(
                    BootstrapperConfig,
                    Box<dyn ActorFactory>,
                    Box<dyn PersistentConfiguration>,
                )>,
            >,
        >,
    }

    impl ActorSystemFactory for ActorSystemFactoryActiveMock {
        fn make_and_start_actors(
            &self,
            config: BootstrapperConfig,
            actor_factory: Box<dyn ActorFactory>,
            persist_config: Box<dyn PersistentConfiguration>,
        ) -> StreamHandlerPoolSubs {
            let mut parameter_guard = self.make_and_start_actors_params.lock().unwrap();
            parameter_guard.push((config.clone(), actor_factory, persist_config));

            self.stream_handler_pool_cluster.subs.clone()
        }
    }

    impl ActorSystemFactoryActiveMock {
        fn new() -> ActorSystemFactoryActiveMock {
            let (tx, rx) = unbounded();
            thread::spawn(move || {
                let system = System::new("test");

                let stream_handler_pool_cluster = {
                    let (stream_handler_pool, awaiter, recording) = make_recorder();
                    StreamHandlerPoolCluster {
                        recording: Some(recording),
                        awaiter: Some(awaiter),
                        subs: make_stream_handler_pool_subs_from_recorder(
                            &stream_handler_pool.start(),
                        ),
                    }
                };

                tx.send(stream_handler_pool_cluster).unwrap();
                system.run();
            });
            let stream_handler_pool_cluster = rx.recv().unwrap();
            ActorSystemFactoryActiveMock {
                stream_handler_pool_cluster,
                make_and_start_actors_params: Arc::new(Mutex::new(vec![])),
            }
        }
    }

    struct BootstrapperBuilder {
        actor_system_factory: Box<dyn ActorSystemFactory>,
        log_initializer_wrapper: Box<dyn LoggerInitializerWrapper>,
        listener_handler_factory: ListenerHandlerFactoryMock,
        config: BootstrapperConfig,
    }

    impl BootstrapperBuilder {
        fn new() -> BootstrapperBuilder {
            BootstrapperBuilder {
                actor_system_factory: Box::new(ActorSystemFactoryActiveMock::new()),
                log_initializer_wrapper: Box::new(LoggerInitializerWrapperMock::new()),
                // Don't modify this line unless you've already looked at DispatcherBuilder::add_listener_handler().
                listener_handler_factory: ListenerHandlerFactoryMock::new(),
                config: BootstrapperConfig::new(),
            }
        }

        fn actor_system_factory(
            mut self,
            actor_system_factory: Box<dyn ActorSystemFactory>,
        ) -> BootstrapperBuilder {
            self.actor_system_factory = actor_system_factory;
            self
        }

        fn add_listener_handler(
            mut self,
            listener_handler: Box<dyn ListenerHandler<Item = (), Error = ()>>,
        ) -> BootstrapperBuilder {
            self.listener_handler_factory.add(listener_handler);
            self
        }

        fn config(mut self, config: BootstrapperConfig) -> Self {
            self.config = config;
            self
        }

        fn build(self) -> Bootstrapper {
            Bootstrapper {
                actor_system_factory: self.actor_system_factory,
                listener_handler_factory: Box::new(self.listener_handler_factory),
                listener_handlers: FuturesUnordered::<
                    Box<dyn ListenerHandler<Item = (), Error = ()>>,
                >::new(),
                logger_initializer: self.log_initializer_wrapper,
                config: self.config,
            }
        }
    }
}
