// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use super::accountant::Accountant;
use super::bootstrapper::BootstrapperConfig;
use super::dispatcher::Dispatcher;
use super::hopper::Hopper;
use super::neighborhood::Neighborhood;
use super::proxy_client::ProxyClient;
use super::proxy_server::ProxyServer;
use super::stream_handler_pool::StreamHandlerPool;
use super::stream_handler_pool::StreamHandlerPoolSubs;
use super::stream_messages::PoolBindMessage;
use super::ui_gateway::UiGateway;
use crate::accountant::db_access_objects::banned_dao::{BannedCacheLoader, BannedCacheLoaderReal};
use crate::blockchain::blockchain_bridge::{BlockchainBridge, BlockchainBridgeSubsFactoryReal};
use crate::bootstrapper::CryptDEPair;
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{connection_or_panic, DbInitializer, DbInitializerReal};
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::node_configurator::configurator::Configurator;
use crate::sub_lib::accountant::{AccountantSubs, AccountantSubsFactoryReal, DaoFactories};
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::configurator::ConfiguratorSubs;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::dispatcher::DispatcherSubs;
use crate::sub_lib::hopper::HopperConfig;
use crate::sub_lib::hopper::HopperSubs;
use crate::sub_lib::neighborhood::{NeighborhoodMode, NeighborhoodSubs};
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::peer_actors::{NewPublicIp, PeerActors};
use crate::sub_lib::proxy_client::ProxyClientConfig;
use crate::sub_lib::proxy_client::ProxyClientSubs;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use actix::Recipient;
use actix::{Addr, Arbiter};
use automap_lib::comm_layer::AutomapError;
use automap_lib::control_layer::automap_control::{
    AutomapChange, AutomapControl, AutomapControlReal, ChangeHandler,
};
use masq_lib::blockchains::chains::Chain;
use masq_lib::crash_point::CrashPoint;
#[cfg(feature = "log_recipient_test")]
use masq_lib::logger::log_broadcast_substitution_in_tests::prepare_log_recipient;
#[cfg(not(feature = "log_recipient_test"))]
use masq_lib::logger::prepare_log_recipient;
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::{exit_process, AutomapProtocol};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

pub trait ActorSystemFactory {
    fn make_and_start_actors(
        &self,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
        persist_config: Box<dyn PersistentConfiguration>,
    ) -> StreamHandlerPoolSubs;
}

pub struct ActorSystemFactoryReal {
    tools: Box<dyn ActorSystemFactoryTools>,
}

impl ActorSystemFactory for ActorSystemFactoryReal {
    fn make_and_start_actors(
        &self,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
        persistent_config: Box<dyn PersistentConfiguration>,
    ) -> StreamHandlerPoolSubs {
        self.tools
            .validate_database_chain(&*persistent_config, config.blockchain_bridge_config.chain);
        let cryptdes = self.tools.cryptdes();
        self.tools
            .prepare_initial_messages(cryptdes, config, persistent_config, actor_factory)
    }
}

impl ActorSystemFactoryReal {
    pub fn new(tools: Box<dyn ActorSystemFactoryTools>) -> Self {
        Self { tools }
    }
}

pub trait ActorSystemFactoryTools {
    fn prepare_initial_messages(
        &self,
        cryptdes: CryptDEPair,
        config: BootstrapperConfig,
        persistent_config: Box<dyn PersistentConfiguration>,
        actor_factory: Box<dyn ActorFactory>,
    ) -> StreamHandlerPoolSubs;
    fn cryptdes(&self) -> CryptDEPair;
    fn validate_database_chain(
        &self,
        persistent_config: &dyn PersistentConfiguration,
        chain: Chain,
    );
}

pub struct ActorSystemFactoryToolsReal {
    log_recipient_setter: Box<dyn LogRecipientSetter>,
    automap_control_factory: Box<dyn AutomapControlFactory>,
}

impl ActorSystemFactoryTools for ActorSystemFactoryToolsReal {
    fn prepare_initial_messages(
        &self,
        cryptdes: CryptDEPair,
        config: BootstrapperConfig,
        persistent_config: Box<dyn PersistentConfiguration>,
        actor_factory: Box<dyn ActorFactory>,
    ) -> StreamHandlerPoolSubs {
        let db_initializer = DbInitializerReal::default();
        let (dispatcher_subs, pool_bind_sub) = actor_factory.make_and_start_dispatcher(&config);
        let proxy_server_subs = actor_factory.make_and_start_proxy_server(cryptdes, &config);
        let proxy_client_subs_opt = if !config.neighborhood_config.mode.is_consume_only() {
            Some(
                actor_factory.make_and_start_proxy_client(ProxyClientConfig {
                    cryptde: cryptdes.main,
                    dns_servers: config.dns_servers.clone(),
                    exit_service_rate: config
                        .neighborhood_config
                        .mode
                        .rate_pack()
                        .exit_service_rate,
                    exit_byte_rate: config.neighborhood_config.mode.rate_pack().exit_byte_rate,
                    is_decentralized: config.neighborhood_config.mode.is_decentralized(),
                    crashable: is_crashable(&config),
                }),
            )
        } else {
            None
        };
        let hopper_subs = actor_factory.make_and_start_hopper(HopperConfig {
            cryptdes,
            per_routing_service: config
                .neighborhood_config
                .mode
                .rate_pack()
                .routing_service_rate,
            per_routing_byte: config
                .neighborhood_config
                .mode
                .rate_pack()
                .routing_byte_rate,
            is_decentralized: config.neighborhood_config.mode.is_decentralized(),
            crashable: is_crashable(&config),
        });
        let blockchain_bridge_subs = actor_factory
            .make_and_start_blockchain_bridge(&config, &BlockchainBridgeSubsFactoryReal {});
        let neighborhood_subs = actor_factory.make_and_start_neighborhood(cryptdes.main, &config);
        let accountant_subs = actor_factory.make_and_start_accountant(
            config.clone(),
            &db_initializer,
            &BannedCacheLoaderReal {},
            &AccountantSubsFactoryReal {},
        );
        let ui_gateway_subs = actor_factory.make_and_start_ui_gateway(&config);
        let stream_handler_pool_subs = actor_factory.make_and_start_stream_handler_pool(&config);
        let configurator_subs = actor_factory.make_and_start_configurator(&config);

        // collect all the subs
        let peer_actors = PeerActors {
            dispatcher: dispatcher_subs.clone(),
            proxy_server: proxy_server_subs,
            proxy_client_opt: proxy_client_subs_opt.clone(),
            hopper: hopper_subs,
            neighborhood: neighborhood_subs.clone(),
            accountant: accountant_subs,
            ui_gateway: ui_gateway_subs.clone(),
            blockchain_bridge: blockchain_bridge_subs,
            configurator: configurator_subs,
        };

        //bind all the actors
        send_bind_message!(peer_actors.dispatcher, peer_actors);
        send_bind_message!(peer_actors.proxy_server, peer_actors);
        send_bind_message!(peer_actors.hopper, peer_actors);
        send_bind_message!(peer_actors.neighborhood, peer_actors);
        send_bind_message!(peer_actors.accountant, peer_actors);
        send_bind_message!(peer_actors.ui_gateway, peer_actors);
        send_bind_message!(peer_actors.blockchain_bridge, peer_actors);
        send_bind_message!(peer_actors.configurator, peer_actors);
        if let Some(subs) = proxy_client_subs_opt {
            send_bind_message!(subs, peer_actors);
        }
        stream_handler_pool_subs
            .bind
            .try_send(PoolBindMessage {
                dispatcher_subs: dispatcher_subs.clone(),
                stream_handler_pool_subs: stream_handler_pool_subs.clone(),
                neighborhood_subs: neighborhood_subs.clone(),
            })
            .expect("Stream Handler Pool is dead");
        pool_bind_sub
            .try_send(PoolBindMessage {
                dispatcher_subs,
                stream_handler_pool_subs: stream_handler_pool_subs.clone(),
                neighborhood_subs,
            })
            .expect("Dispatcher is dead");

        self.log_recipient_setter
            .prepare_log_recipient(ui_gateway_subs.node_to_ui_message_sub);

        self.start_automap(
            &config,
            persistent_config,
            vec![
                peer_actors.neighborhood.new_public_ip.clone(),
                peer_actors.dispatcher.new_ip_sub.clone(),
            ],
        );

        //after we've bound all the actors, send start messages to any actors that need it
        send_start_message!(peer_actors.neighborhood);

        stream_handler_pool_subs
    }

    fn cryptdes(&self) -> CryptDEPair {
        CryptDEPair::default()
    }

    fn validate_database_chain(
        &self,
        persistent_config: &dyn PersistentConfiguration,
        chain: Chain,
    ) {
        let from_db = persistent_config.chain_name();
        let demanded = chain.rec().literal_identifier.to_string();
        if demanded != from_db {
            panic!(
                "Database with a wrong chain name detected; expected: {}, was: {}",
                demanded, from_db
            )
        }
    }
}

impl ActorSystemFactoryToolsReal {
    pub fn new() -> Self {
        Self {
            log_recipient_setter: Box::new(LogRecipientSetterReal::new()),
            automap_control_factory: Box::new(AutomapControlFactoryReal::new()),
        }
    }

    fn notify_of_public_ip_change(
        new_ip_recipients: &[Recipient<NewPublicIp>],
        new_public_ip: IpAddr,
    ) {
        new_ip_recipients.iter().for_each(|r| {
            r.try_send(NewPublicIp {
                new_ip: new_public_ip,
            })
            .expect("NewPublicIp recipient is dead")
        });
    }

    fn handle_housekeeping_thread_error(error: AutomapError) {
        Self::handle_automap_error("", error);
    }

    fn handle_automap_error(prefix: &str, error: AutomapError) {
        exit_process(1, &format!("Automap failure: {}{:?}", prefix, error));
    }

    fn maybe_save_usual_protocol(
        automap_control: &dyn AutomapControl,
        persistent_config: &mut dyn PersistentConfiguration,
        b_config_entry_opt: Option<AutomapProtocol>,
    ) {
        match (b_config_entry_opt, automap_control.get_mapping_protocol()) {
            (Some(_), None) => {
                unreachable!("get_public_ip would've returned AllProtocolsFailed first")
            }
            (old_protocol, new_protocol) => {
                if old_protocol != new_protocol {
                    debug!(
                        Logger::new("ActorSystemFactory"),
                        "Saving a new mapping protocol '{:?}'; used to be '{:?}'",
                        new_protocol,
                        old_protocol
                    );
                    persistent_config
                        .set_mapping_protocol(new_protocol)
                        .expect("write of mapping protocol failed")
                }
            }
        }
    }

    fn start_automap(
        &self,
        config: &BootstrapperConfig,
        mut persistent_config: Box<dyn PersistentConfiguration>,
        new_ip_recipients: Vec<Recipient<NewPublicIp>>,
    ) {
        if let NeighborhoodMode::Standard(node_addr, _, _) = &config.neighborhood_config.mode {
            // If we already know the IP address, no need for Automap
            if node_addr.ip_addr() != IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
                return;
            }
            let change_handler = move |change: AutomapChange| match change {
                AutomapChange::NewIp(new_public_ip) => {
                    exit_process(
                        1,
                        format! ("IP change to {} reported from ISP. We can't handle that until GH-499. Going down...", new_public_ip).as_str()
                    );
                }
                AutomapChange::Error(e) => Self::handle_housekeeping_thread_error(e),
            };
            let mut automap_control = self
                .automap_control_factory
                .make(config.mapping_protocol_opt, Box::new(change_handler));
            let public_ip = match automap_control.get_public_ip() {
                Ok(ip) => ip,
                Err(e) => {
                    Self::handle_automap_error("Can't get public IP - ", e);
                    return; // never happens; handle_automap_error doesn't return.
                }
            };
            Self::maybe_save_usual_protocol(
                automap_control.as_ref(),
                persistent_config.as_mut(),
                config.mapping_protocol_opt,
            );
            Self::notify_of_public_ip_change(new_ip_recipients.as_slice(), public_ip);
            node_addr.ports().iter().for_each(|port| {
                if let Err(e) = automap_control.add_mapping(*port) {
                    Self::handle_automap_error(
                        &format!("Can't map port {} through the router - ", port),
                        e,
                    );
                }
            });
        }
    }
}

pub trait ActorFactory {
    fn make_and_start_dispatcher(
        &self,
        config: &BootstrapperConfig,
    ) -> (DispatcherSubs, Recipient<PoolBindMessage>);
    fn make_and_start_proxy_server(
        &self,
        cryptdes: CryptDEPair,
        config: &BootstrapperConfig,
    ) -> ProxyServerSubs;
    fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs;
    fn make_and_start_neighborhood(
        &self,
        cryptde: &'static dyn CryptDE,
        config: &BootstrapperConfig,
    ) -> NeighborhoodSubs;
    fn make_and_start_accountant(
        &self,
        config: BootstrapperConfig,
        db_initializer: &dyn DbInitializer,
        banned_cache_loader: &dyn BannedCacheLoader,
        subs_factory: &dyn SubsFactory<Accountant, AccountantSubs>,
    ) -> AccountantSubs;
    fn make_and_start_ui_gateway(&self, config: &BootstrapperConfig) -> UiGatewaySubs;
    fn make_and_start_stream_handler_pool(
        &self,
        config: &BootstrapperConfig,
    ) -> StreamHandlerPoolSubs;
    fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs;
    fn make_and_start_blockchain_bridge(
        &self,
        config: &BootstrapperConfig,
        subs_factory: &dyn SubsFactory<BlockchainBridge, BlockchainBridgeSubs>,
    ) -> BlockchainBridgeSubs;
    fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs;
}

pub struct ActorFactoryReal {
    logger: Logger,
}

impl ActorFactoryReal {
    pub fn new() -> Self {
        Self {
            logger: Logger::new("ActorFactory"),
        }
    }
}

impl ActorFactory for ActorFactoryReal {
    fn make_and_start_dispatcher(
        &self,
        config: &BootstrapperConfig,
    ) -> (DispatcherSubs, Recipient<PoolBindMessage>) {
        let node_descriptor = config.node_descriptor.clone();
        let crashable = is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Dispatcher> =
            arbiter.start(move |_| Dispatcher::new(node_descriptor, crashable));
        (
            Dispatcher::make_subs_from(&addr),
            addr.recipient::<PoolBindMessage>(),
        )
    }

    fn make_and_start_proxy_server(
        &self,
        cryptdes: CryptDEPair,
        config: &BootstrapperConfig,
    ) -> ProxyServerSubs {
        let is_decentralized = config.neighborhood_config.mode.is_decentralized();
        let consuming_wallet_balance = if config.consuming_wallet_opt.is_some() {
            Some(0) //TODO this is an old unfinished concept, repair or remove it...never used.
        } else {
            None
        };
        let crashable = is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<ProxyServer> = arbiter.start(move |_| {
            ProxyServer::new(
                cryptdes.main,
                cryptdes.alias,
                is_decentralized,
                consuming_wallet_balance,
                crashable,
            )
        });
        ProxyServer::make_subs_from(&addr)
    }

    fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs {
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Hopper> = arbiter.start(move |_| Hopper::new(config));
        Hopper::make_subs_from(&addr)
    }

    fn make_and_start_neighborhood(
        &self,
        cryptde: &'static dyn CryptDE,
        config: &BootstrapperConfig,
    ) -> NeighborhoodSubs {
        let config_clone = config.clone();
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Neighborhood> =
            arbiter.start(move |_| Neighborhood::new(cryptde, &config_clone));
        Neighborhood::make_subs_from(&addr)
    }

    fn make_and_start_accountant(
        &self,
        config: BootstrapperConfig,
        db_initializer: &dyn DbInitializer,
        banned_cache_loader: &dyn BannedCacheLoader,
        subs_factory: &dyn SubsFactory<Accountant, AccountantSubs>,
    ) -> AccountantSubs {
        let data_directory = config.data_directory.as_path();
        let payable_dao_factory = Box::new(Accountant::dao_factory(data_directory));
        let pending_payable_dao_factory = Box::new(Accountant::dao_factory(data_directory));
        let receivable_dao_factory = Box::new(Accountant::dao_factory(data_directory));
        let banned_dao_factory = Box::new(Accountant::dao_factory(data_directory));
        let config_dao_factory = Box::new(Accountant::dao_factory(data_directory));
        Self::load_banned_cache(db_initializer, banned_cache_loader, data_directory);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Accountant> = arbiter.start(move |_| {
            Accountant::new(
                config,
                DaoFactories {
                    payable_dao_factory,
                    pending_payable_dao_factory,
                    receivable_dao_factory,
                    banned_dao_factory,
                    config_dao_factory,
                },
            )
        });
        subs_factory.make(&addr)
    }

    fn make_and_start_ui_gateway(&self, config: &BootstrapperConfig) -> UiGatewaySubs {
        let crashable = is_crashable(config);
        let ui_gateway = UiGateway::new(&config.ui_gateway_config, crashable);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<UiGateway> = arbiter.start(move |_| ui_gateway);
        UiGateway::make_subs_from(&addr)
    }

    fn make_and_start_stream_handler_pool(
        &self,
        config: &BootstrapperConfig,
    ) -> StreamHandlerPoolSubs {
        let clandestine_discriminator_factories =
            config.clandestine_discriminator_factories.clone();
        let crashable = is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<StreamHandlerPool> = arbiter
            .start(move |_| StreamHandlerPool::new(clandestine_discriminator_factories, crashable));
        StreamHandlerPool::make_subs_from(&addr)
    }

    fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs {
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<ProxyClient> = arbiter.start(move |_| ProxyClient::new(config));
        ProxyClient::make_subs_from(&addr)
    }

    fn make_and_start_blockchain_bridge(
        &self,
        config: &BootstrapperConfig,
        subs_factory: &dyn SubsFactory<BlockchainBridge, BlockchainBridgeSubs>,
    ) -> BlockchainBridgeSubs {
        let blockchain_service_url_opt = config
            .blockchain_bridge_config
            .blockchain_service_url_opt
            .clone();
        let crashable = is_crashable(config);
        let data_directory = config.data_directory.clone();
        let chain = config.blockchain_bridge_config.chain;
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let logger = self.logger.clone();
        let addr: Addr<BlockchainBridge> = arbiter.start(move |_| {
            let blockchain_interface = BlockchainBridge::initialize_blockchain_interface(
                blockchain_service_url_opt,
                chain,
                logger,
            );
            let persistent_config =
                BlockchainBridge::initialize_persistent_configuration(&data_directory);
            BlockchainBridge::new(blockchain_interface, persistent_config, crashable)
        });
        subs_factory.make(&addr)
    }

    fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs {
        let data_directory = config.data_directory.clone();
        let crashable = is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Configurator> =
            arbiter.start(move |_| Configurator::new(data_directory, crashable));
        ConfiguratorSubs {
            bind: recipient!(addr, BindMessage),
            node_from_ui_sub: recipient!(addr, NodeFromUiMessage),
        }
    }
}

impl ActorFactoryReal {
    fn load_banned_cache(
        db_initializer: &dyn DbInitializer,
        banned_cache_loader: &dyn BannedCacheLoader,
        data_directory: &Path,
    ) {
        banned_cache_loader.load(connection_or_panic(
            db_initializer,
            data_directory,
            DbInitializationConfig::panic_on_migration(),
        ));
    }
}

fn is_crashable(config: &BootstrapperConfig) -> bool {
    config.crash_point == CrashPoint::Message
}

pub trait AutomapControlFactory {
    fn make(
        &self,
        usual_protocol_opt: Option<AutomapProtocol>,
        change_handler: ChangeHandler,
    ) -> Box<dyn AutomapControl>;
}

pub struct AutomapControlFactoryReal {}

impl AutomapControlFactory for AutomapControlFactoryReal {
    fn make(
        &self,
        usual_protocol_opt: Option<AutomapProtocol>,
        change_handler: ChangeHandler,
    ) -> Box<dyn AutomapControl> {
        Box::new(AutomapControlReal::new(usual_protocol_opt, change_handler))
    }
}

impl AutomapControlFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct AutomapControlFactoryNull {}

impl AutomapControlFactory for AutomapControlFactoryNull {
    fn make(
        &self,
        _usual_protocol_opt: Option<AutomapProtocol>,
        _change_handler: ChangeHandler,
    ) -> Box<dyn AutomapControl> {
        panic!("Should never call make() on an AutomapControlFactoryNull.");
    }
}

trait LogRecipientSetter: Send {
    fn prepare_log_recipient(&self, recipient: Recipient<NodeToUiMessage>);
}

struct LogRecipientSetterReal {}

impl LogRecipientSetterReal {
    pub fn new() -> Self {
        Self {}
    }
}

impl LogRecipientSetter for LogRecipientSetterReal {
    fn prepare_log_recipient(&self, recipient: Recipient<NodeToUiMessage>) {
        prepare_log_recipient(recipient);
    }
}

// Test writing easing stuff. If further examination of the actor
// starting methods in ActorFactory is desirable.
// This allows to get the started actor's address and then messages
// can be sent to it, possibly the AssertionMessage.
pub trait SubsFactory<Actor, ActorSubs>
where
    Actor: actix::Actor,
{
    fn make(&self, addr: &Addr<Actor>) -> ActorSubs;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::exportable_test_parts::test_accountant_is_constructed_with_upgraded_db_connection_recognizing_our_extra_sqlite_functions;
    use crate::accountant::{ReceivedPayments, DEFAULT_PENDING_TOO_LONG_SEC};
    use crate::blockchain::blockchain_bridge::RetrieveTransactions;
    use crate::bootstrapper::{Bootstrapper, RealUser};
    use crate::db_config::persistent_configuration::PersistentConfigurationReal;
    use crate::node_test_utils::{
        make_stream_handler_pool_subs_from_recorder, start_recorder_refcell_opt,
    };
    use crate::sub_lib::accountant::{PaymentThresholds, ScanIntervals};
    use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
    use crate::sub_lib::cryptde::{PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::dispatcher::{InboundClientData, StreamShutdownMsg};
    use crate::sub_lib::neighborhood::NeighborhoodMode;
    use crate::sub_lib::neighborhood::NodeDescriptor;
    use crate::sub_lib::neighborhood::{NeighborhoodConfig, DEFAULT_RATE_PACK};
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::peer_actors::StartMessage;
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::sub_lib::ui_gateway::UiGatewayConfig;
    use crate::test_utils::actor_system_factory::BannedCacheLoaderMock;
    use crate::test_utils::automap_mocks::{AutomapControlFactoryMock, AutomapControlMock};
    use crate::test_utils::make_wallet;
    use crate::test_utils::neighborhood_test_utils::MIN_HOPS_FOR_TEST;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{
        make_accountant_subs_from_recorder, make_blockchain_bridge_subs_from_recorder,
        make_configurator_subs_from_recorder, make_hopper_subs_from_recorder,
        make_neighborhood_subs_from_recorder, make_proxy_client_subs_from_recorder,
        make_proxy_server_subs_from_recorder, make_ui_gateway_subs_from_recorder,
        peer_actors_builder, Recording,
    };
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::recorder_stop_conditions::{StopCondition, StopConditions};
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use crate::test_utils::unshared_test_utils::system_killer_actor::SystemKillerActor;
    use crate::test_utils::unshared_test_utils::{
        assert_on_initialization_with_panic_on_migration, SubsFactoryTestAddrLeaker,
    };
    use crate::test_utils::{alias_cryptde, rate_pack};
    use crate::test_utils::{main_cryptde, make_cryptde_pair};
    use crate::{
        hopper, match_every_type_id, proxy_client, proxy_server, stream_handler_pool, ui_gateway,
    };
    use actix::{Actor, Arbiter, System};
    use automap_lib::control_layer::automap_control::AutomapChange;
    #[cfg(all(test, not(feature = "no_test_share")))]
    use automap_lib::mocks::{
        parameterizable_automap_control, TransactorMock, PUBLIC_IP, ROUTER_IP,
    };
    use core::any::TypeId;
    use crossbeam_channel::{bounded, unbounded};
    use log::LevelFilter;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::crash_point::CrashPoint;
    #[cfg(feature = "log_recipient_test")]
    use masq_lib::logger::INITIALIZATION_COUNTER;
    use masq_lib::messages::{ToMessageBody, UiCrashRequest, UiDescriptorRequest};
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_exists, LogObject, TEST_DEFAULT_CHAIN,
    };
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::utils::AutomapProtocol::Igdp;
    use masq_lib::utils::{find_free_port, running_test};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::net::Ipv4Addr;
    use std::net::{IpAddr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use std::ptr::addr_of;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    struct LogRecipientSetterNull {}

    impl LogRecipientSetterNull {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl LogRecipientSetter for LogRecipientSetterNull {
        fn prepare_log_recipient(&self, _recipient: Recipient<NodeToUiMessage>) {}
    }

    #[derive(Default)]
    struct ActorSystemFactoryToolsMock {
        prepare_initial_messages_params: Arc<
            Mutex<
                Vec<(
                    Box<dyn CryptDE>,
                    Box<dyn CryptDE>,
                    BootstrapperConfig,
                    Box<dyn ActorFactory>,
                    Box<dyn PersistentConfiguration>,
                )>,
            >,
        >,
        prepare_initial_messages_results: RefCell<Vec<StreamHandlerPoolSubs>>,
        cryptdes_results: RefCell<Vec<CryptDEPair>>,
        validate_database_chain_params: Arc<Mutex<Vec<(ArbitraryIdStamp, Chain)>>>,
    }

    impl ActorSystemFactoryTools for ActorSystemFactoryToolsMock {
        fn prepare_initial_messages(
            &self,
            cryptdes: CryptDEPair,
            config: BootstrapperConfig,
            persistent_config: Box<dyn PersistentConfiguration>,
            actor_factory: Box<dyn ActorFactory>,
        ) -> StreamHandlerPoolSubs {
            self.prepare_initial_messages_params.lock().unwrap().push((
                Box::new(<&CryptDENull>::from(cryptdes.main).clone()),
                Box::new(<&CryptDENull>::from(cryptdes.alias).clone()),
                config,
                actor_factory,
                persistent_config,
            ));
            self.prepare_initial_messages_results.borrow_mut().remove(0)
        }

        fn cryptdes(&self) -> CryptDEPair {
            self.cryptdes_results.borrow_mut().remove(0)
        }

        fn validate_database_chain(
            &self,
            persistent_config: &dyn PersistentConfiguration,
            chain: Chain,
        ) {
            self.validate_database_chain_params
                .lock()
                .unwrap()
                .push((persistent_config.arbitrary_id_stamp(), chain));
        }
    }

    impl ActorSystemFactoryToolsMock {
        pub fn cryptdes_result(self, result: CryptDEPair) -> Self {
            self.cryptdes_results.borrow_mut().push(result);
            self
        }

        pub fn validate_database_chain_params(
            mut self,
            params: &Arc<Mutex<Vec<(ArbitraryIdStamp, Chain)>>>,
        ) -> Self {
            self.validate_database_chain_params = params.clone();
            self
        }

        pub fn prepare_initial_messages_params(
            mut self,
            params: &Arc<
                Mutex<
                    Vec<(
                        Box<dyn CryptDE>,
                        Box<dyn CryptDE>,
                        BootstrapperConfig,
                        Box<dyn ActorFactory>,
                        Box<dyn PersistentConfiguration>,
                    )>,
                >,
            >,
        ) -> Self {
            self.prepare_initial_messages_params = params.clone();
            self
        }

        pub fn prepare_initial_messages_result(self, result: StreamHandlerPoolSubs) -> Self {
            self.prepare_initial_messages_results
                .borrow_mut()
                .push(result);
            self
        }
    }

    struct ActorFactoryMock<'a> {
        dispatcher: RefCell<Option<Recorder>>,
        proxy_client: RefCell<Option<Recorder>>,
        proxy_server: RefCell<Option<Recorder>>,
        hopper: RefCell<Option<Recorder>>,
        neighborhood: RefCell<Option<Recorder>>,
        accountant: RefCell<Option<Recorder>>,
        stream_handler_pool: RefCell<Option<Recorder>>,
        ui_gateway: RefCell<Option<Recorder>>,
        blockchain_bridge: RefCell<Option<Recorder>>,
        configurator: RefCell<Option<Recorder>>,

        parameters: Parameters<'a>,
    }

    impl<'a> ActorFactory for ActorFactoryMock<'a> {
        fn make_and_start_dispatcher(
            &self,
            config: &BootstrapperConfig,
        ) -> (DispatcherSubs, Recipient<PoolBindMessage>) {
            self.parameters
                .dispatcher_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.dispatcher);
            let dispatcher_subs = DispatcherSubs {
                ibcd_sub: recipient!(addr, InboundClientData),
                bind: recipient!(addr, BindMessage),
                from_dispatcher_client: recipient!(addr, TransmitDataMsg),
                stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
                ui_sub: recipient!(addr, NodeFromUiMessage),
                new_ip_sub: recipient!(addr, NewPublicIp),
            };
            (dispatcher_subs, addr.recipient::<PoolBindMessage>())
        }

        fn make_and_start_proxy_server(
            &self,
            cryptdes: CryptDEPair,
            config: &BootstrapperConfig,
        ) -> ProxyServerSubs {
            self.parameters
                .proxy_server_params
                .lock()
                .unwrap()
                .get_or_insert((cryptdes, config.clone()));
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.proxy_server);
            make_proxy_server_subs_from_recorder(&addr)
        }

        fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs {
            self.parameters
                .hopper_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.hopper);
            make_hopper_subs_from_recorder(&addr)
        }

        fn make_and_start_neighborhood(
            &self,
            cryptde: &'a dyn CryptDE,
            config: &BootstrapperConfig,
        ) -> NeighborhoodSubs {
            self.parameters
                .neighborhood_params
                .lock()
                .unwrap()
                .get_or_insert((cryptde, config.clone()));
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.neighborhood);
            make_neighborhood_subs_from_recorder(&addr)
        }

        fn make_and_start_accountant(
            &self,
            config: BootstrapperConfig,
            _db_initializer: &dyn DbInitializer,
            _banned_cache_loader: &dyn BannedCacheLoader,
            _accountant_subs_factory: &dyn SubsFactory<Accountant, AccountantSubs>,
        ) -> AccountantSubs {
            self.parameters
                .accountant_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.accountant);
            make_accountant_subs_from_recorder(&addr)
        }

        fn make_and_start_ui_gateway(&self, config: &BootstrapperConfig) -> UiGatewaySubs {
            self.parameters
                .ui_gateway_params
                .lock()
                .unwrap()
                .get_or_insert(config.ui_gateway_config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.ui_gateway);
            make_ui_gateway_subs_from_recorder(&addr)
        }

        fn make_and_start_stream_handler_pool(
            &self,
            _: &BootstrapperConfig,
        ) -> StreamHandlerPoolSubs {
            let addr = start_recorder_refcell_opt(&self.stream_handler_pool);
            make_stream_handler_pool_subs_from_recorder(&addr)
        }

        fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs {
            self.parameters
                .proxy_client_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.proxy_client);
            make_proxy_client_subs_from_recorder(&addr)
        }

        fn make_and_start_blockchain_bridge(
            &self,
            config: &BootstrapperConfig,
            _subs_factory: &dyn SubsFactory<BlockchainBridge, BlockchainBridgeSubs>,
        ) -> BlockchainBridgeSubs {
            self.parameters
                .blockchain_bridge_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.blockchain_bridge);
            make_blockchain_bridge_subs_from_recorder(&addr)
        }

        fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs {
            self.parameters
                .configurator_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.configurator);
            make_configurator_subs_from_recorder(&addr)
        }
    }

    struct Recordings {
        dispatcher: Arc<Mutex<Recording>>,
        proxy_client: Arc<Mutex<Recording>>,
        proxy_server: Arc<Mutex<Recording>>,
        hopper: Arc<Mutex<Recording>>,
        neighborhood: Arc<Mutex<Recording>>,
        accountant: Arc<Mutex<Recording>>,
        stream_handler_pool: Arc<Mutex<Recording>>,
        ui_gateway: Arc<Mutex<Recording>>,
        blockchain_bridge: Arc<Mutex<Recording>>,
        configurator: Arc<Mutex<Recording>>,
    }

    #[derive(Clone)]
    struct Parameters<'a> {
        dispatcher_params: Arc<Mutex<Option<BootstrapperConfig>>>,
        proxy_client_params: Arc<Mutex<Option<ProxyClientConfig>>>,
        proxy_server_params: Arc<Mutex<Option<(CryptDEPair, BootstrapperConfig)>>>,
        hopper_params: Arc<Mutex<Option<HopperConfig>>>,
        neighborhood_params: Arc<Mutex<Option<(&'a dyn CryptDE, BootstrapperConfig)>>>,
        accountant_params: Arc<Mutex<Option<BootstrapperConfig>>>,
        ui_gateway_params: Arc<Mutex<Option<UiGatewayConfig>>>,
        blockchain_bridge_params: Arc<Mutex<Option<BootstrapperConfig>>>,
        configurator_params: Arc<Mutex<Option<BootstrapperConfig>>>,
    }

    impl<'a> Parameters<'a> {
        pub fn new() -> Parameters<'a> {
            Parameters {
                dispatcher_params: Arc::new(Mutex::new(None)),
                proxy_client_params: Arc::new(Mutex::new(None)),
                proxy_server_params: Arc::new(Mutex::new(None)),
                hopper_params: Arc::new(Mutex::new(None)),
                neighborhood_params: Arc::new(Mutex::new(None)),
                accountant_params: Arc::new(Mutex::new(None)),
                ui_gateway_params: Arc::new(Mutex::new(None)),
                blockchain_bridge_params: Arc::new(Mutex::new(None)),
                configurator_params: Arc::new(Mutex::new(None)),
            }
        }

        pub fn get<T: Clone>(params_arc: Arc<Mutex<Option<T>>>) -> T {
            let params_opt = params_arc.lock().unwrap();
            params_opt.as_ref().unwrap().clone()
        }
    }

    impl<'a> ActorFactoryMock<'a> {
        pub fn new() -> ActorFactoryMock<'a> {
            ActorFactoryMock {
                dispatcher: RefCell::new(Some(Recorder::new())),
                proxy_client: RefCell::new(Some(Recorder::new())),
                proxy_server: RefCell::new(Some(Recorder::new())),
                hopper: RefCell::new(Some(Recorder::new())),
                neighborhood: RefCell::new(Some(Recorder::new())),
                accountant: RefCell::new(Some(Recorder::new())),
                stream_handler_pool: RefCell::new(Some(Recorder::new())),
                ui_gateway: RefCell::new(Some(Recorder::new())),
                blockchain_bridge: RefCell::new(Some(Recorder::new())),
                configurator: RefCell::new(Some(Recorder::new())),

                parameters: Parameters::new(),
            }
        }

        pub fn get_recordings(&self) -> Recordings {
            Recordings {
                dispatcher: self.dispatcher.borrow().as_ref().unwrap().get_recording(),
                proxy_client: self.proxy_client.borrow().as_ref().unwrap().get_recording(),
                proxy_server: self.proxy_server.borrow().as_ref().unwrap().get_recording(),
                hopper: self.hopper.borrow().as_ref().unwrap().get_recording(),
                neighborhood: self.neighborhood.borrow().as_ref().unwrap().get_recording(),
                accountant: self.accountant.borrow().as_ref().unwrap().get_recording(),
                stream_handler_pool: self
                    .stream_handler_pool
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .get_recording(),
                ui_gateway: self.ui_gateway.borrow().as_ref().unwrap().get_recording(),
                blockchain_bridge: self
                    .blockchain_bridge
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .get_recording(),
                configurator: self.configurator.borrow().as_ref().unwrap().get_recording(),
            }
        }

        pub fn make_parameters(&self) -> Parameters<'a> {
            self.parameters.clone()
        }

        fn start_recorder(recorder: &RefCell<Option<Recorder>>) -> Addr<Recorder> {
            recorder.borrow_mut().take().unwrap().start()
        }
    }

    #[test]
    fn make_and_start_actors_happy_path() {
        let validate_database_chain_params_arc = Arc::new(Mutex::new(vec![]));
        let prepare_initial_messages_params_arc = Arc::new(Mutex::new(vec![]));
        let (stream_handler_pool, _, stream_handler_pool_recording_arc) = make_recorder();
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let cryptde_pair = CryptDEPair {
            main: main_cryptde,
            alias: alias_cryptde,
        };
        let main_cryptde_public_key_expected = pk_from_cryptde_null(main_cryptde);
        let alias_cryptde_public_key_expected = pk_from_cryptde_null(alias_cryptde);
        let actor_factory = Box::new(ActorFactoryReal::new());
        let actor_factory_raw_address_expected = addr_of!(*actor_factory);
        let persistent_config_expected_arbitrary_id = ArbitraryIdStamp::new();
        let persistent_config = Box::new(
            PersistentConfigurationMock::default()
                .set_arbitrary_id_stamp(persistent_config_expected_arbitrary_id),
        );
        let stream_holder_pool_subs =
            make_stream_handler_pool_subs_from_recorder(&stream_handler_pool.start());
        let actor_system_factor_tools = ActorSystemFactoryToolsMock::default()
            .validate_database_chain_params(&validate_database_chain_params_arc)
            .cryptdes_result(cryptde_pair)
            .prepare_initial_messages_params(&prepare_initial_messages_params_arc)
            .prepare_initial_messages_result(stream_holder_pool_subs);
        let data_dir = PathBuf::new().join("parent_directory/child_directory");
        let subject = ActorSystemFactoryReal::new(Box::new(actor_system_factor_tools));
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.blockchain_bridge_config.chain = Chain::PolyMainnet;
        bootstrapper_config.data_directory = data_dir.clone();
        bootstrapper_config.db_password_opt = Some("password".to_string());

        let result =
            subject.make_and_start_actors(bootstrapper_config, actor_factory, persistent_config);

        let mut validate_database_chain_params = validate_database_chain_params_arc.lock().unwrap();
        let (persistent_config_actual_arbitrary_id, actual_chain) =
            validate_database_chain_params.remove(0);
        assert_eq!(
            persistent_config_actual_arbitrary_id,
            persistent_config_expected_arbitrary_id
        );
        assert_eq!(actual_chain, Chain::PolyMainnet);
        assert!(validate_database_chain_params.is_empty());
        let mut prepare_initial_messages_params =
            prepare_initial_messages_params_arc.lock().unwrap();
        let (
            main_cryptde_actual,
            alias_cryptde_actual,
            bootstrapper_config_actual,
            actor_factory_actual,
            persistent_config_actual,
        ) = prepare_initial_messages_params.remove(0);
        let main_cryptde_public_key_actual = pk_from_cryptde_null(main_cryptde_actual.as_ref());
        assert_eq!(
            main_cryptde_public_key_actual,
            main_cryptde_public_key_expected
        );
        let alias_cryptde_public_key_actual = pk_from_cryptde_null(alias_cryptde_actual.as_ref());
        assert_eq!(
            alias_cryptde_public_key_actual,
            alias_cryptde_public_key_expected
        );
        assert_eq!(bootstrapper_config_actual.data_directory, data_dir);
        assert_eq!(
            bootstrapper_config_actual.db_password_opt,
            Some("password".to_string())
        );
        assert_eq!(
            addr_of!(*actor_factory_actual),
            actor_factory_raw_address_expected
        );
        assert_eq!(
            persistent_config_actual.arbitrary_id_stamp(),
            persistent_config_expected_arbitrary_id
        );
        assert!(prepare_initial_messages_params.is_empty());
        verify_recipient(&result.node_from_ui_sub, &stream_handler_pool_recording_arc)
    }

    fn verify_recipient(
        recipient: &Recipient<NodeFromUiMessage>,
        recording_arc: &Arc<Mutex<Recording>>,
    ) {
        let system = System::new("verifying_recipient_returned_in_test");
        let expected_msg = NodeFromUiMessage {
            client_id: 5,
            body: UiDescriptorRequest {}.tmb(1),
        };

        recipient.try_send(expected_msg.clone()).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let recording = recording_arc.lock().unwrap();
        let actual_msg = recording.get_record::<NodeFromUiMessage>(0);
        assert_eq!(actual_msg, &expected_msg);
    }

    #[test]
    fn make_and_start_actors_sends_bind_messages() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            scan_intervals_opt: Some(ScanIntervals::default()),
            suppress_initial_scans: false,
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig { ui_port: 5335 },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet_opt: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor: NodeDescriptor::default(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), &[]),
                    vec![],
                    rate_pack(100),
                ),
                min_hops: MIN_HOPS_FOR_TEST,
            },
            payment_thresholds_opt: Some(PaymentThresholds::default()),
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
        };
        let persistent_config = PersistentConfigurationMock::default()
            .chain_name_result("eth-ropsten".to_string())
            .set_min_hops_result(Ok(()));
        Bootstrapper::pub_initialize_cryptdes_for_testing(
            &Some(main_cryptde()),
            &Some(alias_cryptde()),
        );
        let mut tools = make_subject_with_null_setter();
        tools.automap_control_factory = Box::new(
            AutomapControlFactoryMock::new().make_result(Box::new(
                AutomapControlMock::new()
                    .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
                    .add_mapping_result(Ok(())),
            )),
        );
        let subject = ActorSystemFactoryReal::new(Box::new(tools));
        let system = System::new("test");

        subject.make_and_start_actors(config, Box::new(actor_factory), Box::new(persistent_config));
        System::current().stop();
        system.run();
        thread::sleep(Duration::from_millis(100));
        Recording::get::<BindMessage>(&recordings.dispatcher, 0);
        Recording::get::<BindMessage>(&recordings.hopper, 0);
        Recording::get::<BindMessage>(&recordings.proxy_client, 0);
        Recording::get::<BindMessage>(&recordings.proxy_server, 0);
        Recording::get::<BindMessage>(&recordings.neighborhood, 0);
        Recording::get::<BindMessage>(&recordings.accountant, 0);
        Recording::get::<BindMessage>(&recordings.ui_gateway, 0);
        Recording::get::<BindMessage>(&recordings.blockchain_bridge, 0);
        Recording::get::<BindMessage>(&recordings.configurator, 0);
        Recording::get::<PoolBindMessage>(&recordings.stream_handler_pool, 0);
        Recording::get::<StartMessage>(&recordings.neighborhood, 1);
    }

    #[test]
    fn prepare_initial_messages_generates_the_correct_messages() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let parameters = actor_factory.make_parameters();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            scan_intervals_opt: None,
            suppress_initial_scans: false,
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig { ui_port: 5335 },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet_opt: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor: NodeDescriptor::try_from ((main_cryptde(), "masq://polygon-mainnet:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@172.50.48.6:9342")).unwrap(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: Some(AutomapProtocol::Igdp),
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), &[1234, 2345]),
                    vec![],
                    rate_pack(100),
                ),
                min_hops: MIN_HOPS_FOR_TEST,
            },
            payment_thresholds_opt: Default::default(),
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC
        };
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_subject_with_null_setter();
        subject.automap_control_factory = Box::new(
            AutomapControlFactoryMock::new().make_result(Box::new(
                AutomapControlMock::new()
                    .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
                    .get_mapping_protocol_result(Some(AutomapProtocol::Igdp))
                    .add_mapping_params(&add_mapping_params_arc)
                    .add_mapping_result(Ok(()))
                    .add_mapping_result(Ok(())),
            )),
        );

        let _ = subject.prepare_initial_messages(
            make_cryptde_pair(),
            config.clone(),
            Box::new(PersistentConfigurationMock::new()),
            Box::new(actor_factory),
        );

        let system = System::new("MASQNode");
        System::current().stop();
        system.run();
        check_bind_message(&recordings.dispatcher, false);
        check_bind_message(&recordings.hopper, false);
        check_bind_message(&recordings.proxy_client, false);
        check_bind_message(&recordings.proxy_server, false);
        check_bind_message(&recordings.neighborhood, false);
        check_bind_message(&recordings.ui_gateway, false);
        check_bind_message(&recordings.accountant, false);
        check_new_ip_message(
            &recordings.dispatcher,
            IpAddr::from_str("1.2.3.4").unwrap(),
            2,
        );
        check_new_ip_message(
            &recordings.neighborhood,
            IpAddr::from_str("1.2.3.4").unwrap(),
            1,
        );
        check_start_message(&recordings.neighborhood, 2);
        let hopper_config = Parameters::get(parameters.hopper_params);
        check_cryptde(hopper_config.cryptdes.main);
        assert_eq!(hopper_config.per_routing_service, 300);
        assert_eq!(hopper_config.per_routing_byte, 101);
        let proxy_client_config = Parameters::get(parameters.proxy_client_params);
        check_cryptde(proxy_client_config.cryptde);
        assert_eq!(proxy_client_config.exit_service_rate, 500);
        assert_eq!(proxy_client_config.exit_byte_rate, 103);
        assert_eq!(proxy_client_config.dns_servers, config.dns_servers);
        assert_eq!(proxy_client_config.is_decentralized, true);
        let (actual_cryptde_pair, bootstrapper_config) =
            Parameters::get(parameters.proxy_server_params);
        check_cryptde(actual_cryptde_pair.main);
        check_cryptde(actual_cryptde_pair.alias);
        assert_ne!(
            actual_cryptde_pair.main.public_key(),
            actual_cryptde_pair.alias.public_key()
        );
        assert_eq!(
            bootstrapper_config
                .neighborhood_config
                .mode
                .is_decentralized(),
            true
        );
        assert_eq!(
            bootstrapper_config.consuming_wallet_opt,
            Some(make_wallet("consuming"))
        );
        let (cryptde, neighborhood_config) = Parameters::get(parameters.neighborhood_params);
        check_cryptde(cryptde);
        assert_eq!(
            neighborhood_config.neighborhood_config,
            config.neighborhood_config
        );
        assert_eq!(
            neighborhood_config.consuming_wallet_opt,
            config.consuming_wallet_opt
        );
        let ui_gateway_config = Parameters::get(parameters.ui_gateway_params);
        assert_eq!(ui_gateway_config.ui_port, 5335);
        let dispatcher_param = Parameters::get(parameters.dispatcher_params);
        assert_eq!(
            dispatcher_param.node_descriptor,
            NodeDescriptor::try_from ((main_cryptde(), "masq://polygon-mainnet:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@172.50.48.6:9342")).unwrap()
        );
        let blockchain_bridge_param = Parameters::get(parameters.blockchain_bridge_params);
        assert_eq!(
            blockchain_bridge_param.blockchain_bridge_config,
            BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1
            }
        );
        assert_eq!(
            blockchain_bridge_param.consuming_wallet_opt,
            Some(make_wallet("consuming"))
        );
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_mapping_params, vec![1234, 2345]);
    }

    #[cfg(feature = "log_recipient_test")]
    #[test]
    fn prepare_initial_messages_initiates_global_log_recipient() {
        let _guard = TEST_LOG_RECIPIENT_GUARD.lock().unwrap();
        running_test();
        let actor_factory = ActorFactoryMock::new();
        let mut config = BootstrapperConfig::default();
        config.neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::ConsumeOnly(vec![]),
            min_hops: MIN_HOPS_FOR_TEST,
        };
        let subject = ActorSystemFactoryToolsReal::new();
        let state_before = INITIALIZATION_COUNTER.lock().unwrap().0;

        let _ =
            subject.prepare_initial_messages(make_cryptde_pair(), config, Box::new(actor_factory));

        let state_after = INITIALIZATION_COUNTER.lock().unwrap().0;
        assert_eq!(state_after, state_before + 1)
    }

    #[test]
    #[should_panic(
        expected = "1: IP change to 1.2.3.5 reported from ISP. We can't handle that until GH-499. Going down..."
    )]
    fn change_handler_panics_when_receiving_ip_change_from_isp() {
        running_test();
        let actor_factory = ActorFactoryMock::new();
        let mut config = BootstrapperConfig::default();
        config.mapping_protocol_opt = Some(AutomapProtocol::Pcp);
        config.neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), &[1234]),
                vec![],
                rate_pack(100),
            ),
            min_hops: MIN_HOPS_FOR_TEST,
        };
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_subject_with_null_setter();
        subject.automap_control_factory = Box::new(
            AutomapControlFactoryMock::new()
                .make_params(&make_params_arc)
                .make_result(Box::new(
                    AutomapControlMock::new()
                        .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
                        .get_mapping_protocol_result(Some(AutomapProtocol::Pcp))
                        .add_mapping_result(Ok(())),
                )),
        );

        let _ = subject.prepare_initial_messages(
            make_cryptde_pair(),
            config.clone(),
            Box::new(PersistentConfigurationMock::new()),
            Box::new(actor_factory),
        );

        let mut make_params = make_params_arc.lock().unwrap();
        let change_handler: ChangeHandler = make_params.remove(0).1;
        change_handler(AutomapChange::NewIp(IpAddr::from_str("1.2.3.5").unwrap()));

        let system = System::new("MASQNode");
        System::current().stop();
        system.run();
    }

    #[test]
    fn discovered_automap_protocol_is_written_into_the_db() {
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let (tx, _rx) = unbounded();
        let mut config = BootstrapperConfig::default();
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );
        let persistent_config = PersistentConfigurationMock::default()
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .set_mapping_protocol_result(Ok(()));
        let (recorder, _, _) = make_recorder();
        let new_ip_recipient = recorder.start().recipient();
        let pcp_mock = TransactorMock::new(AutomapProtocol::Pcp).find_routers_result(Ok(vec![]));
        let pmp_mock = TransactorMock::new(AutomapProtocol::Pmp)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .start_housekeeping_thread_result(Ok(tx))
            .stop_housekeeping_thread_result(Ok(Box::new(|_| ())))
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_result(Ok(1000));
        let igdp_mock = TransactorMock::new(AutomapProtocol::Igdp).find_routers_result(Ok(vec![]));
        let change_handler = Box::new(|_| ());
        let automap_control: Box<dyn AutomapControl> = Box::new(parameterizable_automap_control(
            change_handler,
            None,
            vec![pcp_mock, pmp_mock, igdp_mock],
        ));
        let automap_control_factory =
            Box::new(AutomapControlFactoryMock::default().make_result(automap_control));
        let mut subject = ActorSystemFactoryToolsReal::new();
        subject.automap_control_factory = automap_control_factory;

        subject.start_automap(&config, Box::new(persistent_config), vec![new_ip_recipient]);

        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(
            *set_mapping_protocol_params,
            vec![Some(AutomapProtocol::Pmp)]
        )
    }

    #[test]
    fn automap_protocol_is_not_saved_if_indifferent_from_last_time() {
        let config_entry = Some(AutomapProtocol::Igdp);
        let automap_control =
            AutomapControlMock::default().get_mapping_protocol_result(Some(AutomapProtocol::Igdp));

        ActorSystemFactoryToolsReal::maybe_save_usual_protocol(
            &automap_control,
            &mut PersistentConfigurationMock::new(),
            config_entry,
        );

        //result for set_mapping_protocol not provided so it hasn't been required if no panic
    }

    #[test]
    fn automap_protocol_is_saved_if_both_values_populated_but_different() {
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .set_mapping_protocol_result(Ok(()));
        let config_entry = Some(AutomapProtocol::Pmp);
        let automap_control =
            AutomapControlMock::default().get_mapping_protocol_result(Some(AutomapProtocol::Igdp));

        ActorSystemFactoryToolsReal::maybe_save_usual_protocol(
            &automap_control,
            &mut persistent_config,
            config_entry,
        );

        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(*set_mapping_protocol_params, vec![Some(Igdp)])
    }

    #[test]
    #[should_panic(
        expected = "entered unreachable code: get_public_ip would've returned AllProtocolsFailed first"
    )]
    fn automap_usual_protocol_beginning_with_some_and_then_none_is_not_possible() {
        let config_entry = Some(AutomapProtocol::Pmp);
        let automap_control = AutomapControlMock::default().get_mapping_protocol_result(None);

        ActorSystemFactoryToolsReal::maybe_save_usual_protocol(
            &automap_control,
            &mut PersistentConfigurationMock::default(),
            config_entry,
        );
    }

    #[test]
    fn prepare_initial_messages_doesnt_start_up_proxy_client_or_automap_if_consume_only_mode() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            scan_intervals_opt: None,
            suppress_initial_scans: false,
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig { ui_port: 5335 },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet_opt: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor: NodeDescriptor::try_from((main_cryptde(), "masq://polygon-mainnet:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@172.50.48.6:9342")).unwrap(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![]),
                min_hops: MIN_HOPS_FOR_TEST,
            },
            payment_thresholds_opt: Default::default(),
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC
        };
        let system = System::new("MASQNode");
        let mut subject = make_subject_with_null_setter();
        subject.automap_control_factory = Box::new(AutomapControlFactoryMock::new());

        let _ = subject.prepare_initial_messages(
            make_cryptde_pair(),
            config.clone(),
            Box::new(PersistentConfigurationMock::new().set_min_hops_result(Ok(()))),
            Box::new(actor_factory),
        );

        System::current().stop();
        system.run();
        let messages = recordings.proxy_client.lock().unwrap();
        assert!(messages.is_empty());
        check_bind_message(&recordings.dispatcher, true);
        check_bind_message(&recordings.hopper, true);
        check_bind_message(&recordings.proxy_server, true);
        check_bind_message(&recordings.neighborhood, true);
        check_bind_message(&recordings.ui_gateway, true);
        check_bind_message(&recordings.accountant, true);
        check_start_message(&recordings.neighborhood, 1);
    }

    #[test]
    fn start_automap_aborts_if_neighborhood_mode_is_standard_and_public_ip_is_supplied() {
        let mut subject = ActorSystemFactoryToolsReal::new();
        let automap_control = Box::new(AutomapControlMock::new());
        subject.automap_control_factory =
            Box::new(AutomapControlFactoryMock::new().make_result(automap_control));
        let mut config = BootstrapperConfig::default();
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );
        let (recorder, _, _) = make_recorder();
        let new_ip_recipient = recorder.start().recipient();

        subject.start_automap(
            &config,
            Box::new(PersistentConfigurationMock::new()),
            vec![new_ip_recipient],
        );

        // no not-enough-results-provided error: test passes
    }

    #[test]
    #[should_panic(expected = "1: Automap failure: AllProtocolsFailed")]
    fn start_automap_change_handler_handles_remapping_errors_properly() {
        running_test();
        let mut subject = ActorSystemFactoryToolsReal::new();
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_configuration =
            PersistentConfigurationMock::new().set_mapping_protocol_result(Ok(()));
        let automap_control = Box::new(
            AutomapControlMock::new()
                .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
                .get_mapping_protocol_result(Some(AutomapProtocol::Pmp))
                .add_mapping_result(Ok(())),
        );
        subject.automap_control_factory = Box::new(
            AutomapControlFactoryMock::new()
                .make_params(&make_params_arc)
                .make_result(automap_control),
        );
        let mut config = BootstrapperConfig::default();
        config.mapping_protocol_opt = None;
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("0.0.0.0").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );

        subject.start_automap(&config, Box::new(persistent_configuration), vec![]);

        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(make_params[0].0, None);
        let system = System::new("test");
        let change_handler = &make_params[0].1;
        change_handler(AutomapChange::Error(AutomapError::AllProtocolsFailed(
            vec![],
        )));
        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(expected = "1: Automap failure: Can't get public IP - AllProtocolsFailed")]
    fn start_automap_change_handler_handles_get_public_ip_errors_properly() {
        running_test();
        let mut subject = ActorSystemFactoryToolsReal::new();
        let automap_control = Box::new(
            AutomapControlMock::new()
                .get_public_ip_result(Err(AutomapError::AllProtocolsFailed(vec![]))),
        );
        subject.automap_control_factory =
            Box::new(AutomapControlFactoryMock::new().make_result(automap_control));
        let mut config = BootstrapperConfig::default();
        config.mapping_protocol_opt = None;
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("0.0.0.0").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );

        subject.start_automap(
            &config,
            Box::new(PersistentConfigurationMock::new()),
            vec![],
        );

        let system = System::new("test");
        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(
        expected = "1: Automap failure: Can't map port 1234 through the router - AllProtocolsFailed"
    )]
    fn start_automap_change_handler_handles_initial_mapping_error_properly() {
        running_test();
        let mut subject = ActorSystemFactoryToolsReal::new();
        let persistent_config =
            PersistentConfigurationMock::new().set_mapping_protocol_result(Ok(()));
        let automap_control = Box::new(
            AutomapControlMock::new()
                .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
                .get_mapping_protocol_result(Some(AutomapProtocol::Pcp))
                .add_mapping_result(Err(AutomapError::AllProtocolsFailed(vec![]))),
        );
        subject.automap_control_factory =
            Box::new(AutomapControlFactoryMock::new().make_result(automap_control));
        let mut config = BootstrapperConfig::default();
        config.mapping_protocol_opt = None;
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("0.0.0.0").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );

        subject.start_automap(&config, Box::new(persistent_config), vec![]);

        let system = System::new("test");
        System::current().stop();
        system.run();
    }

    #[test]
    fn prepare_initial_messages_generates_no_consuming_wallet_balance_if_no_consuming_wallet_is_specified(
    ) {
        let actor_factory = ActorFactoryMock::new();
        let parameters = actor_factory.make_parameters();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            scan_intervals_opt: None,
            suppress_initial_scans: false,
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig { ui_port: 5335 },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            consuming_wallet_opt: None,
            earning_wallet: make_wallet("earning"),
            data_directory: PathBuf::new(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), &[]),
                    vec![],
                    rate_pack(100),
                ),
                min_hops: MIN_HOPS_FOR_TEST,
            },
            node_descriptor: Default::default(),
            payment_thresholds_opt: Default::default(),
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
        };
        let subject = make_subject_with_null_setter();
        let system = System::new("MASQNode");

        let _ = subject.prepare_initial_messages(
            make_cryptde_pair(),
            config.clone(),
            Box::new(PersistentConfigurationMock::new().set_min_hops_result(Ok(()))),
            Box::new(actor_factory),
        );

        System::current().stop();
        system.run();
        let (_, bootstrapper_config) = Parameters::get(parameters.proxy_server_params);
        assert_eq!(bootstrapper_config.consuming_wallet_opt, None);
    }

    #[test]
    fn proxy_server_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let mut bootstrapper_config = BootstrapperConfig::default();
            bootstrapper_config.crash_point = CrashPoint::Message;
            let subscribers = ActorFactoryReal::new()
                .make_and_start_proxy_server(make_cryptde_pair(), &bootstrapper_config);
            subscribers.node_from_ui
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), proxy_server::CRASH_KEY)
    }

    #[test]
    fn proxy_client_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let proxy_cl_config = ProxyClientConfig {
                cryptde: main_cryptde(),
                dns_servers: vec![SocketAddr::V4(
                    SocketAddrV4::from_str("1.1.1.1:45").unwrap(),
                )],
                exit_service_rate: 50,
                is_decentralized: true,
                crashable: true,
                exit_byte_rate: 50,
            };
            let subscribers = ActorFactoryReal::new().make_and_start_proxy_client(proxy_cl_config);
            subscribers.node_from_ui
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), proxy_client::CRASH_KEY)
    }

    #[test]
    fn hopper_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let hopper_config = HopperConfig {
                cryptdes: make_cryptde_pair(),
                per_routing_service: 100,
                per_routing_byte: 50,
                is_decentralized: false,
                crashable: true,
            };
            let subscribers = ActorFactoryReal::new().make_and_start_hopper(hopper_config);
            subscribers.node_from_ui
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), hopper::CRASH_KEY)
    }

    #[test]
    fn ui_gateway_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let mut bootstrapper_config = BootstrapperConfig::default();
            bootstrapper_config.crash_point = CrashPoint::Message;
            let subscribers =
                ActorFactoryReal::new().make_and_start_ui_gateway(&bootstrapper_config);
            subscribers.node_from_ui_message_sub
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), ui_gateway::CRASH_KEY)
    }

    #[test]
    fn stream_handler_pool_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let mut bootstrapper_config = BootstrapperConfig::default();
            bootstrapper_config.crash_point = CrashPoint::Message;
            let subscribers =
                ActorFactoryReal::new().make_and_start_stream_handler_pool(&bootstrapper_config);
            subscribers.node_from_ui_sub
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), stream_handler_pool::CRASH_KEY)
    }

    fn panic_in_arbiter_thread_versus_system<F>(actor_initialization: Box<F>, actor_crash_key: &str)
    where
        F: FnOnce() -> Recipient<NodeFromUiMessage>,
    {
        let system = System::new("test");
        let killer = SystemKillerActor::new(Duration::from_millis(1500));
        let mercy_signal_rx = killer.receiver();
        Arbiter::start(|_| killer);
        let ui_node_addr = actor_initialization();
        let crash_request = UiCrashRequest {
            actor: actor_crash_key.to_string(),
            panic_message: format!(
                "Testing a panic in the arbiter's thread for {}",
                actor_crash_key
            ),
        };
        let actor_message = NodeFromUiMessage {
            client_id: 1,
            body: crash_request.tmb(123),
        };
        ui_node_addr.try_send(actor_message).unwrap();
        system.run();
        assert!(
            mercy_signal_rx.try_recv().is_err(),
            "{} while panicking is unable to shut the system down",
            actor_crash_key
        )
    }

    fn check_bind_message(recording: &Arc<Mutex<Recording>>, consume_only_flag: bool) {
        let bind_message = Recording::get::<BindMessage>(recording, 0);
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.neighborhood),
            "NeighborhoodSubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.accountant),
            "AccountantSubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.ui_gateway),
            "UiGatewaySubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.blockchain_bridge),
            "BlockchainBridgeSubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.dispatcher),
            "DispatcherSubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.hopper),
            "HopperSubs"
        );

        assert_eq!(
            format!("{:?}", bind_message.peer_actors.proxy_server),
            "ProxyServerSubs"
        );

        if consume_only_flag {
            assert!(bind_message.peer_actors.proxy_client_opt.is_none())
        } else {
            assert_eq!(
                format!("{:?}", bind_message.peer_actors.proxy_client_opt.unwrap()),
                "ProxyClientSubs"
            )
        };
    }

    fn check_start_message(recording: &Arc<Mutex<Recording>>, idx: usize) {
        let _start_message = Recording::get::<StartMessage>(recording, idx);
    }

    fn check_new_ip_message(recording: &Arc<Mutex<Recording>>, new_ip: IpAddr, idx: usize) {
        let new_ip_message = Recording::get::<NewPublicIp>(recording, idx);
        assert_eq!(new_ip_message.new_ip, new_ip);
    }

    fn check_cryptde(candidate: &dyn CryptDE) {
        let plain_data = PlainData::new(&b"booga"[..]);
        let crypt_data = candidate
            .encode(&candidate.public_key(), &plain_data)
            .unwrap();
        let result = candidate.decode(&crypt_data).unwrap();
        assert_eq!(result, plain_data);
    }

    #[test]
    fn validate_database_chain_happy_path() {
        let chain = DEFAULT_CHAIN;
        let persistent_config = PersistentConfigurationMock::default()
            .chain_name_result(DEFAULT_CHAIN.rec().literal_identifier.to_string());

        let _ =
            ActorSystemFactoryToolsReal::new().validate_database_chain(&persistent_config, chain);
    }

    #[test]
    #[should_panic(
        expected = "Database with a wrong chain name detected; expected: eth-ropsten, was: eth-mainnet"
    )]
    fn make_and_start_actors_does_not_tolerate_differences_in_setup_chain_and_database_chain() {
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.blockchain_bridge_config.chain = TEST_DEFAULT_CHAIN;
        let persistent_config =
            PersistentConfigurationMock::default().chain_name_result("eth-mainnet".to_string());
        Bootstrapper::pub_initialize_cryptdes_for_testing(
            &Some(main_cryptde().clone()),
            &Some(alias_cryptde().clone()),
        );
        let subject = ActorSystemFactoryReal::new(Box::new(ActorSystemFactoryToolsReal::new()));

        let _ = subject.make_and_start_actors(
            bootstrapper_config,
            Box::new(ActorFactoryReal::new()),
            Box::new(persistent_config),
        );
    }

    #[test]
    fn accountant_is_constructed_with_upgraded_db_connection_recognizing_our_extra_sqlite_functions(
    ) {
        let act = |bootstrapper_config: BootstrapperConfig,
                   db_initializer: DbInitializerReal,
                   banned_cache_loader: BannedCacheLoaderMock,
                   address_leaker: SubsFactoryTestAddrLeaker<Accountant>| {
            ActorFactoryReal::new().make_and_start_accountant(
                bootstrapper_config,
                &db_initializer,
                &banned_cache_loader,
                &address_leaker,
            )
        };

        test_accountant_is_constructed_with_upgraded_db_connection_recognizing_our_extra_sqlite_functions(
            "actor_system_factory",
            "accountant_is_constructed_with_upgraded_db_connection_recognizing_our_extra_sqlite_functions",
            act,
        )
    }

    #[test]
    fn blockchain_bridge_is_constructed_with_correctly_functioning_connections() {
        let test_name = "blockchain_bridge_is_constructed_with_correctly_functioning_connections";
        let data_dir = ensure_node_home_directory_exists("actor_system_factory", test_name);
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0)
            .response(
                vec![LogObject {
                    removed: false,
                    log_index: Some("0x20".to_string()),
                    transaction_index: Some("0x30".to_string()),
                    transaction_hash: Some(
                        "0x2222222222222222222222222222222222222222222222222222222222222222"
                            .to_string(),
                    ),
                    block_hash: Some(
                        "0x1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    ),
                    block_number: Some("0x7D0".to_string()), // 2000 decimal
                    address: "0x3333333333333333333333333333333333333334".to_string(),
                    data: "0x000000000000000000000000000000000000000000000000000000003b5dc100"
                        .to_string(),
                    topics: vec![
                        "0xddf252ad1be2c89b69c2b0680000000000006561726e696e675f77616c6c6574"
                            .to_string(),
                        "0xddf252ad1be2c89b69c2b0690000000000006561726e696e675f77616c6c6574"
                            .to_string(),
                    ],
                }],
                1,
            )
            .start();
        let server_url = format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port);
        let _persistent_config = {
            let conn = DbInitializerReal::default()
                .initialize(&data_dir, DbInitializationConfig::test_default())
                .unwrap();
            PersistentConfigurationReal::from(conn)
        };
        let wallet = make_wallet("abc");
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config
            .blockchain_bridge_config
            .blockchain_service_url_opt = Some(server_url);
        bootstrapper_config.blockchain_bridge_config.chain = TEST_DEFAULT_CHAIN;
        bootstrapper_config.data_directory = data_dir.clone();
        let system = System::new(test_name);
        let (accountant, _, accountant_recording) = make_recorder();
        let accountant = accountant.system_stop_conditions(match_every_type_id!(ReceivedPayments));
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        let (tx, blockchain_bridge_addr_rx) = bounded(1);
        let address_leaker = SubsFactoryTestAddrLeaker { address_leaker: tx };

        ActorFactoryReal::new()
            .make_and_start_blockchain_bridge(&bootstrapper_config, &address_leaker);

        let blockchain_bridge_addr = blockchain_bridge_addr_rx.try_recv().unwrap();
        blockchain_bridge_addr
            .try_send(BindMessage {
                peer_actors: peer_actors,
            })
            .unwrap();
        blockchain_bridge_addr
            .try_send(RetrieveTransactions {
                recipient: wallet,
                response_skeleton_opt: None,
            })
            .unwrap();
        assert_eq!(system.run(), 0);
        let recording = accountant_recording.lock().unwrap();
        let received_payments_message = recording.get_record::<ReceivedPayments>(0);
        assert!(received_payments_message.scan_result.is_ok());
    }

    #[test]
    fn load_banned_cache_implements_panic_on_migration() {
        let data_dir = ensure_node_home_directory_exists(
            "actor_system_factory",
            "load_banned_cache_implements_panic_on_migration",
        );

        let act = |data_dir: &Path| {
            ActorFactoryReal::load_banned_cache(
                &DbInitializerReal::default(),
                &BannedCacheLoaderMock::default(),
                &data_dir,
            );
        };

        assert_on_initialization_with_panic_on_migration(&data_dir, &act);
    }

    fn pk_from_cryptde_null(cryptde: &dyn CryptDE) -> &PublicKey {
        let null_cryptde = <&CryptDENull>::from(cryptde);
        null_cryptde.public_key()
    }

    fn make_subject_with_null_setter() -> ActorSystemFactoryToolsReal {
        let mut subject = ActorSystemFactoryToolsReal::new();
        subject.log_recipient_setter = Box::new(LogRecipientSetterNull::new());
        subject
    }
}
