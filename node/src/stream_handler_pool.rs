// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::bootstrapper::PortConfiguration;
use crate::discriminator::DiscriminatorFactory;
use crate::json_masquerader::JsonMasquerader;
use crate::masquerader::Masquerader;
use crate::stream_messages::*;
use crate::stream_reader::StreamReaderReal;
use crate::stream_writer_sorted::StreamWriterSorted;
use crate::stream_writer_unsorted::StreamWriterUnsorted;
use crate::sub_lib::channel_wrappers::FuturesChannelFactory;
use crate::sub_lib::channel_wrappers::FuturesChannelFactoryReal;
use crate::sub_lib::channel_wrappers::SenderWrapper;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher;
use crate::sub_lib::dispatcher::Endpoint;
use crate::sub_lib::dispatcher::{DispatcherSubs, StreamShutdownMsg};
use crate::sub_lib::neighborhood::NodeQueryResponseMetadata;
use crate::sub_lib::neighborhood::RemoveNeighborMessage;
use crate::sub_lib::neighborhood::{
    ConnectionProgressEvent, ConnectionProgressMessage, NodeQueryMessage,
};
use crate::sub_lib::neighborhood::{DispatcherNodeQueryMessage, ZERO_RATE_PACK};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_connector::ConnectionInfo;
use crate::sub_lib::stream_connector::StreamConnector;
use crate::sub_lib::stream_connector::StreamConnectorReal;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use crate::sub_lib::utils::{handle_ui_crash_request, MessageScheduler, NODE_MAILBOX_CAPACITY};
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::{Actor, AsyncContext};
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::localhost;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::prelude::Future;

// IMPORTANT: Nothing at or below the level of StreamHandlerPool should know about StreamKeys.
// StreamKeys should exist solely between ProxyServer and ProxyClient. Many of the streams
// overseen by StreamHandlerPool will not (and should not) have StreamKeys. Don't let the
// concept leak down this far.

pub const CRASH_KEY: &str = "STREAMHANDLERPOOL";

#[derive(PartialEq, Eq)]
pub struct StreamHandlerPoolSubs {
    pub add_sub: Recipient<AddStreamMsg>,
    pub transmit_sub: Recipient<TransmitDataMsg>,
    pub remove_sub: Recipient<RemoveStreamMsg>,
    pub bind: Recipient<PoolBindMessage>,
    pub node_query_response: Recipient<DispatcherNodeQueryResponse>,
    pub node_from_ui_sub: Recipient<NodeFromUiMessage>,
    pub scheduled_node_query_response_sub: Recipient<MessageScheduler<DispatcherNodeQueryResponse>>,
}

impl Clone for StreamHandlerPoolSubs {
    fn clone(&self) -> Self {
        StreamHandlerPoolSubs {
            add_sub: self.add_sub.clone(),
            transmit_sub: self.transmit_sub.clone(),
            remove_sub: self.remove_sub.clone(),
            bind: self.bind.clone(),
            node_query_response: self.node_query_response.clone(),
            node_from_ui_sub: self.node_from_ui_sub.clone(),
            scheduled_node_query_response_sub: self.scheduled_node_query_response_sub.clone(),
        }
    }
}

#[derive(Hash, PartialEq, Eq, Copy, Clone, Debug)]
struct StreamWriterKey {
    socket_addr: SocketAddr,
}

impl From<SocketAddr> for StreamWriterKey {
    fn from(socket_addr: SocketAddr) -> Self {
        if socket_addr.ip().is_loopback() {
            StreamWriterKey { socket_addr }
        } else {
            StreamWriterKey {
                socket_addr: SocketAddr::new(socket_addr.ip(), 0),
            }
        }
    }
}

impl Display for StreamWriterKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        if self.socket_addr.ip().is_loopback() {
            write!(f, "localhost:{}", self.socket_addr.port())
        } else {
            write!(f, "{}:*", self.socket_addr.ip())
        }
    }
}

// TODO: To avoid confusion with ProxyClient's StreamHandlerPool, rename this one or the other for easy identification.
// It is used to store streams for both neighbors and browser.
pub struct StreamHandlerPool {
    stream_writers: HashMap<StreamWriterKey, Option<Box<dyn SenderWrapper<SequencedPacket>>>>,
    dispatcher_subs_opt: Option<DispatcherSubs>,
    self_subs_opt: Option<StreamHandlerPoolSubs>,
    ask_neighborhood_opt: Option<Recipient<DispatcherNodeQueryMessage>>,
    remove_neighbor_sub_opt: Option<Recipient<RemoveNeighborMessage>>,
    connection_progress_sub_opt: Option<Recipient<ConnectionProgressMessage>>,
    logger: Logger,
    crashable: bool,
    stream_connector: Box<dyn StreamConnector>,
    channel_factory: Box<dyn FuturesChannelFactory<SequencedPacket>>,
    clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    traffic_analyzer: Box<dyn TrafficAnalyzer>,
}

impl Actor for StreamHandlerPool {
    type Context = Context<Self>;
}

impl Handler<AddStreamMsg> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: AddStreamMsg, _ctx: &mut Self::Context) {
        self.handle_add_stream_msg(msg)
    }
}

impl Handler<RemoveStreamMsg> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: RemoveStreamMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_remove_stream_msg(msg)
    }
}

impl Handler<TransmitDataMsg> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut <Self as Actor>::Context) {
        self.handle_transmit_data_msg(msg)
    }
}

impl Handler<DispatcherNodeQueryResponse> for StreamHandlerPool {
    type Result = ();
    fn handle(&mut self, msg: DispatcherNodeQueryResponse, _ctx: &mut Self::Context) {
        self.handle_dispatcher_node_query_response(msg)
    }
}

// TODO: GH-686 - This handler can be implemented using a Procedural Macro
impl<M: actix::Message + 'static> Handler<MessageScheduler<M>> for StreamHandlerPool
where
    StreamHandlerPool: Handler<M>,
{
    type Result = ();

    fn handle(&mut self, msg: MessageScheduler<M>, ctx: &mut Self::Context) -> Self::Result {
        ctx.notify_later(msg.scheduled_msg, msg.delay);
    }
}

impl Handler<PoolBindMessage> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: PoolBindMessage, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.dispatcher_subs_opt = Some(msg.dispatcher_subs);
        self.self_subs_opt = Some(msg.stream_handler_pool_subs);
        self.ask_neighborhood_opt = Some(msg.neighborhood_subs.dispatcher_node_query);
        self.remove_neighbor_sub_opt = Some(msg.neighborhood_subs.remove_neighbor);
        self.connection_progress_sub_opt = Some(msg.neighborhood_subs.connection_progress_sub);
    }
}

impl Handler<NodeFromUiMessage> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
    }
}

impl StreamHandlerPool {
    pub fn new(
        clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
        crashable: bool,
    ) -> StreamHandlerPool {
        StreamHandlerPool {
            stream_writers: HashMap::new(),
            dispatcher_subs_opt: None,
            self_subs_opt: None,
            ask_neighborhood_opt: None,
            remove_neighbor_sub_opt: None,
            connection_progress_sub_opt: None,
            logger: Logger::new("Dispatcher"),
            crashable,
            stream_connector: Box::new(StreamConnectorReal {}),
            channel_factory: Box::new(FuturesChannelFactoryReal {}),
            clandestine_discriminator_factories,
            traffic_analyzer: Box::new(TrafficAnalyzerReal {}),
        }
    }

    pub fn make_subs_from(pool_addr: &Addr<StreamHandlerPool>) -> StreamHandlerPoolSubs {
        StreamHandlerPoolSubs {
            add_sub: recipient!(pool_addr, AddStreamMsg),
            transmit_sub: recipient!(pool_addr, TransmitDataMsg),
            remove_sub: recipient!(pool_addr, RemoveStreamMsg),
            bind: recipient!(pool_addr, PoolBindMessage),
            node_query_response: recipient!(pool_addr, DispatcherNodeQueryResponse),
            node_from_ui_sub: recipient!(pool_addr, NodeFromUiMessage),
            scheduled_node_query_response_sub: recipient!(
                pool_addr,
                MessageScheduler<DispatcherNodeQueryResponse>
            ),
        }
    }

    fn set_up_stream_reader(
        &mut self,
        read_stream: Box<dyn ReadHalfWrapper>,
        origin_port: Option<u16>,
        port_configuration: PortConfiguration,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) {
        let ibcd_sub: Recipient<dispatcher::InboundClientData> = self
            .dispatcher_subs_opt
            .as_ref()
            .expect("Dispatcher is unbound")
            .ibcd_sub
            .clone();
        let remove_sub: Recipient<RemoveStreamMsg> = self
            .self_subs_opt
            .as_ref()
            .expect("StreamHandlerPool is unbound")
            .remove_sub
            .clone();
        let dispatcher_shutdown_sub: Recipient<StreamShutdownMsg> = self
            .dispatcher_subs_opt
            .as_ref()
            .expect("Dispatcher is unbound")
            .stream_shutdown_sub
            .clone();
        let stream_reader = StreamReaderReal::new(
            read_stream,
            origin_port,
            ibcd_sub,
            remove_sub,
            dispatcher_shutdown_sub,
            port_configuration.discriminator_factories.clone(),
            port_configuration.is_clandestine,
            peer_addr,
            local_addr,
        );
        debug!(
            self.logger,
            "Setting up {}clandestine StreamReader with reception_port {:?} on {} to listen to {}",
            if port_configuration.is_clandestine {
                ""
            } else {
                "non-"
            },
            origin_port,
            local_addr,
            peer_addr
        );
        tokio::spawn(stream_reader);
    }

    fn set_up_stream_writer(
        &mut self,
        write_stream: Box<dyn WriteHalfWrapper>,
        peer_addr: SocketAddr,
        is_clandestine: bool,
    ) {
        let (tx, rx) = self.channel_factory.make(peer_addr);
        self.stream_writers
            .insert(StreamWriterKey::from(peer_addr), Some(tx));

        if is_clandestine {
            tokio::spawn(StreamWriterUnsorted::new(write_stream, peer_addr, rx));
        } else {
            tokio::spawn(StreamWriterSorted::new(write_stream, peer_addr, rx));
        };
    }

    fn handle_transmit_data_msg(&mut self, msg: TransmitDataMsg) {
        debug!(
            self.logger,
            "Handling order to transmit {} bytes to {:?}",
            msg.data.len(),
            msg.endpoint
        );
        let node_query_response_recipient = self
            .self_subs_opt
            .as_ref()
            .expect("StreamHandlerPool is unbound.")
            .node_query_response
            .clone();
        match msg.endpoint.clone() {
            Endpoint::Key(key) => {
                // It is used to query PublicKey inside Neighborhood
                let request = DispatcherNodeQueryMessage {
                    query: NodeQueryMessage::PublicKey(key.clone()),
                    context: msg,
                    recipient: node_query_response_recipient,
                };
                debug!(
                    self.logger,
                    "Sending node query about {} to Neighborhood", key
                );
                self.ask_neighborhood_opt
                    .as_ref()
                    .expect("StreamHandlerPool is unbound.")
                    .try_send(request)
                    .expect("Neighborhood is Dead")
            }
            Endpoint::Socket(socket_addr) => {
                // The socket_addr can either be for the Neighbor or the browser
                debug!(
                    self.logger,
                    "Translating TransmitDataMsg to node query response about {}", socket_addr
                );
                node_query_response_recipient
                    .try_send(DispatcherNodeQueryResponse {
                        result: Some(NodeQueryResponseMetadata::new(
                            PublicKey::new(&[]),
                            Some(NodeAddr::from(&socket_addr)),
                            ZERO_RATE_PACK,
                        )),
                        context: msg,
                    })
                    .expect("StreamHandlerPool is dead?")
            }
        };
    }

    fn handle_add_stream_msg(
        &mut self,
        msg: AddStreamMsg,
    ) -> <Self as Handler<AddStreamMsg>>::Result {
        let port_config = msg.port_configuration.clone();
        self.set_up_stream_writer(
            msg.connection_info.writer,
            msg.connection_info.peer_addr,
            port_config.is_clandestine,
        );
        self.set_up_stream_reader(
            msg.connection_info.reader,
            msg.origin_port,
            msg.port_configuration,
            msg.connection_info.peer_addr,
            msg.connection_info.local_addr,
        );
    }

    fn handle_remove_stream_msg(&mut self, msg: RemoveStreamMsg) {
        let stream_writer_key = StreamWriterKey::from(msg.peer_addr);
        debug!(
            self.logger,
            "Stream from local {} to peer {} has closed; removing writer with key {}",
            msg.local_addr,
            msg.peer_addr,
            stream_writer_key
        );
        let report_to_counterpart = match self.stream_writers.remove(&stream_writer_key) {
            None => {
                trace!(
                    self.logger,
                    "While handling RemoveStreamMsg: Stream Writers did not contain any entry for key {}",
                    stream_writer_key
                );
                false
            }
            Some(None) => {
                error!(
                    self.logger,
                    "An unpopulated entry in stream_writers was found for a {:?} stream ({:?}) from \
                    a client. This shouldn't be possible. Investigate!",
                    msg.stream_type, stream_writer_key
                );
                false
            }
            Some(Some(_sender_wrapper)) => {
                trace!(
                    self.logger,
                    "While handling RemoveStreamMsg: Stream Writers contained an entry for key {}, also found stream writer; removing",
                    stream_writer_key
                );
                true
            }
        };
        let stream_shutdown_msg = StreamShutdownMsg {
            peer_addr: msg.peer_addr,
            stream_type: msg.stream_type,
            report_to_counterpart,
        };
        debug!(
            self.logger,
            "Signaling StreamShutdownMsg to Dispatcher for stream from {} with stream type {:?}, {}report to counterpart",
            stream_shutdown_msg.peer_addr,
            stream_shutdown_msg.stream_type,
            if stream_shutdown_msg.report_to_counterpart {""} else {"don't "}
        );
        msg.dispatcher_sub
            .try_send(stream_shutdown_msg)
            .expect("StreamShutdownMsg target is dead");
    }

    fn handle_dispatcher_node_query_response(&mut self, msg: DispatcherNodeQueryResponse) {
        // TODO Can be recombined with TransmitDataMsg after SC-358/GH-96
        debug!(
            self.logger,
            "Handling node query response containing {:?}", msg.result
        );
        let node_addr = match self.extract_node_addr(&msg) {
            Ok(node_addr) => node_addr,
            Err(e) => {
                error!(self.logger, "{e}");
                return;
            }
        };

        if node_addr.ports().is_empty() {
            // If the NodeAddr has no ports, then either
            // we are a 0-hop-only node or
            // something has gone terribly wrong with the Neighborhood's state,
            // so we should blow up.
            panic!("Neighborhood has returned a NodeDescriptor with no ports. This indicates an unrecoverable error.")
        }

        // TODO: Picking the first port is a temporary hack. This problem should go away with clandestine ports.
        let peer_addr = SocketAddr::new(node_addr.ip_addr(), node_addr.ports()[0]);

        let sw_key = StreamWriterKey::from(peer_addr);

        if let Err(e) = self.send_or_queue_packet(msg, peer_addr, sw_key) {
            error!(self.logger, "{e}");
        };
    }

    fn extract_node_addr(&self, msg: &DispatcherNodeQueryResponse) -> Result<NodeAddr, String> {
        match msg.result.clone() {
            Some(metadata) => match metadata.node_addr_opt {
                Some(node_addr) => Ok(node_addr),
                None => Err(format!(
                    "No known IP for neighbor in route with key: {}",
                    metadata.public_key
                )),
            },
            None => Err(format!(
                "No Node found at endpoint {:?}",
                msg.context.endpoint
            )),
        }
    }

    fn send_or_queue_packet(
        &mut self,
        msg: DispatcherNodeQueryResponse,
        peer_addr: SocketAddr,
        sw_key: StreamWriterKey,
    ) -> Result<(), String> {
        let tx_box_opt_opt = self.stream_writers.get(&sw_key);
        match tx_box_opt_opt {
            Some(Some(tx_box)) => {
                let remove_stream_writer =
                    self.send_packet_on_open_stream(msg, peer_addr, sw_key, tx_box.as_ref())?;
                if remove_stream_writer {
                    self.stream_writers
                        .remove(&StreamWriterKey::from(peer_addr));
                }
            }
            Some(None) => self.delay_packet_for_opening_stream(msg, peer_addr, sw_key),
            None => {
                if peer_addr.ip() == localhost() {
                    return Err(format!(
                        "Local connection {:?} not found. Discarding {} bytes.",
                        peer_addr,
                        msg.context.data.len()
                    ));
                };

                self.stream_writers
                    .insert(StreamWriterKey::from(peer_addr), None);

                self.open_new_stream_and_recycle_message(msg, peer_addr, sw_key);
            }
        }

        Ok(())
    }

    fn send_packet_on_open_stream(
        &self,
        msg: DispatcherNodeQueryResponse,
        peer_addr: SocketAddr,
        sw_key: StreamWriterKey,
        tx_box: &dyn SenderWrapper<SequencedPacket>,
    ) -> Result<bool, String> {
        debug!(
            self.logger,
            "Found already-open stream to {} keyed by {}: using",
            tx_box.peer_addr(),
            sw_key
        );
        debug!(self.logger, "Masking {} bytes", msg.context.data.len());
        let packet = if msg.context.sequence_number.is_none() {
            let masquerader = self.traffic_analyzer.get_masquerader();
            match masquerader.mask(msg.context.data.as_slice()) {
                Ok(masked_data) => SequencedPacket::new(masked_data, 0, false),
                Err(e) => {
                    return Err(format!(
                        "Masking failed for {}: {}. Discarding {} bytes.",
                        peer_addr,
                        e,
                        msg.context.data.len()
                    ));
                }
            }
        } else {
            SequencedPacket::from(&msg.context)
        };

        let packet_len = packet.data.len();
        match tx_box.unbounded_send(packet) {
            Err(e) => {
                error!(
                    self.logger,
                    "Removing channel to disabled StreamWriter {} to {}: {}", sw_key, peer_addr, e
                );
                // TODO GH-667 It looks like what we should do here is inform our caller somehow
                // that we can no longer communicate with the Node specified in the route, and
                // signal that somebody (the Dispatcher?) should remove this neighbor, make another
                // route, and try again.
                return Ok(true);
            }
            Ok(_) => {
                debug!(self.logger, "Queued {} bytes for transmission", packet_len);
            }
        };
        if msg.context.last_data {
            debug!(
                self.logger,
                "Removing channel to StreamWriter {} to {} in response to server-drop report",
                sw_key,
                peer_addr
            );
            return Ok(true);
        }
        Ok(false)
    }

    fn delay_packet_for_opening_stream(
        &self,
        msg: DispatcherNodeQueryResponse,
        peer_addr: SocketAddr,
        sw_key: StreamWriterKey,
    ) {
        debug!(
            self.logger,
            "Found in-the-process-of-being-opened stream to {} keyed by {}: preparing to use",
            peer_addr,
            sw_key
        );
        // a connection is already in progress. resubmit this message, to give the connection time to complete
        info!(
            self.logger,
            "connection for {} in progress, resubmitting {} bytes",
            peer_addr,
            msg.context.data.len()
        );
        let scheduled_node_query_response_sub = self
            .self_subs_opt
            .as_ref()
            .expect("StreamHandlerPool is unbound")
            .scheduled_node_query_response_sub
            .clone();

        scheduled_node_query_response_sub
            .try_send(MessageScheduler {
                scheduled_msg: msg,
                delay: Duration::from_millis(100),
            })
            .expect("StreamHandlerPool is dead");
    }

    fn open_new_stream_and_recycle_message(
        &self,
        msg: DispatcherNodeQueryResponse,
        peer_addr: SocketAddr,
        sw_key: StreamWriterKey,
    ) {
        debug!(
            self.logger,
            "No existing stream keyed by {}: creating one to {}", sw_key, peer_addr
        );
        let failure_handler = StreamStartFailureHandler::new(self, &msg, peer_addr);
        let success_handler = StreamStartSuccessHandler::new(self, msg, peer_addr);

        let connect_future = self
            .stream_connector
            .connect(peer_addr, &self.logger)
            .map(move |connection_info| success_handler.handle(connection_info))
            .map_err(move |err| {
                // connection was unsuccessful
                failure_handler.handle(err)
            });

        debug!(self.logger, "Beginning connection attempt to {}", peer_addr);
        tokio::spawn(connect_future);
    }
}

struct StreamStartFailureHandler {
    pub msg_data_len: usize,
    pub key: PublicKey,
    pub remove_sub: Recipient<RemoveStreamMsg>,
    pub connection_progress_sub: Recipient<ConnectionProgressMessage>,
    pub remove_neighbor_sub: Recipient<RemoveNeighborMessage>,
    pub logger: Logger,
    pub peer_addr: SocketAddr,
    pub dispatcher_sub: Recipient<StreamShutdownMsg>,
}

impl StreamStartFailureHandler {
    pub fn new(
        pool: &StreamHandlerPool,
        msg: &DispatcherNodeQueryResponse,
        peer_addr: SocketAddr,
    ) -> Self {
        let subs = pool
            .self_subs_opt
            .clone()
            .expect("StreamHandlerPool Unbound");
        Self {
            msg_data_len: msg.context.data.len(),
            key: msg
                .result
                .clone()
                .map(|d| d.public_key)
                .expect("Key magically disappeared"),
            remove_sub: subs.remove_sub,
            connection_progress_sub: pool
                .connection_progress_sub_opt
                .clone()
                .expect("Neighborhood Unbound"),
            remove_neighbor_sub: pool
                .remove_neighbor_sub_opt
                .clone()
                .expect("Neighborhood Unbound"),
            logger: pool.logger.clone(),
            peer_addr,
            dispatcher_sub: pool
                .dispatcher_subs_opt
                .as_ref()
                .expect("Dispatcher is dead")
                .stream_shutdown_sub
                .clone(),
        }
    }

    pub fn handle(self, err: io::Error) {
        error!(
            self.logger,
            "Stream to {} does not exist and could not be connected; discarding {} bytes: {}",
            self.peer_addr,
            self.msg_data_len,
            err
        );
        self.remove_sub
            .try_send(RemoveStreamMsg {
                peer_addr: self.peer_addr,
                local_addr: SocketAddr::new(localhost(), 0), // irrelevant; stream was never opened
                stream_type: RemovedStreamType::Clandestine,
                dispatcher_sub: self.dispatcher_sub,
            })
            .expect("StreamHandlerPool is dead");
        let remove_node_message = RemoveNeighborMessage {
            public_key: self.key.clone(),
        };
        self.remove_neighbor_sub
            .try_send(remove_node_message)
            .expect("Neighborhood is Dead");
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: self.peer_addr.ip(),
            event: ConnectionProgressEvent::TcpConnectionFailed,
        };
        self.connection_progress_sub
            .try_send(connection_progress_message)
            .expect("Neighborhood is dead");
    }
}

struct StreamStartSuccessHandler {
    pub msg: DispatcherNodeQueryResponse,
    pub add_stream_sub: Recipient<AddStreamMsg>,
    pub node_query_response_sub: Recipient<DispatcherNodeQueryResponse>,
    pub connection_progress_sub_ok: Recipient<ConnectionProgressMessage>,
    pub logger: Logger,
    pub clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    pub peer_addr: SocketAddr,
}

impl StreamStartSuccessHandler {
    pub fn new(
        pool: &StreamHandlerPool,
        msg: DispatcherNodeQueryResponse,
        peer_addr: SocketAddr,
    ) -> Self {
        let subs = pool
            .self_subs_opt
            .clone()
            .expect("StreamHandlerPool Unbound");
        Self {
            msg,
            add_stream_sub: subs.add_sub,
            node_query_response_sub: subs.node_query_response,
            connection_progress_sub_ok: pool
                .connection_progress_sub_opt
                .clone()
                .expect("Neighborhood Unbound"),
            logger: pool.logger.clone(),
            clandestine_discriminator_factories: pool.clandestine_discriminator_factories.clone(),
            peer_addr,
        }
    }

    pub fn handle(self, connection_info: ConnectionInfo) {
        debug!(
            self.logger,
            "Connection attempt to {} succeeded", self.peer_addr
        );
        let origin_port = connection_info.local_addr.port();
        self.add_stream_sub
            .try_send(AddStreamMsg {
                connection_info,
                origin_port: Some(origin_port),
                port_configuration: PortConfiguration::new(
                    self.clandestine_discriminator_factories,
                    true,
                ),
            })
            .expect("StreamHandlerPool is dead");
        self.node_query_response_sub
            .try_send(self.msg)
            .expect("StreamHandlerPool is dead");
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: self.peer_addr.ip(),
            event: ConnectionProgressEvent::TcpConnectionSuccessful,
        };
        self.connection_progress_sub_ok
            .try_send(connection_progress_message)
            .expect("Neighborhood is dead");
    }
}

trait TrafficAnalyzer {
    fn get_masquerader(&self) -> Box<dyn Masquerader>;
}

struct TrafficAnalyzerReal {}

impl TrafficAnalyzer for TrafficAnalyzerReal {
    fn get_masquerader(&self) -> Box<dyn Masquerader> {
        Box::new(JsonMasquerader::new())
    }
}

impl TrafficAnalyzerReal {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
    use crate::json_discriminator_factory::JsonDiscriminatorFactory;
    use crate::json_masquerader::JsonMasquerader;
    use crate::masquerader::Masquerader;
    use crate::node_test_utils::{check_timestamp, FailingMasquerader};
    use crate::sub_lib::dispatcher::InboundClientData;
    use crate::sub_lib::neighborhood::{
        ConnectionProgressEvent, ConnectionProgressMessage, NodeQueryResponseMetadata,
    };
    use crate::sub_lib::stream_connector::ConnectionInfo;
    use crate::test_utils::channel_wrapper_mocks::SenderWrapperMock;
    use crate::test_utils::main_cryptde;
    use crate::test_utils::rate_pack;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::stream_connector_mock::StreamConnectorMock;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use crate::test_utils::unshared_test_utils::prove_that_crash_request_handler_is_hooked_up;
    use crate::test_utils::{await_messages, make_send_error};
    use actix::Actor;
    use actix::Addr;
    use actix::System;
    use crossbeam_channel::unbounded;
    use masq_lib::constants::HTTP_PORT;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::utils::find_free_port;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::SystemTime;
    use tokio::prelude::Async;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "STREAMHANDLERPOOL");
    }

    struct TrafficAnalyzerMock {}

    impl TrafficAnalyzer for TrafficAnalyzerMock {
        fn get_masquerader(&self) -> Box<dyn Masquerader> {
            Box::new(FailingMasquerader {})
        }
    }

    #[test]
    fn a_newly_added_stream_produces_stream_handler_that_sends_received_data_to_dispatcher() {
        let dispatcher = Recorder::new();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let peer_addr = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let peer_addr_a = peer_addr.clone();
        let local_addr = SocketAddr::from_str("1.2.3.5:80").unwrap();
        let reception_port = Some(8081);
        let is_clandestine = false;
        let one_http_req = b"GET http://here.com HTTP/1.1\r\n\r\n".to_vec();
        let one_http_req_a = one_http_req.clone();
        let another_http_req = b"DELETE http://there.com HTTP/1.1\r\n\r\n".to_vec();
        let another_http_req_a = another_http_req.clone();
        let a_third_http_req = b"HEAD http://everywhere.com HTTP/1.1\r\n\r\n".to_vec();
        let a_third_http_req_a = a_third_http_req.clone();
        let mut second_chunk = Vec::new();
        second_chunk.extend(another_http_req.clone());
        second_chunk.extend(Vec::from("glorp".as_bytes()));
        second_chunk.extend(a_third_http_req.clone());
        let awaiter = dispatcher.get_awaiter();
        let before = SystemTime::now();

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec![], false);
            subject.stream_connector = Box::new(StreamConnectorMock::new());
            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().dispatcher(dispatcher).build();

            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new(
                    ReadHalfWrapperMock::new()
                        .poll_read_ok(one_http_req.clone())
                        .poll_read_ok(second_chunk.clone())
                        .poll_read_result(vec![], Err(Error::from(ErrorKind::BrokenPipe))),
                ),
                writer: Box::new(
                    WriteHalfWrapperMock::new()
                        .poll_write_result(Ok(Async::Ready(one_http_req.len())))
                        .poll_write_result(Ok(Async::Ready(second_chunk.len()))),
                ),
                local_addr,
                peer_addr,
            };

            subject_subs
                .add_sub
                .try_send(AddStreamMsg::new(
                    connection_info, // the stream splitter mock will return mocked reader/writer
                    reception_port,
                    PortConfiguration::new(
                        vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                        is_clandestine,
                    ),
                ))
                .unwrap();

            system.run();
        });

        awaiter.await_message_count(4);
        let after = SystemTime::now();
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let dispatcher_record = dispatcher_recording.get_record::<dispatcher::InboundClientData>(0);
        check_timestamp(before, dispatcher_record.timestamp, after);
        assert_eq!(
            dispatcher_record,
            &dispatcher::InboundClientData {
                timestamp: dispatcher_record.timestamp,
                peer_addr: peer_addr_a,
                reception_port,
                last_data: false,
                is_clandestine,
                sequence_number: Some(0),
                data: one_http_req_a,
            }
        );
        let dispatcher_record = dispatcher_recording.get_record::<dispatcher::InboundClientData>(1);
        check_timestamp(before, dispatcher_record.timestamp, after);
        assert_eq!(
            dispatcher_record,
            &dispatcher::InboundClientData {
                timestamp: dispatcher_record.timestamp,
                peer_addr: peer_addr_a,
                reception_port,
                last_data: false,
                is_clandestine,
                sequence_number: Some(1),
                data: another_http_req_a,
            }
        );
        let dispatcher_record = dispatcher_recording.get_record::<dispatcher::InboundClientData>(2);
        check_timestamp(before, dispatcher_record.timestamp, after);
        assert_eq!(
            dispatcher_record,
            &dispatcher::InboundClientData {
                timestamp: dispatcher_record.timestamp,
                peer_addr: peer_addr_a,
                reception_port,
                last_data: false,
                is_clandestine,
                sequence_number: Some(2),
                data: a_third_http_req_a,
            }
        );
        let dispatcher_record = dispatcher_recording.get_record::<dispatcher::StreamShutdownMsg>(3);
        assert_eq!(
            dispatcher_record,
            &dispatcher::StreamShutdownMsg {
                peer_addr: peer_addr_a,
                stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                    reception_port: reception_port.unwrap(),
                    sequence_number: 3
                }),
                report_to_counterpart: true,
            }
        );
        assert_eq!(dispatcher_recording.len(), 4);
    }

    #[test]
    fn stream_handler_pool_writes_data_to_stream_writer() {
        init_test_logging();
        let reader = ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::NotReady));
        let write_stream_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(Error::from(ErrorKind::Other)))
            .poll_write_result(Ok(Async::Ready(5)))
            .poll_write_result(Ok(Async::NotReady))
            .poll_write_params(&write_stream_params_arc);
        let local_addr = SocketAddr::from_str("1.2.3.4:6789").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();

        thread::spawn(move || {
            let system = System::new("test");
            let subject = StreamHandlerPool::new(vec![], false);

            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new(reader),
                writer: Box::new(writer),
                local_addr,
                peer_addr,
            };

            subject_subs
                .add_sub
                .try_send(AddStreamMsg::new(
                    connection_info,
                    None,
                    PortConfiguration::new(
                        vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                        true,
                    ),
                ))
                .unwrap();

            subject_subs
                .transmit_sub
                .try_send(TransmitDataMsg {
                    endpoint: Endpoint::Socket(peer_addr),
                    last_data: true,
                    sequence_number: Some(0),
                    data: b"hello".to_vec(),
                })
                .unwrap();

            system.run();
        });

        TestLogHandler::new().await_log_containing(
            "WARN: StreamWriter for 1.2.3.5:6789: Continuing after write error: other error",
            1000,
        );

        let mut sw_to_stream_params = write_stream_params_arc.lock().unwrap();
        assert_eq!(sw_to_stream_params.len(), 2);
        assert_eq!(sw_to_stream_params.remove(0), b"hello".to_vec());
    }

    #[test]
    fn terminal_packet_is_transmitted_and_then_stream_is_shut_down() {
        init_test_logging();
        let (sub_tx, sub_rx) = unbounded();

        thread::spawn(move || {
            let system = System::new("test");

            let mut subject = StreamHandlerPool::new(vec![], false);
            subject.stream_connector = Box::new(
                StreamConnectorMock::new()
                    .connect_pair_result(Err(Error::from(ErrorKind::ConnectionRefused))),
            );
            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            sub_tx.send(subject_subs).unwrap();
            system.run();
        });

        let subject_subs = sub_rx.recv().unwrap();

        let reader = ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::NotReady));
        let poll_write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(2)))
            .poll_write_result(Ok(Async::NotReady))
            .poll_write_params(&poll_write_params_arc)
            .shutdown_ok();
        let local_addr = SocketAddr::from_str("1.2.3.4:5673").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.4.5:5673").unwrap();
        let connection_info = ConnectionInfo {
            reader: Box::new(reader),
            writer: Box::new(writer),
            local_addr,
            peer_addr,
        };

        subject_subs
            .add_sub
            .try_send(AddStreamMsg::new(
                connection_info,
                None,
                PortConfiguration::new(
                    vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                    false,
                ),
            ))
            .unwrap();

        subject_subs
            .transmit_sub
            .try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(peer_addr),
                last_data: true,
                sequence_number: Some(0),
                data: vec![0x12, 0x34],
            })
            .unwrap();

        let tlh = TestLogHandler::new();
        tlh.await_log_containing(
            "Removing channel to StreamWriter 1.2.4.5:* to 1.2.4.5:5673 in response to server-drop report",
            1000,
        );

        await_messages(1, &poll_write_params_arc);
        let poll_write_params = poll_write_params_arc
            .lock()
            .expect("is this really the poison error? NO!");
        assert_eq!(poll_write_params.len(), 1);
        assert_eq!(*poll_write_params, vec![vec![0x12, 0x34]]);

        subject_subs
            .transmit_sub
            .try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(peer_addr),
                last_data: true,
                sequence_number: Some(0),
                data: vec![0x56, 0x78],
            })
            .unwrap();

        tlh.await_log_containing(
            "No existing stream keyed by 1.2.4.5:*: creating one to 1.2.4.5:5673",
            1000,
        );
    }

    #[test]
    fn stream_handler_pool_removes_stream_when_it_gets_the_remove_stream_msg() {
        init_test_logging();
        let reader = ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::NotReady));
        let write_stream_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(2)))
            .poll_write_params(&write_stream_params_arc);
        let local_addr = SocketAddr::from_str("1.2.3.4:5673").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:5673").unwrap();

        thread::spawn(move || {
            let system = System::new("test");

            let mut subject =
                StreamHandlerPool::new(vec![Box::new(JsonDiscriminatorFactory {})], false);
            subject.stream_connector = Box::new(StreamConnectorMock::new().connection(
                local_addr,
                peer_addr,
                vec![(vec![], Ok(Async::NotReady))],
                vec![Ok(Async::Ready(2))],
            ));
            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher.clone(),
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new(reader),
                writer: Box::new(writer),
                local_addr,
                peer_addr,
            };

            subject_subs
                .add_sub
                .try_send(AddStreamMsg::new(
                    connection_info,
                    None,
                    PortConfiguration::new(
                        vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                        true,
                    ),
                ))
                .unwrap();

            subject_subs
                .remove_sub
                .try_send(RemoveStreamMsg {
                    peer_addr,
                    local_addr,
                    stream_type: RemovedStreamType::Clandestine,
                    dispatcher_sub: peer_actors.dispatcher.stream_shutdown_sub,
                })
                .unwrap();

            subject_subs
                .transmit_sub
                .try_send(TransmitDataMsg {
                    endpoint: Endpoint::Socket(peer_addr),
                    last_data: true,
                    sequence_number: Some(0),
                    data: vec![0x12, 0x34],
                })
                .unwrap();

            system.run();
        });

        TestLogHandler::new().await_log_containing(
            "No existing stream keyed by 1.2.3.5:*: creating one to 1.2.3.5:5673",
            1000,
        );
    }

    #[test]
    fn handle_remove_stream_msg_handles_report_to_counterpart_scenario() {
        let (recorder, _, recording_arc) = make_recorder();
        let system = System::new("test");
        let sub = recorder.start().recipient::<StreamShutdownMsg>();
        let mut subject = StreamHandlerPool::new(vec![], false);
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
        let sw_key = StreamWriterKey::from(peer_addr);
        let sender_wrapper = SenderWrapperMock::new(local_addr);
        subject
            .stream_writers
            .insert(sw_key.clone(), Some(Box::new(sender_wrapper)));

        subject.handle_remove_stream_msg(RemoveStreamMsg {
            peer_addr,
            local_addr,
            stream_type: RemovedStreamType::Clandestine,
            dispatcher_sub: sub,
        });

        System::current().stop_with_code(0);
        system.run();
        assert_eq!(subject.stream_writers.contains_key(&sw_key), false);
        let recording = recording_arc.lock().unwrap();
        let record = recording.get_record::<StreamShutdownMsg>(0);
        assert_eq!(
            record,
            &StreamShutdownMsg {
                peer_addr,
                stream_type: RemovedStreamType::Clandestine,
                report_to_counterpart: true
            }
        );
    }

    #[test]
    fn handle_remove_stream_msg_handles_no_report_to_counterpart_scenario() {
        let (recorder, _, recording_arc) = make_recorder();
        let system = System::new("test");
        let sub = recorder.start().recipient::<StreamShutdownMsg>();
        let mut subject = StreamHandlerPool::new(vec![], false);
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
        let sw_key = StreamWriterKey::from(peer_addr);

        subject.handle_remove_stream_msg(RemoveStreamMsg {
            peer_addr,
            local_addr,
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: HTTP_PORT,
                sequence_number: 1234,
            }),
            dispatcher_sub: sub,
        });

        System::current().stop_with_code(0);
        system.run();
        assert_eq!(subject.stream_writers.contains_key(&sw_key), false);
        let recording = recording_arc.lock().unwrap();
        let record = recording.get_record::<StreamShutdownMsg>(0);
        assert_eq!(
            record,
            &StreamShutdownMsg {
                peer_addr,
                stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                    reception_port: HTTP_PORT,
                    sequence_number: 1234
                }),
                report_to_counterpart: false
            }
        );
    }

    #[test]
    fn handle_remove_stream_msg_handles_stream_waiting_for_connect_scenario() {
        init_test_logging();
        let test_name = "handle_remove_stream_msg_handles_stream_waiting_for_connect_scenario";
        let (recorder, _, recording_arc) = make_recorder();
        let system = System::new(test_name);
        let sub = recorder.start().recipient::<StreamShutdownMsg>();
        let mut subject = StreamHandlerPool::new(vec![], false);
        subject.logger = Logger::new(test_name);
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
        let sw_key = StreamWriterKey::from(peer_addr);
        subject.stream_writers.insert(sw_key.clone(), None);

        subject.handle_remove_stream_msg(RemoveStreamMsg {
            peer_addr,
            local_addr,
            stream_type: RemovedStreamType::Clandestine,
            dispatcher_sub: sub,
        });

        System::current().stop_with_code(0);
        system.run();
        assert_eq!(subject.stream_writers.contains_key(&sw_key), false);
        let recording = recording_arc.lock().unwrap();
        let record = recording.get_record::<StreamShutdownMsg>(0);
        assert_eq!(
            record,
            &StreamShutdownMsg {
                peer_addr,
                stream_type: RemovedStreamType::Clandestine,
                report_to_counterpart: false
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {}: An unpopulated entry in stream_writers was found for a \
            Clandestine stream ({:?}) from a client. This shouldn't be possible. Investigate!",
            test_name, sw_key
        ));
    }

    #[test]
    fn when_stream_handler_pool_fails_to_create_nonexistent_stream_for_write_then_it_logs_and_notifies_neighborhood(
    ) {
        init_test_logging();
        let public_key = PublicKey::from(vec![0, 1, 2, 3]);
        let expected_key = public_key.clone();
        let connect_pair_params_arc = Arc::new(Mutex::new(vec![]));
        let connect_pair_params_arc_a = connect_pair_params_arc.clone();
        let (neighborhood, neighborhood_awaiter, neighborhood_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("when_stream_handler_pool_fails_to_create_nonexistent_stream_for_write_then_it_logs_and_notifies_neighborhood");
            let mut subject = StreamHandlerPool::new(vec![], false);
            subject.stream_connector = Box::new(
                StreamConnectorMock::new()
                    .connect_pair_result(Err(Error::from(ErrorKind::Other)))
                    .connect_pair_params(&connect_pair_params_arc),
            );
            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            subject_subs
                .node_query_response
                .try_send(DispatcherNodeQueryResponse {
                    result: Some(NodeQueryResponseMetadata::new(
                        public_key.clone(),
                        Some(NodeAddr::new(
                            &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
                            &[7000],
                        )),
                        rate_pack(100),
                    )),
                    context: TransmitDataMsg {
                        endpoint: Endpoint::Key(public_key),
                        last_data: false,
                        sequence_number: None,
                        data: b"hello".to_vec(),
                    },
                })
                .unwrap();

            system.run();
        });

        TestLogHandler::new().await_log_containing("ERROR: Dispatcher: Stream to 1.2.3.5:7000 does not exist and could not be connected; discarding 5 bytes: other error", 1000);
        neighborhood_awaiter.await_message_count(1);
        let remove_neighbor_msg =
            Recording::get::<RemoveNeighborMessage>(&neighborhood_recording_arc, 0);
        assert_eq!(remove_neighbor_msg.public_key, expected_key);

        let connect_pair_params = connect_pair_params_arc_a.lock().unwrap();
        let connect_pair_params_vec: &Vec<SocketAddr> = connect_pair_params.as_ref();
        assert_eq!(
            *connect_pair_params_vec,
            vec![SocketAddr::from_str("1.2.3.5:7000").unwrap()]
        );
    }

    #[test]
    fn stream_handler_pool_creates_nonexistent_stream_for_reading_and_writing() {
        use crossbeam_channel::unbounded;
        let public_key = PublicKey::from(vec![0, 1, 2, 3]);
        let masquerader = JsonMasquerader::new();
        let incoming_unmasked = b"Incoming data".to_vec();
        let incoming_masked = masquerader.mask(&incoming_unmasked).unwrap();
        let outgoing_unmasked = b"Outgoing data".to_vec();
        let outgoing_masked = masquerader.mask(&outgoing_unmasked).unwrap();
        let outgoing_masked_len = outgoing_masked.len();
        let (dispatcher, dispatcher_awaiter, dispatcher_recording_arc) = make_recorder();
        let (neighborhood, neighborhood_awaiter, neighborhood_recording_arc) = make_recorder();
        let poll_write_params_arc = Arc::new(Mutex::new(vec![]));
        let poll_write_params_arc_a = poll_write_params_arc.clone();
        let (tx, rx) = unbounded();
        thread::spawn(move || {
            let system = System::new(
                "stream_handler_pool_creates_nonexistent_stream_for_reading_and_writing",
            );
            let discriminator_factory = JsonDiscriminatorFactory::new();
            let mut subject = StreamHandlerPool::new(vec![Box::new(discriminator_factory)], false);
            subject.stream_connector = Box::new(
                StreamConnectorMock::new().connect_pair_result(Ok(ConnectionInfo {
                    reader: Box::new(
                        ReadHalfWrapperMock::new()
                            .poll_read_ok(incoming_masked)
                            .poll_read_result(vec![], Ok(Async::NotReady)),
                    ),
                    writer: Box::new(
                        WriteHalfWrapperMock::new()
                            .poll_write_ok(outgoing_masked_len)
                            .poll_write_result(Ok(Async::NotReady))
                            .poll_write_params(&poll_write_params_arc),
                    ),
                    local_addr: SocketAddr::from_str("127.0.0.1:54321").unwrap(),
                    peer_addr: SocketAddr::from_str("1.2.3.5:7000").unwrap(),
                })),
            );
            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .neighborhood(neighborhood)
                .build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            tx.send(subject_subs).unwrap();

            system.run();
        });

        let subject_subs = rx.recv().unwrap();
        let before = SystemTime::now();

        subject_subs
            .transmit_sub
            .try_send(TransmitDataMsg {
                endpoint: Endpoint::Key(public_key.clone()),
                last_data: false,
                sequence_number: None,
                data: outgoing_unmasked,
            })
            .unwrap();

        neighborhood_awaiter.await_message_count(1);
        let target_ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5));
        let node_query_msg =
            Recording::get::<DispatcherNodeQueryMessage>(&neighborhood_recording_arc, 0);
        subject_subs
            .node_query_response
            .try_send(DispatcherNodeQueryResponse {
                result: Some(NodeQueryResponseMetadata::new(
                    public_key.clone(),
                    Some(NodeAddr::new(&target_ip_addr, &[7000])),
                    rate_pack(100),
                )),
                context: node_query_msg.context,
            })
            .unwrap();

        await_messages(1, &poll_write_params_arc_a);
        let after = SystemTime::now();
        let poll_write_params = poll_write_params_arc_a.lock().unwrap();
        assert_eq!(poll_write_params[0], outgoing_masked);

        dispatcher_awaiter.await_message_count(1);
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let ibcd = dispatcher_recording.get_record::<InboundClientData>(0);
        check_timestamp(before, ibcd.timestamp, after);
        assert_eq!(
            ibcd,
            &InboundClientData {
                timestamp: ibcd.timestamp,
                peer_addr: SocketAddr::from_str("1.2.3.5:7000").unwrap(),
                reception_port: Some(54321),
                last_data: false,
                is_clandestine: true,
                sequence_number: None,
                data: incoming_unmasked,
            }
        );

        neighborhood_awaiter.await_message_count(2);
        let connection_progress_message =
            Recording::get::<ConnectionProgressMessage>(&neighborhood_recording_arc, 1);
        assert_eq!(
            connection_progress_message,
            ConnectionProgressMessage {
                peer_addr: target_ip_addr,
                event: ConnectionProgressEvent::TcpConnectionSuccessful
            }
        );
    }

    #[test]
    fn transmit_data_msg_handler_finds_ip_from_neighborhood_and_transmits_message() {
        init_test_logging();
        let key = PublicKey::from(vec![8, 4, 8, 4]);
        let reader = ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::NotReady));
        let write_stream_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(Error::from(ErrorKind::Other)))
            .poll_write_result(Ok(Async::Ready(5)))
            .poll_write_result(Ok(Async::NotReady))
            .poll_write_params(&write_stream_params_arc);
        let local_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();

        let (neighborhood, awaiter, recording_arc) = make_recorder();
        let (tx, rx) = unbounded();

        thread::spawn(move || {
            let system = System::new("test");
            let subject = StreamHandlerPool::new(vec![], false);

            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new(reader),
                writer: Box::new(writer),
                local_addr,
                peer_addr,
            };

            subject_subs
                .add_sub
                .try_send(AddStreamMsg::new(
                    connection_info,
                    None,
                    PortConfiguration::new(vec![Box::new(JsonDiscriminatorFactory::new())], true),
                ))
                .unwrap();

            tx.send(subject_subs).unwrap();

            system.run();
        });

        let subject_subs = rx.recv().unwrap();

        subject_subs
            .transmit_sub
            .try_send(TransmitDataMsg {
                endpoint: Endpoint::Key(key.clone()),
                last_data: false,
                sequence_number: Some(0),
                data: b"hello".to_vec(),
            })
            .unwrap();

        awaiter.await_message_count(1);
        let node_query_msg = Recording::get::<DispatcherNodeQueryMessage>(&recording_arc, 0);
        subject_subs
            .node_query_response
            .try_send(DispatcherNodeQueryResponse {
                result: Some(NodeQueryResponseMetadata::new(
                    key.clone(),
                    Some(NodeAddr::new(
                        &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
                        &[6789],
                    )),
                    rate_pack(100),
                )),
                context: node_query_msg.context,
            })
            .unwrap();

        await_messages(2, &write_stream_params_arc);
        let mut sw_to_stream_params = write_stream_params_arc.lock().unwrap();
        assert_eq!(sw_to_stream_params.len(), 2);
        assert_eq!(sw_to_stream_params.remove(0), b"hello");
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Dispatcher: Sending node query about CAQIBA to Neighborhood"
        ));
    }

    #[test]
    fn node_query_response_handler_does_not_try_to_write_when_neighbor_is_not_found() {
        init_test_logging();
        let cryptde = main_cryptde();
        let key = cryptde.public_key().clone();

        thread::spawn(move || {
            let system = System::new("test");
            let subject = StreamHandlerPool::new(vec![], false);

            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            subject_subs
                .node_query_response
                .try_send(DispatcherNodeQueryResponse {
                    result: None,
                    context: TransmitDataMsg {
                        endpoint: Endpoint::Key(key.clone()),
                        last_data: false,
                        sequence_number: Some(0),
                        data: b"hello".to_vec(),
                    },
                })
                .unwrap();

            system.run();
        });

        TestLogHandler::new().await_log_containing(
            format!(
                "ERROR: Dispatcher: No Node found at endpoint {:?}",
                Endpoint::Key(cryptde.public_key().clone())
            )
            .as_str(),
            1000,
        );
    }

    #[test]
    fn node_query_response_handler_does_not_try_to_write_when_neighbor_ip_is_not_known() {
        init_test_logging();
        let cryptde = main_cryptde();
        let key = cryptde.public_key().clone();

        thread::spawn(move || {
            let system = System::new("test");
            let subject = StreamHandlerPool::new(vec![], false);

            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            subject_subs
                .node_query_response
                .try_send(DispatcherNodeQueryResponse {
                    result: Some(NodeQueryResponseMetadata::new(
                        key.clone(),
                        None,
                        rate_pack(100),
                    )),
                    context: TransmitDataMsg {
                        endpoint: Endpoint::Key(key.clone()),
                        last_data: false,
                        sequence_number: None,
                        data: b"hello".to_vec(),
                    },
                })
                .unwrap();

            system.run();
        });

        TestLogHandler::new().await_log_containing(
            format!(
                "ERROR: Dispatcher: No known IP for neighbor in route with key: {}",
                cryptde.public_key()
            )
            .as_str(),
            1000,
        );
    }

    #[test]
    fn node_query_response_handler_resends_transmit_data_msg_when_connection_is_in_progress() {
        init_test_logging();
        let cryptde = main_cryptde();
        let key = cryptde.public_key().clone();

        let peer_addr = SocketAddr::from_str("5.4.3.1:8000").unwrap();
        let peer_addr_a = peer_addr.clone();
        let msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr.clone()),
            last_data: false,
            sequence_number: Some(0),
            data: b"hello".to_vec(),
        };
        let msg_a = msg.clone();

        let (tx, rx) = unbounded();

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec![], false);
            subject
                .stream_writers
                .insert(StreamWriterKey::from(peer_addr), None);
            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            subject_subs
                .node_query_response
                .try_send(DispatcherNodeQueryResponse {
                    result: Some(NodeQueryResponseMetadata::new(
                        key.clone(),
                        Some(NodeAddr::new(&peer_addr.ip(), &[peer_addr.port()])),
                        rate_pack(100),
                    )),
                    context: msg,
                })
                .unwrap();

            tx.send(subject_subs).expect("Tx failure");

            system.run();
        });
        let subject_subs = rx.recv().unwrap();

        TestLogHandler::new().await_log_containing(
            format!(
                "connection for {} in progress, resubmitting {} bytes",
                peer_addr_a,
                msg_a.data.len()
            )
            .as_str(),
            1000,
        );

        let local_addr = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let poll_write_params_arc = Arc::new(Mutex::new(Vec::new()));

        let connection_info = ConnectionInfo {
            reader: Box::new(
                ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::NotReady)),
            ),
            writer: Box::new(
                WriteHalfWrapperMock::new()
                    .poll_write_result(Ok(Async::NotReady))
                    .poll_write_params(&poll_write_params_arc),
            ),
            local_addr,
            peer_addr: peer_addr_a,
        };

        subject_subs
            .add_sub
            .try_send(AddStreamMsg::new(
                connection_info,
                Some(HTTP_PORT),
                PortConfiguration::new(
                    vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                    false,
                ),
            ))
            .unwrap();

        await_messages(1, &poll_write_params_arc);
        let poll_write_params = poll_write_params_arc.lock().unwrap();

        assert_eq!(poll_write_params[0], msg_a.data);
    }

    #[test]
    fn log_an_error_when_it_fails_to_send_a_packet() {
        init_test_logging();
        let cryptde = main_cryptde();
        let key = cryptde.public_key().clone();
        let peer_addr = SocketAddr::new(localhost(), find_free_port());
        let sw_key = StreamWriterKey::from(peer_addr);
        let sender_wrapper_unbounded_send_params_arc = Arc::new(Mutex::new(vec![]));
        let send_error = make_send_error();
        let sender_wrapper = SenderWrapperMock::new(peer_addr)
            .unbounded_send_params(&sender_wrapper_unbounded_send_params_arc)
            .unbounded_send_result(Err(send_error));
        let mut subject = StreamHandlerPool::new(vec![], false);
        subject
            .stream_writers
            .insert(sw_key, Some(Box::new(sender_wrapper)));
        let msg = DispatcherNodeQueryResponse {
            result: Some(NodeQueryResponseMetadata {
                public_key: key,
                node_addr_opt: Some(NodeAddr::new(&peer_addr.ip(), &[peer_addr.port()])),
                rate_pack: ZERO_RATE_PACK.clone(),
            }),
            context: TransmitDataMsg {
                endpoint: Endpoint::Socket(peer_addr.clone()),
                last_data: true,
                sequence_number: Some(0),
                data: b"hello".to_vec(),
            },
        };

        let _ = subject.handle_dispatcher_node_query_response(msg);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            format!(
                "ERROR: Dispatcher: Removing channel to disabled StreamWriter {} to {}: send failed because receiver is gone",
                StreamWriterKey::from (peer_addr), peer_addr,
            )
                .as_str(),
        );
    }

    #[test]
    fn when_a_new_connection_fails_the_stream_writer_flag_is_removed_and_another_connection_is_attempted_for_the_next_message_with_the_same_stream_key(
    ) {
        init_test_logging();
        let cryptde = main_cryptde();
        let key = cryptde.public_key().clone();
        let key_bg = key.clone();
        let peer_addr = SocketAddr::from_str("5.4.3.1:8000").unwrap();
        let peer_addr_a = peer_addr.clone();
        let msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr.clone()),
            last_data: false,
            sequence_number: None,
            data: b"hello".to_vec(),
        };
        let msg_a = TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr.clone()),
            last_data: false,
            sequence_number: None,
            data: b"worlds".to_vec(),
        };
        let expected_data = JsonMasquerader::new().mask(&msg_a.data).unwrap();

        let local_addr = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let poll_write_params_arc = Arc::new(Mutex::new(Vec::new()));

        let connection_info = ConnectionInfo {
            reader: Box::new(
                ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::NotReady)),
            ),
            writer: Box::new(
                WriteHalfWrapperMock::new()
                    .poll_write_params(&poll_write_params_arc)
                    .poll_write_result(Ok(Async::Ready(expected_data.len()))),
            ),
            local_addr,
            peer_addr: peer_addr_a,
        };
        let (neighborhood, neighborhood_awaiter, neighborhood_recording_arc) = make_recorder();
        let (tx, rx) = unbounded();

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec![], false);
            subject.stream_connector = Box::new(
                StreamConnectorMock::new()
                    .connect_pair_result(Err(Error::from(ErrorKind::Other)))
                    .connect_pair_result(Ok(connection_info)),
            );
            subject.clandestine_discriminator_factories =
                vec![Box::new(HttpRequestDiscriminatorFactory::new())];
            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            subject_subs
                .node_query_response
                .try_send(DispatcherNodeQueryResponse {
                    result: Some(NodeQueryResponseMetadata::new(
                        key_bg,
                        Some(NodeAddr::new(&peer_addr.ip(), &[peer_addr.port()])),
                        rate_pack(100),
                    )),
                    context: msg,
                })
                .unwrap();

            tx.send(subject_subs).expect("Tx failure");

            system.run();
        });
        let subject_subs = rx.recv().unwrap();

        let expected_data = JsonMasquerader::new().mask(&msg_a.data).unwrap();
        subject_subs
            .node_query_response
            .try_send(DispatcherNodeQueryResponse {
                result: Some(NodeQueryResponseMetadata::new(
                    cryptde.public_key().clone(),
                    Some(NodeAddr::new(&peer_addr.ip(), &[peer_addr.port()])),
                    rate_pack(100),
                )),
                context: msg_a,
            })
            .unwrap();

        await_messages(1, &poll_write_params_arc);
        let poll_write_params = poll_write_params_arc.lock().unwrap();

        assert_eq!(poll_write_params[0], expected_data);
        assert_eq!(poll_write_params.len(), 1);

        neighborhood_awaiter.await_message_count(1);
        let connection_progress_message =
            Recording::get::<ConnectionProgressMessage>(&neighborhood_recording_arc, 1);
        assert_eq!(
            connection_progress_message,
            ConnectionProgressMessage {
                peer_addr: peer_addr.ip(),
                event: ConnectionProgressEvent::TcpConnectionFailed
            }
        );
    }

    #[test]
    fn node_query_response_handler_sets_counterpart_flag_and_removes_stream_writer_if_last_data_is_true(
    ) {
        init_test_logging();
        let cryptde = main_cryptde();
        let key = cryptde.public_key().clone();
        let peer_addr = SocketAddr::from_str("127.0.0.1:8005").unwrap();
        let sender_wrapper_unbounded_send_params_arc = Arc::new(Mutex::new(vec![]));
        let sender_wrapper = SenderWrapperMock::new(peer_addr)
            .unbounded_send_params(&sender_wrapper_unbounded_send_params_arc)
            .unbounded_send_result(Ok(()));
        let mut subject = StreamHandlerPool::new(vec![], false);
        subject.stream_writers.insert(
            StreamWriterKey::from(peer_addr),
            Some(Box::new(sender_wrapper)),
        );

        let _ = subject.handle_dispatcher_node_query_response(DispatcherNodeQueryResponse {
            result: Some(NodeQueryResponseMetadata {
                public_key: key,
                node_addr_opt: Some(NodeAddr::new(&peer_addr.ip(), &[peer_addr.port()])),
                rate_pack: ZERO_RATE_PACK.clone(),
            }),
            context: TransmitDataMsg {
                endpoint: Endpoint::Socket(peer_addr.clone()),
                last_data: true,
                sequence_number: Some(0),
                data: b"hello".to_vec(),
            },
        });

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            format!(
                "DEBUG: Dispatcher: Removing channel to StreamWriter {} to {} in response to server-drop report",
                StreamWriterKey::from (peer_addr), peer_addr,
            )
                .as_str(),
        );
        assert_eq!(
            subject
                .stream_writers
                .contains_key(&StreamWriterKey::from(peer_addr)),
            false
        );
        let sender_wrapper_unbounded_send_params =
            sender_wrapper_unbounded_send_params_arc.lock().unwrap();
        assert_eq!(
            sender_wrapper_unbounded_send_params.deref(),
            &[SequencedPacket::new(b"hello".to_vec(), 0, true),]
        );
    }

    #[test]
    #[should_panic(
        expected = "Neighborhood has returned a NodeDescriptor with no ports. This indicates an unrecoverable error."
    )]
    fn when_node_query_response_node_addr_contains_no_ports_then_stream_handler_pool_panics() {
        init_test_logging();
        let cryptde = main_cryptde();
        let key = cryptde.public_key();

        let peer_addr = SocketAddr::from_str("5.4.3.1:8000").unwrap();
        let msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr.clone()),
            last_data: false,
            sequence_number: None,
            data: b"hello".to_vec(),
        };

        let system = System::new("test");
        let subject = StreamHandlerPool::new(vec![], false);
        let subject_addr: Addr<StreamHandlerPool> = subject.start();
        let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
        let peer_actors = peer_actors_builder().build();
        subject_subs
            .bind
            .try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            })
            .unwrap();

        subject_subs
            .node_query_response
            .try_send(DispatcherNodeQueryResponse {
                result: Some(NodeQueryResponseMetadata::new(
                    key.clone(),
                    Some(NodeAddr::new(&peer_addr.ip(), &[])),
                    rate_pack(100),
                )),
                context: msg,
            })
            .unwrap();

        system.run();
    }

    #[test]
    fn stream_handler_pool_writes_much_clandestine_data_to_stream_writer() {
        let hello = b"hello".to_vec();
        let worlds = b"worlds".to_vec();

        let masked_hello = JsonMasquerader::new().mask(&hello).unwrap();
        let masked_worlds = JsonMasquerader::new().mask(&worlds).unwrap();

        let reader = ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::NotReady));
        let write_stream_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(masked_hello.len())))
            .poll_write_result(Ok(Async::Ready(masked_worlds.len())))
            .poll_write_result(Ok(Async::NotReady))
            .poll_write_params(&write_stream_params_arc);
        let local_addr = SocketAddr::from_str("1.2.3.4:6789").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();

        thread::spawn(move || {
            let system = System::new("test");
            let subject = StreamHandlerPool::new(vec![], false);

            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new(reader),
                writer: Box::new(writer),
                local_addr,
                peer_addr,
            };

            subject_subs
                .add_sub
                .try_send(AddStreamMsg::new(
                    connection_info,
                    None,
                    PortConfiguration::new(
                        vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                        true,
                    ),
                ))
                .unwrap();

            subject_subs
                .transmit_sub
                .try_send(TransmitDataMsg {
                    endpoint: Endpoint::Socket(peer_addr),
                    last_data: false,
                    sequence_number: None,
                    data: hello,
                })
                .unwrap();

            subject_subs
                .transmit_sub
                .try_send(TransmitDataMsg {
                    endpoint: Endpoint::Socket(peer_addr),
                    last_data: false,
                    sequence_number: None,
                    data: worlds,
                })
                .unwrap();

            system.run();
        });

        await_messages(2, &write_stream_params_arc);
        let mut sw_to_stream_params = write_stream_params_arc.lock().unwrap();
        assert_eq!(sw_to_stream_params.len(), 2);
        assert_eq!(sw_to_stream_params.remove(0), masked_hello);
        assert_eq!(sw_to_stream_params.remove(0), masked_worlds);
    }

    #[test]
    fn stream_handler_pool_drops_data_when_masking_fails() {
        init_test_logging();
        let reader = ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::NotReady));
        let writer = WriteHalfWrapperMock::new().poll_write_result(Ok(Async::NotReady));
        let local_addr = SocketAddr::from_str("1.2.3.4:6789").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec![], false);
            subject.traffic_analyzer = Box::new(TrafficAnalyzerMock {});

            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new(reader),
                writer: Box::new(writer),
                local_addr,
                peer_addr,
            };

            subject_subs
                .add_sub
                .try_send(AddStreamMsg::new(
                    connection_info,
                    None,
                    PortConfiguration::new(
                        vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                        true,
                    ),
                ))
                .unwrap();

            subject_subs
                .transmit_sub
                .try_send(TransmitDataMsg {
                    endpoint: Endpoint::Socket(peer_addr),
                    last_data: false,
                    sequence_number: None,
                    data: b"hello".to_vec(),
                })
                .unwrap();

            system.run();
        });

        TestLogHandler::new().await_log_containing("Masking failed for 1.2.3.5:6789: Low-level data error: don't care. Discarding 5 bytes.", 1000);
    }

    #[test]
    fn stream_handler_pool_logs_error_and_returns_when_local_connection_is_gone() {
        init_test_logging();
        let outgoing_unmasked = b"Outgoing data".to_vec();
        let outgoing_unmasked_len = outgoing_unmasked.len();
        let (tx, rx) = unbounded();
        thread::spawn(move || {
            let system = System::new(
                "stream_handler_pool_creates_nonexistent_stream_for_reading_and_writing",
            );
            let discriminator_factory = JsonDiscriminatorFactory::new();
            let mut subject = StreamHandlerPool::new(vec![Box::new(discriminator_factory)], false);
            subject.stream_connector = Box::new(StreamConnectorMock::new()); // this will panic if a connection is attempted
            let subject_addr: Addr<StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = peer_actors_builder().build();
            subject_subs
                .bind
                .try_send(PoolBindMessage {
                    dispatcher_subs: peer_actors.dispatcher,
                    stream_handler_pool_subs: subject_subs.clone(),
                    neighborhood_subs: peer_actors.neighborhood,
                })
                .unwrap();

            tx.send(subject_subs).unwrap();

            system.run();
        });

        let subject_subs = rx.recv().unwrap();
        let local_addr = SocketAddr::from_str("127.0.0.1:46377").unwrap();

        subject_subs
            .transmit_sub
            .try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(local_addr),
                last_data: false,
                sequence_number: Some(0),
                data: outgoing_unmasked,
            })
            .unwrap();

        TestLogHandler::new().await_log_containing(
            format!(
                "Local connection {:?} not found. Discarding {} bytes.",
                local_addr, outgoing_unmasked_len
            )
            .as_str(),
            1000,
        );
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn stream_handler_can_be_crashed_properly_but_not_improperly() {
        let stream_handler_pool = StreamHandlerPool::new(vec![], true);

        prove_that_crash_request_handler_is_hooked_up(stream_handler_pool, CRASH_KEY);
    }
}
