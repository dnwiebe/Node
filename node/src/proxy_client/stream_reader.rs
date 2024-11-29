// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::proxy_client::InboundServerData;
use crate::sub_lib::sequencer::Sequencer;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use actix::Recipient;
use crossbeam_channel::{Receiver, Sender};
use masq_lib::logger::Logger;
use std::net::SocketAddr;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct StreamReader {
    stream_key: StreamKey,
    proxy_client_sub: Recipient<InboundServerData>,
    stream: Box<dyn ReadHalfWrapper>,
    stream_killer: Sender<(StreamKey, u64)>,
    shutdown_signal: Receiver<()>,
    peer_addr: SocketAddr,
    logger: Logger,
    sequencer: Sequencer,
}

impl Future for StreamReader {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        let mut buf: [u8; 16384] = [0; 16384];
        loop {
            if self.shutdown_signal.try_recv().is_ok() {
                info!(
                    self.logger,
                    "Shutting down for stream: {:?}", self.stream_key
                );
                return Ok(Async::Ready(()));
            }
            match self.stream.poll_read(&mut buf) {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(0)) => {
                    // see RETURN VALUE section of recv man page (Unix)
                    debug!(
                        self.logger,
                        "Stream from {} was closed: (0-byte read)", self.peer_addr
                    );
                    self.shutdown();
                    return Ok(Async::Ready(()));
                }
                Ok(Async::Ready(len)) => {
                    if self.logger.trace_enabled() {
                        trace!(
                            self.logger,
                            "Read {}-byte chunk from {}",
                            len,
                            self.peer_addr
                        );
                    }
                    let stream_key = self.stream_key;
                    self.send_inbound_server_data(stream_key, Vec::from(&buf[0..len]), false);
                }
                Err(e) => {
                    if indicates_dead_stream(e.kind()) {
                        debug!(
                            self.logger,
                            "Stream from {} was closed: {}", self.peer_addr, e
                        );
                        self.shutdown();
                        return Err(());
                    } else {
                        // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                        warning!(
                            self.logger,
                            "Continuing after read error on stream from {}: {}",
                            self.peer_addr,
                            e
                        );
                    }
                }
            }
        }
    }
}

impl StreamReader {
    pub fn new(
        stream_key: StreamKey,
        proxy_client_sub: Recipient<InboundServerData>,
        stream: Box<dyn ReadHalfWrapper>,
        stream_killer: Sender<(StreamKey, u64)>,
        shutdown_signal: Receiver<()>,
        peer_addr: SocketAddr,
    ) -> StreamReader {
        let logger = Logger::new(&format!("StreamReader for {:?}/{}", stream_key, peer_addr)[..]);
        debug!(logger, "Initialised StreamReader");
        StreamReader {
            stream_key,
            proxy_client_sub,
            stream,
            stream_killer,
            shutdown_signal,
            peer_addr,
            logger,
            sequencer: Sequencer::new(),
        }
    }

    fn shutdown(&mut self) {
        let _ = self
            .stream_killer
            .send((self.stream_key, self.sequencer.next_sequence_number()));
    }

    fn send_inbound_server_data(&mut self, stream_key: StreamKey, data: Vec<u8>, last_data: bool) {
        self.proxy_client_sub
            .try_send(InboundServerData {
                stream_key,
                last_data,
                sequence_number: self.sequencer.next_sequence_number(),
                source: self.peer_addr,
                data,
            })
            .expect("ProxyClient is dead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use actix::{Actor, System};
    use crossbeam_channel::unbounded;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::thread;

    #[test]
    fn stream_reader_assigns_a_sequence_to_client_response_payloads() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();

        let read_results = vec![
            b"HTTP/1.1 200".to_vec(),
            b" OK\r\n\r\nHTTP/1.1 40".to_vec(),
            b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec(),
        ];

        let mut stream = Box::new(ReadHalfWrapperMock::new());

        stream.poll_read_results = vec![
            (
                read_results[0].clone(),
                Ok(Async::Ready(read_results[0].len())),
            ),
            (
                read_results[1].clone(),
                Ok(Async::Ready(read_results[1].len())),
            ),
            (
                read_results[2].clone(),
                Ok(Async::Ready(read_results[2].len())),
            ),
            (vec![], Ok(Async::Ready(0))),
        ];

        let (tx, rx) = unbounded();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            tx.send(peer_actors.proxy_client_opt.unwrap().inbound_server_data)
                .expect("Internal Error");
            system.run();
        });

        let proxy_client_sub = rx.recv().unwrap();
        let (stream_killer, stream_killer_params) = unbounded();
        let mut subject = StreamReader {
            stream_key: StreamKey::make_meaningless_stream_key(),
            proxy_client_sub,
            stream,
            stream_killer,
            shutdown_signal: unbounded().1,
            peer_addr: SocketAddr::from_str("8.7.4.3:50").unwrap(),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let _res = subject.poll();

        proxy_client_awaiter.await_message_count(3);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: StreamKey::make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b"HTTP/1.1 200".to_vec()
            },
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(1),
            &InboundServerData {
                stream_key: StreamKey::make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 1,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b" OK\r\n\r\nHTTP/1.1 40".to_vec()
            },
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(2),
            &InboundServerData {
                stream_key: StreamKey::make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 2,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec()
            },
        );
        let stream_killer_parameters = stream_killer_params.try_recv().unwrap();
        assert_eq!(
            stream_killer_parameters,
            (StreamKey::make_meaningless_stream_key(), 3)
        );
    }

    #[test]
    fn stream_reader_can_handle_multiple_packets_followed_by_dropped_stream() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let mut stream = ReadHalfWrapperMock::new();
        stream.poll_read_results = vec![
            (
                Vec::from(&b"HTTP/1.1 200"[..]),
                Ok(Async::Ready(b"HTTP/1.1 200".len())),
            ),
            (
                Vec::from(&b" OK\r\n\r\nHTTP/1.1 40"[..]),
                Ok(Async::Ready(b" OK\r\n\r\nHTTP/1.1 40".len())),
            ),
            (
                Vec::from(&b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n"[..]),
                Ok(Async::Ready(
                    b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".len(),
                )),
            ),
            (vec![], Err(Error::from(ErrorKind::BrokenPipe))),
        ];
        let (tx, rx) = unbounded();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            tx.send(peer_actors.proxy_client_opt.unwrap().inbound_server_data)
                .expect("Internal Error");

            system.run();
        });
        let proxy_client_sub = rx.recv().unwrap();
        let (stream_killer, stream_killer_params) = unbounded();
        let peer_addr = SocketAddr::from_str("5.7.9.0:95").unwrap();
        let mut subject = make_subject();
        subject.proxy_client_sub = proxy_client_sub;
        subject.stream = Box::new(stream);
        subject.stream_killer = stream_killer;
        subject.peer_addr = peer_addr;

        let result = subject.poll();

        assert_eq!(result, Err(()));
        proxy_client_awaiter.await_message_count(3);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: StreamKey::make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: peer_addr,
                data: b"HTTP/1.1 200".to_vec()
            }
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(1),
            &InboundServerData {
                stream_key: StreamKey::make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 1,
                source: peer_addr,
                data: b" OK\r\n\r\nHTTP/1.1 40".to_vec()
            }
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(2),
            &InboundServerData {
                stream_key: StreamKey::make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 2,
                source: peer_addr,
                data: b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec()
            }
        );

        let kill_stream_msg = stream_killer_params
            .try_recv()
            .expect("stream was not killed");
        assert_eq!(
            kill_stream_msg,
            (StreamKey::make_meaningless_stream_key(), 3)
        );
        assert!(stream_killer_params.try_recv().is_err());
    }

    #[test]
    fn receiving_0_bytes_kills_stream() {
        init_test_logging();
        let test_name = "receiving_0_bytes_kills_stream";
        let stream_key = StreamKey::make_meaningless_stream_key();
        let (stream_killer, kill_stream_params) = unbounded();
        let mut stream = ReadHalfWrapperMock::new();
        stream.poll_read_results = vec![(vec![], Ok(Async::Ready(0)))];
        let peer_addr = SocketAddr::from_str("5.3.4.3:654").unwrap();
        let system = System::new(test_name);
        let mut sequencer = Sequencer::new();
        sequencer.next_sequence_number();
        sequencer.next_sequence_number();

        let mut subject = StreamReader {
            stream_key,
            proxy_client_sub: make_recorder().0.start().recipient(),
            stream: Box::new(stream),
            stream_killer,
            shutdown_signal: unbounded().1,
            peer_addr,
            logger: Logger::new(test_name),
            sequencer,
        };
        System::current().stop();
        system.run();

        let result = subject.poll();

        assert_eq!(result, Ok(Async::Ready(())));
        assert_eq!(kill_stream_params.try_recv().unwrap(), (stream_key, 2));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Stream from {peer_addr} was closed: (0-byte read)"
        ));
    }

    #[test]
    fn non_dead_stream_read_errors_log_but_do_not_shut_down() {
        init_test_logging();
        let test_name = "non_dead_stream_read_errors_log_but_do_not_shut_down";
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let (stream_killer, _) = unbounded();
        let mut stream = ReadHalfWrapperMock::new();
        let http_response = b"HTTP/1.1 200 OK\r\n\r\n";
        stream.poll_read_results = vec![
            (vec![], Err(Error::from(ErrorKind::Other))),
            (
                http_response.to_vec(),
                Ok(Async::Ready(http_response.len())),
            ),
            (vec![], Err(Error::from(ErrorKind::BrokenPipe))),
        ];

        let (tx, rx) = unbounded();

        thread::spawn(move || {
            let system = System::new("non_dead_stream_read_errors_log_but_do_not_shut_down");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            tx.send(peer_actors.proxy_client_opt.unwrap().inbound_server_data)
                .expect("Internal Error");
            system.run();
        });

        let proxy_client_sub = rx.recv().unwrap();
        let peer_addr = SocketAddr::from_str("6.5.4.1:8325").unwrap();
        let mut subject = StreamReader {
            stream_key,
            proxy_client_sub,
            stream: Box::new(stream),
            stream_killer,
            shutdown_signal: unbounded().1,
            peer_addr,
            logger: Logger::new(test_name),
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Err(()));
        proxy_client_awaiter.await_message_count(1);
        TestLogHandler::new().exists_log_containing(
            &format!("WARN: {test_name}: Continuing after read error on stream from {peer_addr}: other error"),
        );
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key,
                last_data: false,
                sequence_number: 0,
                source: peer_addr,
                data: http_response.to_vec()
            }
        );
    }

    #[test]
    fn stream_reader_shuts_down_when_it_receives_the_shutdown_signal() {
        init_test_logging();
        let test_name = "stream_reader_shuts_down_when_it_receives_the_shutdown_signal";
        let (shutdown_tx, shutdown_rx) = unbounded();
        let mut subject = make_subject();
        subject.shutdown_signal = shutdown_rx;
        subject.logger = Logger::new(test_name);
        shutdown_tx.send(()).unwrap();

        let result = subject.poll();

        assert_eq!(result, Ok(Async::Ready(())));
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Shutting down for stream: {:?}",
            subject.stream_key
        ));
    }

    pub fn make_subject() -> StreamReader {
        StreamReader {
            stream_key: StreamKey::make_meaningless_stream_key(),
            proxy_client_sub: make_recorder().0.start().recipient(),
            stream: Box::new(ReadHalfWrapperMock::new()),
            stream_killer: unbounded().0,
            shutdown_signal: unbounded().1,
            peer_addr: SocketAddr::from_str("9.8.7.6:5432").unwrap(),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        }
    }
}
