// Copyright (c) 2022, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::test_utils::utils::UrlHolder;
use crate::utils::localhost;
use crossbeam_channel::{unbounded, Receiver, Sender};
use itertools::Either;
use itertools::Either::{Left, Right};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

lazy_static! {
    pub static ref CONTENT_LENGTH_DETECTOR: Regex =
        Regex::new(r"[Cc]ontent-[Ll]ength: *(\d+)\r\n").expect("Bad regular expression");
    pub static ref HTTP_VERSION_DETECTOR: Regex =
        Regex::new(r"HTTP/(\d\.\d)").expect("Bad regular expression");
}

pub struct MBCSBuilder {
    port: u16,
    run_on_docker: bool,
    response_batch_opt: Option<Vec<String>>,
    responses: Vec<String>,
    notifier: Sender<()>,
}

impl MBCSBuilder {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            run_on_docker: false,
            response_batch_opt: None,
            responses: vec![],
            notifier: unbounded().0,
        }
    }

    pub fn run_on_docker(mut self) -> Self {
        self.run_on_docker = true;
        self
    }

    pub fn begin_batch(mut self) -> Self {
        if self.response_batch_opt.is_some() {
            panic!("Cannot nest response batches")
        }
        self.response_batch_opt = Some(vec![]);
        self
    }

    pub fn end_batch(mut self) -> Self {
        let batch_contents = self.response_batch_opt.take().unwrap();
        self.responses
            .push(format!("[{}]", batch_contents.join(", ")));
        self
    }

    pub fn raw_response(self, raw_string: String) -> Self {
        self.store_response_string(raw_string)
    }

    pub fn response<R>(self, result: R, id: u64) -> Self
    where
        R: Serialize,
    {
        let result = serde_json::to_string(&result).unwrap();
        let body = format!(
            r#"{{"jsonrpc": "2.0", "result": {}, "id": {}}}"#,
            result, id
        );
        self.store_response_string(body)
    }

    pub fn err_response<R>(self, code: i64, message: R, id: u64) -> Self
    where
        R: Serialize,
    {
        let message = serde_json::to_string(&message).unwrap();
        let body = format!(
            r#"{{"jsonrpc": "2.0", "error": {{ "code": {}, "message": {} }}, "id": {}}}"#,
            code, message, id
        );
        self.store_response_string(body)
    }

    pub fn error<D>(self, code: u64, message: &str, data: Option<D>) -> Self
    where
        D: Serialize,
    {
        let data_str = match data.map(|d| serde_json::to_string(&d).unwrap()) {
            None => "".to_string(),
            Some(json) => format!(r#", "data": {}"#, json),
        };
        let body = format!(
            r#"{{"jsonrpc": "2.0", "error": {{"code": {}, "message": "{}"{}}}}}"#,
            code, message, data_str
        );
        self.store_response_string(body)
    }

    pub fn notifier(mut self, notifier: Sender<()>) -> Self {
        self.notifier = notifier;
        self
    }

    pub fn start(self) -> MockBlockchainClientServer {
        let requests = Arc::new(Mutex::new(vec![]));
        let mut server = MockBlockchainClientServer {
            port_or_local_addr: if self.run_on_docker {
                Right(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(172, 18, 0, 1),
                    self.port,
                )))
            } else {
                Left(self.port)
            },
            thread_info_opt: None,
            requests_arc: requests,
            responses: self.responses,
            notifier: self.notifier,
        };
        server.start();
        server
    }

    fn store_response_string(mut self, response_string: String) -> Self {
        match self.response_batch_opt.as_mut() {
            Some(response_batch) => response_batch.push(response_string),
            None => self.responses.push(response_string),
        }
        self
    }
}

struct MBCSThreadInfo {
    stopper: Sender<()>,
    join_handle: JoinHandle<()>,
}

pub struct MockBlockchainClientServer {
    port_or_local_addr: Either<u16, SocketAddr>,
    thread_info_opt: Option<MBCSThreadInfo>,
    requests_arc: Arc<Mutex<Vec<String>>>,
    responses: Vec<String>,
    notifier: Sender<()>,
}

impl UrlHolder for MockBlockchainClientServer {
    fn url(&self) -> String {
        format!("http://{}", self.local_addr().unwrap())
    }
}

impl Drop for MockBlockchainClientServer {
    fn drop(&mut self) {
        if let Some(thread_info) = self.thread_info_opt.take() {
            let _ = thread_info.stopper.try_send(());
            if let Err(e) = thread_info.join_handle.join() {
                let msg = match e.downcast_ref::<&'static str>() {
                    Some(m) => m.to_string(),
                    None => match e.downcast::<String>() {
                        Ok(m) => m.to_string(),
                        Err(e) => format!("{:?}", e),
                    },
                };
                if thread::panicking() {
                    eprintln!(
                        "MockBlockchainClientServer service thread also panicked: {}",
                        msg
                    );
                } else {
                    panic!("{}", msg);
                }
            }
        }
    }
}

impl MockBlockchainClientServer {
    pub fn builder(port: u16) -> MBCSBuilder {
        MBCSBuilder::new(port)
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests_arc.lock().unwrap().drain(..).collect()
    }

    pub fn start(&mut self) {
        let addr = match self.port_or_local_addr {
            Left(port) => SocketAddr::new(localhost(), port),
            Right(addr) => addr,
        };
        let listener = match TcpListener::bind(addr) {
            Ok(listener) => listener,
            Err(e) => panic!(
                "Error binding MBCS listener: did you remember to start the cluster first? ({:?})",
                e
            ),
        };
        listener.set_nonblocking(true).unwrap();
        self.port_or_local_addr = Right(listener.local_addr().unwrap());
        let requests_arc = self.requests_arc.clone();
        let mut responses: Vec<String> = self.responses.drain(..).collect();
        let (stopper_tx, stopper_rx) = unbounded();
        let notifier = self.notifier.clone();
        let join_handle = thread::spawn(move || {
            let conn = loop {
                if stopper_rx.try_recv().is_ok() {
                    return;
                }
                match listener.accept() {
                    Ok((conn, _)) => break conn,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                    Err(e) if e.kind() == ErrorKind::TimedOut => (),
                    Err(e) => panic!("MBCS accept() failed: {:?}", e),
                };
                thread::sleep(Duration::from_millis(100));
            };
            drop(listener);
            conn.set_nonblocking(true).unwrap();
            let mut conn_state = ConnectionState {
                conn,
                receive_buffer: [0u8; 16384],
                receive_buffer_occupied: 0,
                request_stage: RequestStage::Unparsed,
                request_accumulator: "".to_string(),
            };
            Self::thread_guts(
                &mut conn_state,
                &requests_arc,
                &mut responses,
                &stopper_rx,
                notifier,
            );
        });
        self.thread_info_opt = Some(MBCSThreadInfo {
            stopper: stopper_tx,
            join_handle,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self.port_or_local_addr {
            Left(_) => None,
            Right(local_addr) => Some(local_addr),
        }
    }

    fn thread_guts(
        conn_state: &mut ConnectionState,
        requests_arc: &Arc<Mutex<Vec<String>>>,
        responses: &mut Vec<String>,
        stopper_rx: &Receiver<()>,
        notifier_tx: Sender<()>,
    ) {
        loop {
            if stopper_rx.try_recv().is_ok() {
                break;
            }
            Self::receive_body(conn_state);
            let body_opt = Self::process_body(conn_state);
            match body_opt {
                Some(body) if body.is_empty() => break,
                Some(body) => {
                    {
                        let mut requests = requests_arc.lock().unwrap();
                        requests.push(body);
                    }
                    if responses.is_empty() {
                        break;
                    }
                    let response = responses.remove(0);
                    Self::send_body(conn_state, response);
                    let _ = notifier_tx.send(()); // receiver doesn't exist if test didn't set it up
                }
                None => (),
            };
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn receive_body(conn_state: &mut ConnectionState) {
        let offset = conn_state.receive_buffer_occupied;
        let limit = conn_state.receive_buffer.len();
        if conn_state.receive_buffer_occupied >= limit {
            panic!(
                "{}-byte receive buffer overflowed; increase size or fix test",
                conn_state.receive_buffer.len()
            );
        }
        let len = match conn_state
            .conn
            .read(&mut conn_state.receive_buffer[offset..limit])
        {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => return,
            Err(e) if e.kind() == ErrorKind::TimedOut => return,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return,
            Err(e) => panic!("{:?}", e),
        };
        conn_state.receive_buffer_occupied += len;
        let chunk = String::from_utf8_lossy(
            &conn_state.receive_buffer[offset..conn_state.receive_buffer_occupied],
        );
        conn_state.request_accumulator.extend(chunk.chars());
    }

    fn process_body(conn_state: &mut ConnectionState) -> Option<String> {
        loop {
            let original_stage = conn_state.request_stage.clone();
            let request_str_opt = match conn_state.request_stage {
                RequestStage::Unparsed => Self::handle_unparsed(conn_state),
                RequestStage::Parsed {
                    content_offset,
                    content_length,
                } => Self::handle_parsed(conn_state, content_offset, content_length),
            };
            match request_str_opt {
                Some(request_str) => return Some(request_str),
                None => {
                    if conn_state.request_stage == original_stage {
                        return None;
                    }
                }
            }
        }
    }

    fn handle_unparsed(conn_state: &mut ConnectionState) -> Option<String> {
        match conn_state.request_accumulator.find("\r\n\r\n") {
            None => None,
            Some(crlf_offset) => {
                let content_offset = crlf_offset + 4;
                match HTTP_VERSION_DETECTOR.captures(&conn_state.request_accumulator) {
                    Some(captures) => {
                        let http_version = captures.get(1).unwrap().as_str();
                        if http_version != "1.1" {
                            panic!("MBCS handles only HTTP version 1.1, not {}", http_version)
                        }
                    }
                    None => panic!("Request has no HTTP version"),
                }
                match CONTENT_LENGTH_DETECTOR.captures(&conn_state.request_accumulator) {
                    Some(captures) => {
                        let content_length =
                            captures.get(1).unwrap().as_str().parse::<usize>().unwrap();
                        conn_state.request_stage = RequestStage::Parsed {
                            content_offset,
                            content_length,
                        };
                        None
                    }
                    None => panic!("Request has no Content-Length header"),
                }
            }
        }
    }

    fn handle_parsed(
        conn_state: &mut ConnectionState,
        content_offset: usize,
        content_length: usize,
    ) -> Option<String> {
        let request_length = content_offset + content_length;
        if conn_state.request_accumulator.len() >= request_length {
            let request = conn_state.request_accumulator[0..request_length].to_string();
            // TODO: What happens if we have multibyte Unicode characters here?
            let delete_count = request.len();
            let remaining_len = conn_state.receive_buffer_occupied - delete_count;
            for i in 0..remaining_len {
                conn_state.receive_buffer[i] = conn_state.receive_buffer[i + delete_count];
            }
            conn_state.receive_buffer_occupied -= delete_count;
            conn_state.request_accumulator =
                conn_state.request_accumulator[delete_count..].to_string();
            conn_state.request_stage = RequestStage::Unparsed;
            Some(request)
        } else {
            None
        }
    }

    fn send_body(conn_state: &mut ConnectionState, response: String) {
        let http = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            response.len(),
            response
        );
        conn_state.conn.write_all(http.as_bytes()).unwrap();
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
enum RequestStage {
    Unparsed,
    Parsed {
        content_offset: usize,
        content_length: usize,
    },
}

struct ConnectionState {
    conn: TcpStream,
    receive_buffer: [u8; 16384],
    receive_buffer_occupied: usize,
    request_stage: RequestStage,
    request_accumulator: String,
}

// Test for this are located: multinode_integration_tests/src/mock_blockchain_client_server.rs
