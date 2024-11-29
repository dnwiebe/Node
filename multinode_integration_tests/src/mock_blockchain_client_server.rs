// Copyright (c) 2022, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::{unbounded, Receiver, Sender};
use itertools::Either;
use itertools::Either::{Left, Right};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;

use crate::masq_node_cluster::DockerHostSocketAddr;
use crate::utils::UrlHolder;

lazy_static! {
    static ref CONTENT_LENGTH_DETECTOR: Regex =
        Regex::new(r"[Cc]ontent-[Ll]ength: *(\d+)\r\n").expect("Bad regular expression");
    static ref HTTP_VERSION_DETECTOR: Regex =
        Regex::new(r"HTTP/(\d\.\d)").expect("Bad regular expression");
}

pub struct MBCSBuilder {
    port: u16,
    response_batch_opt: Option<Vec<String>>,
    responses: Vec<String>,
    notifier: Sender<()>,
}

impl MBCSBuilder {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            response_batch_opt: None,
            responses: vec![],
            notifier: unbounded().0,
        }
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
            port_or_local_addr: Left(self.port),
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
        let addr = DockerHostSocketAddr::new(self.port_or_local_addr.unwrap_left());
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
                    if !responses.is_empty() {
                        let response = responses.remove(0);
                        Self::send_body(conn_state, response);
                    }
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

#[cfg(test)]
mod tests {
    use serde_derive::Deserialize;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::ops::Add;
    use std::time::{Duration, Instant};

    use crate::masq_node_cluster::MASQNodeCluster;
    use masq_lib::utils::find_free_port;

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Person {
        pub name: String,
        pub age: u8,
    }

    #[test]
    fn receives_request_in_multiple_chunks() {
        let _cluster = MASQNodeCluster::start();
        let port = find_free_port();
        let _subject = MockBlockchainClientServer::builder(port)
            .response("Thank you and good night", 40)
            .start();
        let mut client = connect(port);
        let chunks = vec![
            "POST /biddle HTTP/1.1\r\nCont".to_string(),
            "ent-Length: 4".to_string(),
            "8\r\nContent-Type: application/json\r\n".to_string(),
            "\r\n{\"jsonrpc\": \"2.0\", \"method\": ".to_string(),
            "\"method\", \"id\": 40".to_string(),
        ];
        chunks.into_iter().for_each(|chunk| {
            client.write(chunk.as_bytes()).unwrap();
            let result = receive_response_with_timeout(&mut client, Duration::from_millis(50));
            assert_eq!(result, None);
        });

        client.write(b"}").unwrap();

        let (_, body) = receive_response(&mut client);
        assert_eq!(
            body,
            r#"{"jsonrpc": "2.0", "result": "Thank you and good night", "id": 40}"#
        );
    }

    #[test]
    fn parses_out_multiple_requests_from_single_chunk() {
        let _cluster = MASQNodeCluster::start();
        let port = find_free_port();
        let _subject = MockBlockchainClientServer::builder(port)
            .response("Welcome, and thanks for coming!", 39)
            .response("Thank you and good night", 40)
            .start();
        let mut client = connect(port);
        client.write(b"POST /biddle HTTP/1.1\r\nContent-Length: 5\r\n\r\nfirstPOST /biddle HTTP/1.1\r\nContent-Length: 6\r\n\r\nsecond").unwrap();

        let (_, body) = receive_response(&mut client);
        assert_eq!(
            body,
            r#"{"jsonrpc": "2.0", "result": "Welcome, and thanks for coming!", "id": 39}"#
        );
        let (_, body) = receive_response(&mut client);
        assert_eq!(
            body,
            r#"{"jsonrpc": "2.0", "result": "Thank you and good night", "id": 40}"#
        );
    }

    #[test]
    #[should_panic(expected = "Request has no Content-Length header")]
    fn panics_if_given_a_request_without_a_content_length() {
        let _cluster = MASQNodeCluster::start();
        let port = find_free_port();
        let _subject = MockBlockchainClientServer::builder(port)
            .response("irrelevant".to_string(), 42)
            .start();
        let mut client = connect(port);
        let request = b"POST /biddle HTTP/1.1\r\n\r\nbody";

        client.write(request).unwrap();

        let _ = receive_response_with_timeout(&mut client, Duration::from_millis(250));
    }

    #[test]
    #[should_panic(expected = "Request has no HTTP version")]
    fn panics_if_http_version_is_missing() {
        let _cluster = MASQNodeCluster::start();
        let port = find_free_port();
        let _subject = MockBlockchainClientServer::builder(port)
            .response("irrelevant".to_string(), 42)
            .start();
        let mut client = connect(port);
        let request = b"GET /booga\r\nContent-Length: 4\r\n\r\nbody";

        client.write(request).unwrap();

        let _ = receive_response_with_timeout(&mut client, Duration::from_millis(250));
    }

    #[test]
    #[should_panic(expected = "MBCS handles only HTTP version 1.1, not 2.0")]
    fn panics_if_http_version_is_not_1_1() {
        let _cluster = MASQNodeCluster::start();
        let port = find_free_port();
        let _subject = MockBlockchainClientServer::builder(port)
            .response("irrelevant".to_string(), 42)
            .start();
        let mut client = connect(port);
        let request = b"GET /booga HTTP/2.0\r\nContent-Length: 4\r\n\r\nbody";

        client.write(request).unwrap();

        let _ = receive_response_with_timeout(&mut client, Duration::from_millis(250));
    }

    #[test]
    fn mbcs_works_for_responses_and_errors_both_inside_a_batch_and_outside() {
        let _cluster = MASQNodeCluster::start();
        let port = find_free_port();
        let (notifier, notified) = unbounded();
        let subject = MockBlockchainClientServer::builder(port)
            .notifier(notifier)
            .begin_batch()
            .response(1234u64, 40)
            .error(1234, "My tummy hurts", None as Option<()>)
            .end_batch()
            .response(
                Person {
                    name: "Billy".to_string(),
                    age: 15,
                },
                42,
            )
            .error(
                4321,
                "Taxation is theft!",
                Some(Person {
                    name: "Stanley".to_string(),
                    age: 37,
                }),
            )
            .start();
        let mut client = connect(port);

        let request = make_post(
            r#"{"jsonrpc": "2.0", "method": "first", "params": ["biddle", "de", "bee"], "id": 40}"#,
        );
        client.write(request.as_slice()).unwrap();

        let (response_header, response_body) = receive_response(&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq!(
            &response_body,
            r#"[{"jsonrpc": "2.0", "result": 1234, "id": 40}, {"jsonrpc": "2.0", "error": {"code": 1234, "message": "My tummy hurts"}}]"#
        );
        assert_eq!(notified.try_recv(), Ok(()));
        assert_eq!(notified.try_recv().is_err(), true);

        let request = make_post(r#"{"jsonrpc": "2.0", "method": "second", "id": 42}"#);
        client.write(request.as_slice()).unwrap();

        let (response_header, response_body) = receive_response(&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq!(
            &response_body,
            r#"{"jsonrpc": "2.0", "result": {"name":"Billy","age":15}, "id": 42}"#
        );
        assert_eq!(notified.try_recv(), Ok(()));
        assert_eq!(notified.try_recv().is_err(), true);

        let request = make_post(r#"{"jsonrpc": "2.0", "method": "third", "id": 42}"#);
        client.write(request.as_slice()).unwrap();

        let (response_header, response_body) = receive_response(&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq!(
            &response_body,
            r#"{"jsonrpc": "2.0", "error": {"code": 4321, "message": "Taxation is theft!", "data": {"name":"Stanley","age":37}}}"#
        );
        assert_eq!(notified.try_recv(), Ok(()));
        assert_eq!(notified.try_recv().is_err(), true);

        let requests = subject.requests();
        assert_eq!(requests, vec![
            "POST /biddle HTTP/1.1\r\nContent-Type: application-json\r\nContent-Length: 82\r\n\r\n{\"jsonrpc\": \"2.0\", \"method\": \"first\", \"params\": [\"biddle\", \"de\", \"bee\"], \"id\": 40}".to_string(),
            "POST /biddle HTTP/1.1\r\nContent-Type: application-json\r\nContent-Length: 48\r\n\r\n{\"jsonrpc\": \"2.0\", \"method\": \"second\", \"id\": 42}".to_string(),
            "POST /biddle HTTP/1.1\r\nContent-Type: application-json\r\nContent-Length: 47\r\n\r\n{\"jsonrpc\": \"2.0\", \"method\": \"third\", \"id\": 42}".to_string(),
        ])
    }

    #[test]
    fn mbcs_understands_real_world_request() {
        let _cluster = MASQNodeCluster::start();
        let port = find_free_port();
        let subject = MockBlockchainClientServer::builder(port)
            .response(
                Person {
                    name: "Billy".to_string(),
                    age: 15,
                },
                42,
            )
            .start();
        let mut client = connect(port);
        let request =
            b"POST / HTTP/1.1\r\ncontent-type: application/json\r\nuser-agent: web3.rs\r\nhost: 172.18.0.1:32768\r\ncontent-length: 308\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"eth_getLogs\",\"params\":[{\"address\":\"0x59882e4a8f5d24643d4dda422922a870f1b3e664\",\"fromBlock\":\"0x3e8\",\"toBlock\":\"latest\",\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\",null,\"0x00000000000000000000000027d9a2ac83b493f88ce9b4532edcf74e95b9788d\"]}],\"id\":0}";

        client.write(request).unwrap();

        let (response_header, response_body) = receive_response(&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq!(
            &response_body,
            r#"{"jsonrpc": "2.0", "result": {"name":"Billy","age":15}, "id": 42}"#
        );
        let requests = subject.requests();
        assert_eq!(requests, vec![
            "POST / HTTP/1.1\r\ncontent-type: application/json\r\nuser-agent: web3.rs\r\nhost: 172.18.0.1:32768\r\ncontent-length: 308\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"eth_getLogs\",\"params\":[{\"address\":\"0x59882e4a8f5d24643d4dda422922a870f1b3e664\",\"fromBlock\":\"0x3e8\",\"toBlock\":\"latest\",\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\",null,\"0x00000000000000000000000027d9a2ac83b493f88ce9b4532edcf74e95b9788d\"]}],\"id\":0}".to_string()
        ])
    }

    fn connect(port: u16) -> TcpStream {
        let deadline = Instant::now().add(Duration::from_secs(1));
        let addr = DockerHostSocketAddr::new(port);
        loop {
            thread::sleep(Duration::from_millis(100));
            match TcpStream::connect(&addr) {
                Ok(client) => {
                    client.set_nonblocking(true).unwrap();
                    return client;
                }
                Err(e) => eprintln!("Mock server not ready yet ({:?})", e),
            }
            if Instant::now().gt(&deadline) {
                panic!("MockBlockchainClientServer never started");
            }
        }
    }

    fn receive_response(client: &mut TcpStream) -> (String, String) {
        match receive_response_with_timeout(client, Duration::from_secs(10)) {
            Some(result) => result,
            None => panic!("Timed out waiting for response from server"),
        }
    }

    fn receive_response_with_timeout(
        client: &mut TcpStream,
        timeout: Duration,
    ) -> Option<(String, String)> {
        let mut buffer = [0u8; 1024];
        let mut response_str = String::new();
        let mut expected_length_opt = None;
        let deadline = Instant::now().add(timeout);
        loop {
            match client.read(&mut buffer) {
                Ok(len) => {
                    let string: String = String::from_utf8(buffer[0..len].to_vec()).unwrap();
                    response_str.extend(string.chars());
                    match response_str.find("\r\n\r\n") {
                        Some(index) => {
                            let body_length_str = CONTENT_LENGTH_DETECTOR
                                .captures(&response_str)
                                .unwrap()
                                .get(1)
                                .unwrap();
                            let body_length = body_length_str.as_str().parse::<usize>().unwrap();
                            expected_length_opt = Some(index + 2 + body_length);
                        }
                        None => (),
                    }
                    if let Some(expected_length) = expected_length_opt {
                        if response_str.len() >= expected_length {
                            break;
                        }
                    }
                }
                Err(e)
                    if (e.kind() == ErrorKind::TimedOut) || (e.kind() == ErrorKind::WouldBlock) =>
                {
                    ()
                }
                Err(e) => panic!("Error waiting for response from server: {:?}", e),
            }
            if Instant::now().gt(&deadline) {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let parts = response_str.splitn(2, "\r\n\r\n").collect::<Vec<&str>>();
        Some((parts[0].to_string(), parts[1].to_string()))
    }

    fn verify_response_header(response_header: &str, response_body: &str) {
        assert_eq!(
            response_header.contains("HTTP/1.1 200 OK\r\n"),
            true,
            "{}",
            response_header
        );
        assert_eq!(
            response_header.contains("Content-Type: application/json"),
            true,
            "{}",
            response_header
        );
        assert_eq!(
            response_header.contains(format!("Content-Length: {}", response_body.len()).as_str()),
            true,
            "{}",
            response_header
        );
    }

    fn make_post(body: &str) -> Vec<u8> {
        format!(
            "POST /biddle HTTP/1.1\r\nContent-Type: application-json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
            .into_bytes()
    }
}
