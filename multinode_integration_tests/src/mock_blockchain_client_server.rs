// Copyright (c) 2022, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

// TODO: GH-805
// The actual mock server has been migrated to masq_lib/src/test_utils/mock_blockchain_client_server.rs

#[cfg(test)]
mod tests {
    use crate::masq_node_cluster::{DockerHostSocketAddr, MASQNodeCluster};
    use crossbeam_channel::unbounded;
    use masq_lib::test_utils::mock_blockchain_client_server::{
        MockBlockchainClientServer, CONTENT_LENGTH_DETECTOR,
    };
    use masq_lib::utils::find_free_port;
    use serde_derive::{Deserialize, Serialize};
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpStream;
    use std::ops::Add;
    use std::thread;
    use std::time::{Duration, Instant};

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
            .ok_response("Thank you and good night", 40)
            .run_in_docker()
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
            .ok_response("Welcome, and thanks for coming!", 39)
            .ok_response("Thank you and good night", 40)
            .run_in_docker()
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
            .ok_response("irrelevant".to_string(), 42)
            .run_in_docker()
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
            .ok_response("irrelevant".to_string(), 42)
            .run_in_docker()
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
            .ok_response("irrelevant".to_string(), 42)
            .run_in_docker()
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
            .ok_response(1234u64, 40)
            .error(1234, "My tummy hurts", None as Option<()>)
            .end_batch()
            .ok_response(
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
            .run_in_docker()
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
            .ok_response(
                Person {
                    name: "Billy".to_string(),
                    age: 15,
                },
                42,
            )
            .run_in_docker()
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
