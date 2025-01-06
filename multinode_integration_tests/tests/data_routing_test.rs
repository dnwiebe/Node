// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use itertools::Itertools;
use masq_lib::utils::index_of;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    default_consuming_wallet_info, make_consuming_wallet_info, MASQRealNode,
    NodeStartupConfigBuilder, STANDARD_CLIENT_TIMEOUT_MILLIS,
};
use native_tls::HandshakeError;
use native_tls::TlsConnector;
use native_tls::TlsStream;
use node_lib::proxy_server::protocol_pack::ServerImpersonator;
use node_lib::proxy_server::server_impersonator_http::ServerImpersonatorHttp;
use node_lib::test_utils::{handle_connection_error, read_until_timeout};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

#[test]
fn http_end_to_end_routing_test() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .build(),
    );

    let nodes = (0..6)
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(first_node.node_reference())
                    .chain(cluster.chain)
                    .build(),
            )
        })
        .collect::<Vec<MASQRealNode>>();

    thread::sleep(Duration::from_millis(500 * (nodes.len() as u64)));

    let last_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(nodes.last().unwrap().node_reference())
            .consuming_wallet_info(make_consuming_wallet_info("last_node"))
            .chain(cluster.chain)
            // This line is commented out because for some reason the installation of iptables-persistent hangs forever on
            // bullseye-slim. Its absence means that the NodeStartupConfigBuilder::open_firewall_port() function won't work, but
            // at the time of this comment it's used only in this one place, where it adds no value. So we decided to
            // comment it out and continue adding value rather than spending time getting this to work for no profit.
            //            .open_firewall_port(8080)
            .build(),
    );

    thread::sleep(Duration::from_millis(500));

    let mut client = last_node.make_client(8080, 5000);
    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let response = client.wait_for_chunk();

    assert_eq!(
        index_of(&response, &b"<h1>Example Domain</h1>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}

#[test]
fn http_end_to_end_routing_test_with_consume_and_originate_only_nodes() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .build(),
    );
    let _second_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(first_node.node_reference())
            .chain(cluster.chain)
            .build(),
    );
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::consume_only()
            .neighbor(first_node.node_reference())
            .chain(cluster.chain)
            .build(),
    );
    let _potential_exit_nodes = vec![0, 1, 2, 3, 4]
        .into_iter()
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::originate_only()
                    .neighbor(first_node.node_reference())
                    .chain(cluster.chain)
                    .build(),
            )
        })
        .collect_vec();

    thread::sleep(Duration::from_millis(1000));

    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let response = client.wait_for_chunk();

    assert_eq!(
        index_of(&response, &b"<h1>Example Domain</h1>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}

#[test]
#[should_panic(expected = "extracting node reference")]
fn consume_only_mode_rejects_dns_servers_parameter() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .build(),
    );
    let config = NodeStartupConfigBuilder::consume_only()
        .dns_servers(vec![IpAddr::from_str("1.1.1.1").unwrap()])
        .neighbor(first_node.node_reference())
        .chain(cluster.chain)
        .build();

    let _ = cluster.start_real_node(config);
}

#[test]
fn tls_end_to_end_routing_test() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .build(),
    );

    let nodes = (0..7)
        .map(|n| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .consuming_wallet_info(make_consuming_wallet_info(&format!("{}", n)))
                    .neighbor(first_node.node_reference())
                    .chain(cluster.chain)
                    .build(),
            )
        })
        .collect::<Vec<MASQRealNode>>();

    thread::sleep(Duration::from_millis(500 * (nodes.len() as u64)));

    let mut tls_stream = {
        let mut tls_stream: Option<TlsStream<TcpStream>> = None;
        let stream = TcpStream::connect(
            SocketAddr::from_str(&format!(
                "{}:{}",
                &nodes[5].node_addr().ip_addr().to_string(),
                "8443"
            ))
            .unwrap(),
        )
        .expect(&format!(
            "Could not connect to {}:8443",
            &nodes[5].node_addr().ip_addr().to_string()
        ));
        stream
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .expect("Could not set read timeout to 1000ms");
        let connector = TlsConnector::new().expect("Could not build TlsConnector");
        match connector.connect(
            "example.com",
            stream.try_clone().expect("Couldn't clone TcpStream"),
        ) {
            Ok(s) => {
                tls_stream = Some(s);
            }
            Err(HandshakeError::WouldBlock(interrupted_stream)) => {
                thread::sleep(Duration::from_millis(100));
                match interrupted_stream.handshake() {
                    Ok(stream) => tls_stream = Some(stream),
                    Err(e) => {
                        println!("connection error after interruption retry: {:?}", e);
                        handle_connection_error(stream);
                    }
                }
            }
            Err(e) => {
                println!("connection error: {:?}", e);
                handle_connection_error(stream);
            }
        }

        tls_stream.expect("Couldn't handshake")
    };
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();
    tls_stream
        .write(request.clone())
        .expect("Could not write request to TLS stream");
    let buf = read_until_timeout(&mut tls_stream);
    let _ = tls_stream.shutdown().is_ok(); // Can't do anything about an error here

    let response = String::from_utf8(Vec::from(&buf[..])).expect("Response is not UTF-8");
    assert_eq!(&response[9..15], &"200 OK"[..]);
    assert_eq!(
        response.contains("<h1>Example Domain</h1>"),
        true,
        "{}",
        response
    );
}

#[test]
fn http_routing_failure_produces_internal_error_response() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let neighbor_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .build(),
    );
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .consuming_wallet_info(default_consuming_wallet_info())
            .neighbor(neighbor_node.node_reference())
            .chain(cluster.chain)
            .build(),
    );
    thread::sleep(Duration::from_millis(1000));

    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);

    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let response = client.wait_for_chunk();

    let expected_response =
        ServerImpersonatorHttp {}.route_query_failure_response("www.example.com");

    assert_eq!(
        &expected_response,
        &response
            .into_iter()
            .take(expected_response.len())
            .collect::<Vec<u8>>(),
    );
}

#[test]
fn tls_routing_failure_produces_internal_error_response() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let neighbor = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .build(),
    );
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .consuming_wallet_info(default_consuming_wallet_info())
            .neighbor(neighbor.node_reference())
            .chain(cluster.chain)
            .build(),
    );
    let mut client = originating_node.make_client(8443, STANDARD_CLIENT_TIMEOUT_MILLIS);
    let client_hello = vec![
        0x16, // content_type: Handshake
        0x03, 0x03, // TLS 1.2
        0x00, 0x3F, // length
        0x01, // handshake_type: ClientHello
        0x00, 0x00, 0x3B, // length
        0x00, 0x00, // version: don't care
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // random: don't care
        0x00, // session_id_length
        0x00, 0x00, // cipher_suites_length
        0x00, // compression_methods_length
        0x00, 0x13, // extensions_length
        0x00, 0x00, // extension_type: server_name
        0x00, 0x0F, // extension_length
        0x00, 0x0D, // server_name_list_length
        0x00, // server_name_type
        0x00, 0x0A, // server_name_length
        b's', b'e', b'r', b'v', b'e', b'r', b'.', b'c', b'o', b'm', // server_name
    ];

    client.send_chunk(&client_hello);
    let response = client.wait_for_chunk();

    assert_eq!(
        vec![
            0x15, // alert
            0x03, 0x03, // TLS 1.2
            0x00, 0x02, // packet length
            0x02, // fatal alert
            0x50, // internal_error alert
        ],
        response
    )
}

#[test]
fn multiple_stream_zero_hop_test() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let zero_hop_node = cluster.start_real_node(
        NodeStartupConfigBuilder::zero_hop()
            .consuming_wallet_info(default_consuming_wallet_info())
            .chain(cluster.chain)
            .build(),
    );
    let mut one_client = zero_hop_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    let mut another_client = zero_hop_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);

    one_client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    another_client.send_chunk(b"GET /online/ HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Language: cs-CZ,cs;q=0.9,en;q=0.8,sk;q=0.7\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\nHost: whatever.neverssl.com\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n\r\n");

    let one_response = one_client.wait_for_chunk();
    let another_response = another_client.wait_for_chunk();

    assert_eq!(
        index_of(&one_response, &b"<h1>Example Domain</h1>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(one_response).unwrap()
    );
    assert_eq!(
        index_of(
            &another_response,
            &b"neverssl.com will never use SSL (also known as TLS)"[..],
        )
        .is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(another_response).unwrap()
    );
}
