// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::test_utils::utils::TEST_DEFAULT_MULTINODE_CHAIN;
use masq_lib::utils::{find_free_port, index_of};
use multinode_integration_tests_lib::masq_mock_node::MASQMockNode;
use multinode_integration_tests_lib::masq_node::{MASQNode, PortSelector};
use multinode_integration_tests_lib::masq_node_client::MASQNodeClient;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    make_consuming_wallet_info, MASQRealNode, NodeStartupConfigBuilder,
    STANDARD_CLIENT_TIMEOUT_MILLIS,
};
use multinode_integration_tests_lib::neighborhood_constructor::construct_neighborhood;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::neighborhood::neighborhood_database::NeighborhoodDatabase;
use node_lib::neighborhood::node_record::NodeRecord;
use node_lib::neighborhood::AccessibleGossipRecord;
use node_lib::sub_lib::cryptde::{CryptDE, PublicKey};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::hopper::{
    ExpiredCoresPackage, IncipientCoresPackage, MessageType, MessageTypeLite,
};
use node_lib::sub_lib::neighborhood::{Hops, RatePack, DEFAULT_RATE_PACK};
use node_lib::sub_lib::proxy_client::{ClientResponsePayload_0v1, DnsResolveFailure_0v1};
use node_lib::sub_lib::route::Route;
use node_lib::sub_lib::sequence_buffer::SequencedPacket;
use node_lib::sub_lib::versioned_data::VersionedData;
use node_lib::test_utils::assert_string_contains;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

const EXAMPLE_HTML_RESPONSE: &str = "<!doctype html>
    <html>
        <head><title>Example Domain</title></head>
        <body>
            <div>
               <h1>Example Domain</h1>
               <p>This domain is for use in illustrative examples in documents. You may use this
               domain in literature without prior coordination or asking for permission.</p>
            </div>
        </body>
    </html>";

#[test]
#[ignore] // Should be removed by SC-811/GH-158
fn neighborhood_notified_of_newly_missing_node() {
    // Set up three-Node network, and add a mock witness Node.
    let mut cluster = MASQNodeCluster::start().unwrap();
    let chain = cluster.chain;
    let neighbor = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .fake_public_key(&PublicKey::new(&[1, 2, 3, 4]))
            .chain(chain)
            .build(),
    );
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor.node_reference())
            .fake_public_key(&PublicKey::new(&[2, 3, 4, 5]))
            .chain(chain)
            .build(),
    );
    let _staying_up_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor.node_reference())
            .fake_public_key(&PublicKey::new(&[3, 4, 5, 6]))
            .chain(chain)
            .build(),
    );
    let disappearing_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor.node_reference())
            .fake_public_key(&PublicKey::new(&[4, 5, 6, 7]))
            .chain(chain)
            .build(),
    );
    let witness_node = cluster
        .start_mock_node_with_public_key(vec![find_free_port()], &PublicKey::new(&[5, 6, 7, 8]));
    witness_node.transmit_debut(&originating_node).unwrap();
    let (introductions, _) = witness_node
        .wait_for_gossip(Duration::from_millis(1000))
        .unwrap();
    assert!(
        introductions.node_records.len() > 1,
        "Should have been introductions, but wasn't: {}",
        introductions.to_dot_graph(
            (
                originating_node.main_public_key(),
                &Some(originating_node.node_addr()),
            ),
            (
                witness_node.main_public_key(),
                &Some(witness_node.node_addr()),
            ),
        )
    );

    // Kill one of the Nodes--not the originating Node and not the witness Node.
    cluster.stop_node(disappearing_node.name());

    //Establish a client on the originating Node and send some ill-fated traffic.
    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    client.send_chunk("GET http://example.com HTTP/1.1\r\n\r\n".as_bytes());

    // Now direct the witness Node to wait for Gossip about the disappeared Node.
    let (disappearance_gossip, _) = witness_node
        .wait_for_gossip(Duration::from_secs(130))
        .unwrap();

    let dot_graph = disappearance_gossip.to_dot_graph(
        (
            originating_node.main_public_key(),
            &Some(originating_node.node_addr()),
        ),
        (
            witness_node.main_public_key(),
            &Some(witness_node.node_addr()),
        ),
    );
    assert_eq!(
        3,
        disappearance_gossip.node_records.len(),
        "Should have had three records: {}",
        dot_graph
    );
    let disappearance_agrs: Vec<AccessibleGossipRecord> = disappearance_gossip.try_into().unwrap();
    let originating_node_agr = disappearance_agrs
        .into_iter()
        .find(|agr| &agr.inner.public_key == originating_node.main_public_key())
        .unwrap();
    assert!(
        !originating_node_agr
            .inner
            .neighbors
            .contains(&disappearing_node.main_public_key(),),
        "Originating Node {} should not be connected to the disappeared Node {}, but is: {}",
        originating_node.main_public_key(),
        disappearing_node.main_public_key(),
        dot_graph
    );
}

#[test]
fn dns_resolution_failure_first_automatic_retry_succeeds() {
    /* Mock_node_good_exit <-- Originating_node --> Mock_node_bad_exit */
    let mut cluster = MASQNodeCluster::start().unwrap();
    let (originating_node, bad_exit_node, good_exit_node) = {
        let originating_node: NodeRecord = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&originating_node);
        let mut bad_exit_node_record = make_node_record(4567, true);
        let good_exit_node_record = make_node_record(5678, true);
        let low_rate_pack = cheaper_rate_pack(&good_exit_node_record.inner.rate_pack, 100);
        bad_exit_node_record.inner.rate_pack = low_rate_pack;
        let bad_exit_node_public_key = db.add_node(bad_exit_node_record).unwrap();
        let good_exit_node_public_key = db.add_node(good_exit_node_record).unwrap();
        db.add_arbitrary_full_neighbor(originating_node.public_key(), &bad_exit_node_public_key);
        db.add_arbitrary_full_neighbor(originating_node.public_key(), &good_exit_node_public_key);
        let (_, originating_node, mut node_map) =
            construct_neighborhood(&mut cluster, db, vec![], |builder| {
                builder.min_hops(Hops::OneHop).build()
            });
        let bad_exit_node = node_map.remove(&bad_exit_node_public_key).unwrap();
        let good_exit_node = node_map.remove(&good_exit_node_public_key).unwrap();
        (originating_node, bad_exit_node, good_exit_node)
    };
    let masquerader = JsonMasquerader::new();
    let originating_node_alias_cryptde = CryptDENull::from(
        originating_node.alias_public_key(),
        TEST_DEFAULT_MULTINODE_CHAIN,
    );
    let mut client = originating_node.make_client(8080, 10000);
    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let expired_cores_package = bad_exit_node
        .wait_for_specific_package(
            MessageTypeLite::ClientRequest,
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    let dns_fail_pkg = make_package_for_client(
        expired_cores_package.remaining_route.clone(),
        expired_cores_package,
        &originating_node_alias_cryptde,
        None,
        MessageTypeLite::DnsResolveFailed,
    );
    bad_exit_node
        .transmit_package(
            bad_exit_node.port_list()[0],
            dns_fail_pkg,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    let expired_cores_package = good_exit_node
        .wait_for_specific_package(
            MessageTypeLite::ClientRequest,
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    let sequenced_packet = SequencedPacket::new(EXAMPLE_HTML_RESPONSE.as_bytes().to_vec(), 0, true);
    let client_response_pkg = make_package_for_client(
        expired_cores_package.remaining_route.clone(),
        expired_cores_package,
        &originating_node_alias_cryptde,
        Some(sequenced_packet),
        MessageTypeLite::ClientResponse,
    );

    good_exit_node
        .transmit_package(
            good_exit_node.port_list()[0],
            client_response_pkg,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();

    let response = client.wait_for_chunk();
    assert_eq!(
        index_of(&response, &b"<h1>Example Domain</h1>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}

#[test]
fn dns_resolution_failure_with_real_nodes() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .consuming_wallet_info(make_consuming_wallet_info("first_node"))
            .chain(cluster.chain)
            .build(),
    );
    let nodes = (0..5)
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
    let mut client = first_node.make_client(8080, 2 * 60_000);

    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.nonexistent.com\r\n\r\n");

    let response = client.wait_for_chunk();
    assert_eq!(
        index_of(&response, &b"<h2>Title: DNS Resolution Problem</h2>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response.clone()).unwrap()
    );
    assert_eq!(
        index_of(
            &response,
            &b"<h3>Subtitle: Exit Nodes couldn't resolve \"www.nonexistent.com\"</h3>"[..]
        )
        .is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}

#[test]
fn dns_resolution_failure_for_wildcard_ip_with_real_nodes() {
    let dns_server_that_fails = Ipv4Addr::new(1, 1, 1, 3).into();
    let mut cluster = MASQNodeCluster::start().unwrap();
    let exit_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .consuming_wallet_info(make_consuming_wallet_info("exit_node"))
            .dns_servers(vec![dns_server_that_fails])
            .build(),
    );
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(exit_node.node_reference())
            .consuming_wallet_info(make_consuming_wallet_info("originating_node"))
            .chain(cluster.chain)
            .min_hops(Hops::OneHop)
            .build(),
    );

    thread::sleep(Duration::from_millis(1000));
    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.adomainthatdoesntexist.com\r\n\r\n");
    let response = client.wait_for_chunk();

    assert_eq!(
        index_of(&response, &b"<h2>Title: DNS Resolution Problem</h2>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response.clone()).unwrap()
    );
    assert_eq!(
        index_of(&response, &b"<p>DNS Failure, We have tried multiple Exit Nodes and all have failed to resolve this address www.adomainthatdoesntexsit.com</p>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}

#[test]
fn dns_resolution_failure_no_longer_blacklists_exit_node_for_all_hosts() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    // Make network:
    //  +--> node_4  +--> node_3
    //  |            |
    // originating_node --> node_1
    //  |            |
    //  +--> node_2  +--> most_expensive_node
    let (originating_node, node_list) = {
        let originating_node: NodeRecord = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&originating_node);
        let node_pub_key_list = (1..=4)
            .into_iter()
            .map(|i| {
                let nonce = (i + 1) * 1000 + (i + 2) * 100 + (i + 3) * 10 + (i + 4);
                let decrement = 5000 - (i * 1000);
                let mut exit_node = make_node_record(nonce, true);
                exit_node.inner.rate_pack = cheaper_rate_pack(&DEFAULT_RATE_PACK, decrement);
                let exit_node_key = db.add_node(exit_node).unwrap();
                db.add_arbitrary_full_neighbor(originating_node.public_key(), &exit_node_key);
                exit_node_key
            })
            .collect::<Vec<PublicKey>>();
        // The most expensive node should be untouched
        let mut most_expensive_exit_node = make_node_record(6969, true);
        most_expensive_exit_node.inner.rate_pack = DEFAULT_RATE_PACK;
        let most_expensive_exit_node_key = db.add_node(most_expensive_exit_node).unwrap();
        db.add_arbitrary_full_neighbor(
            originating_node.public_key(),
            &most_expensive_exit_node_key,
        );
        let (_, originating_node, mut node_map) =
            construct_neighborhood(&mut cluster, db, vec![], |builder| {
                builder.min_hops(Hops::OneHop).build()
            });
        let node_list = node_pub_key_list
            .iter()
            .map(|pub_key| node_map.remove(pub_key).unwrap())
            .collect::<Vec<MASQMockNode>>();
        (originating_node, node_list)
    };
    let mut client: MASQNodeClient = originating_node.make_client(8080, 5000);
    let masquerader = JsonMasquerader::new();
    let originating_node_alias_cryptde = CryptDENull::from(
        &originating_node.alias_public_key(),
        TEST_DEFAULT_MULTINODE_CHAIN,
    );
    let originating_node_socket_address = originating_node.socket_addr(PortSelector::First);
    client.send_chunk("GET / HTTP/1.1\r\nHost: nonexistent.com\r\n\r\n".as_bytes());
    for node in &node_list {
        let expired_cores_package = node
            .wait_for_specific_package(
                MessageTypeLite::ClientRequest,
                originating_node_socket_address,
            )
            .unwrap();
        let dns_fail_pkg = make_package_for_client(
            expired_cores_package.remaining_route.clone(),
            expired_cores_package,
            &originating_node_alias_cryptde,
            None,
            MessageTypeLite::DnsResolveFailed,
        );
        node.transmit_package(
            node.port_list()[0],
            dns_fail_pkg,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    }
    let dns_error_response: Vec<u8> = client.wait_for_chunk();
    let dns_error_response_str = String::from_utf8(dns_error_response).unwrap();
    assert_string_contains(&dns_error_response_str, "<h1>Error 503</h1>");
    assert_string_contains(
        &dns_error_response_str,
        "<h2>Title: DNS Resolution Problem</h2>",
    );
    assert_string_contains(
        &dns_error_response_str,
        "<h3>Subtitle: Exit Nodes couldn't resolve \"nonexistent.com\"</h3>",
    );
    assert_string_contains(
        &dns_error_response_str,
        &format!(
            "<p>DNS Failure, We have tried multiple Exit Nodes and all have failed to resolve this address nonexistent.com</p>"
        ),
    );

    client.send_chunk("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes());
    let cheapest_node = node_list.first().unwrap();
    let cheapest_node_expired_cores_package = cheapest_node
        .wait_for_specific_package(
            MessageTypeLite::ClientRequest,
            originating_node_socket_address,
        )
        .unwrap();
    assert_eq!(
        cheapest_node_expired_cores_package.immediate_neighbor,
        originating_node_socket_address
    );
}

fn cheaper_rate_pack(base_rate_pack: &RatePack, decrement: u16) -> RatePack {
    let mut result = *base_rate_pack;
    result.exit_byte_rate -= decrement as u64;
    result.exit_service_rate -= decrement as u64;
    result
}

fn make_package_for_client(
    route: Route,
    expired_cores_package: ExpiredCoresPackage<MessageType>,
    destination_alias_cryptde: &dyn CryptDE,
    sequenced_packet_opt: Option<SequencedPacket>,
    message_type_lite: MessageTypeLite,
) -> IncipientCoresPackage {
    let stream_key = match expired_cores_package.payload {
        MessageType::ClientRequest(vdata) => {
            vdata
                .extract(&node_lib::sub_lib::migrations::client_request_payload::MIGRATIONS)
                .unwrap()
                .stream_key
        }
        x => panic!("Expected ClientRequest, got {:?}", x),
    };
    let payload = match message_type_lite {
        MessageTypeLite::ClientResponse => {
            let client_response_vdata = VersionedData::new(
                &node_lib::sub_lib::migrations::client_response_payload::MIGRATIONS,
                &ClientResponsePayload_0v1 {
                    stream_key,
                    sequenced_packet: sequenced_packet_opt.unwrap(),
                },
            );
            MessageType::ClientResponse(client_response_vdata)
        }
        MessageTypeLite::DnsResolveFailed => {
            let dns_fail_vdata = VersionedData::new(
                &node_lib::sub_lib::migrations::dns_resolve_failure::MIGRATIONS,
                &DnsResolveFailure_0v1 { stream_key },
            );
            MessageType::DnsResolveFailed(dns_fail_vdata)
        }
        _ => {
            panic!("Not implemented");
        }
    };
    IncipientCoresPackage::new(
        destination_alias_cryptde,
        route,
        payload,
        destination_alias_cryptde.public_key(),
    )
    .unwrap()
}
