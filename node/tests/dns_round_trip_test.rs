// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;
use crate::utils::CommandConfig;
use node_lib::entry_dns::packet_facade::PacketFacade;
use serial_test_derive::serial;
use std::net::UdpSocket;
use std::time::Duration;
use trust_dns::op::{OpCode, ResponseCode};
use trust_dns::rr::{DNSClass, RecordType};

#[test]
#[serial(port53)]
fn handles_two_consecutive_ipv4_dns_requests_integration() {
    let _node = utils::MASQNode::start_standard(
        "handles_two_consecutive_ipv4_dns_requests_integration",
        Some(CommandConfig::new().opt("--entry-dns")),
        true,
        true,
        false,
        true,
    );

    perform_ipv4_query();
    perform_ipv4_query();
}

#[test]
#[serial(port53)]
fn handles_consecutive_heterogeneous_dns_requests_integration() {
    let _node = utils::MASQNode::start_standard(
        "handles_consecutive_heterogeneous_dns_requests_integration",
        Some(CommandConfig::new().opt("--entry-dns")),
        true,
        true,
        false,
        true,
    );

    perform_ipv4_query();
    perform_ipv6_query();
    perform_ipv4_query();
}

fn perform_query(record_type: RecordType, rdata: &[u8]) {
    let mut buf: [u8; 1024] = [0; 1024];
    let length = {
        let mut facade = PacketFacade::new(&mut buf, 12);
        facade.set_transaction_id(0x1234);
        facade.set_query(true);
        facade.set_opcode(OpCode::Query.into());
        facade.set_recursion_desired(true);
        facade.add_query("www.domain.com", record_type.into(), DNSClass::IN.into());
        facade.get_length()
    };

    let socket = UdpSocket::bind(&format!("0.0.0.0:0")).expect("Couldn't bind socket");
    socket
        .connect(&format!("127.0.0.1:53"))
        .expect("Couldn't connect");
    let transmit_count = socket.send(&buf[..length]).expect("Couldn't send");
    assert_eq!(transmit_count, length);
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("Couldn't set read timeout");
    let receive_count = socket.recv(&mut buf).expect("Couldn't receive");

    {
        let facade = PacketFacade::new(&mut buf, receive_count);
        assert_eq!(Some(0x1234), facade.get_transaction_id());
        assert_eq!(Some(false), facade.is_query());
        assert_eq!(Some(false), facade.is_truncated());
        assert_eq!(Some(false), facade.is_authoritative_answer());
        assert_eq!(Some(true), facade.is_recursion_desired());
        assert_eq!(Some(true), facade.is_recursion_available());
        assert_eq!(Some(OpCode::Query.into()), facade.get_opcode());
        assert_eq!(Some(ResponseCode::NoError.low()), facade.get_rcode());
        let queries = facade.get_queries().unwrap();
        assert_eq!("www.domain.com", queries[0].get_query_name());
        assert_eq!(u16::from(record_type), queries[0].get_query_type());
        assert_eq!(u16::from(DNSClass::IN), queries[0].get_query_class());
        assert_eq!(1, queries.len());
        let answers = facade.get_answers().unwrap();
        assert_eq!("www.domain.com", answers[0].get_name());
        assert_eq!(3600, answers[0].get_time_to_live());
        assert_eq!(u16::from(record_type), answers[0].get_resource_type());
        assert_eq!(u16::from(DNSClass::IN), answers[0].get_resource_class());
        assert_eq!(rdata, answers[0].get_rdata());
        assert_eq!(1, answers.len());
    }
}

fn perform_ipv4_query() {
    perform_query(RecordType::A, &[127, 0, 0, 1]);
}

fn perform_ipv6_query() {
    perform_query(
        RecordType::AAAA,
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
}
