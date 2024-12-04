// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command::Command;
use crate::masq_node::{MASQNode, MASQNodeUtils};
use crate::masq_real_node::MASQRealNode;
use masq_lib::test_utils::utils::TEST_DEFAULT_MULTINODE_CHAIN;
use masq_lib::utils::NeighborhoodModeLight;
use node_lib::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoReal};
use node_lib::accountant::db_access_objects::receivable_dao::{ReceivableDao, ReceivableDaoReal};
use node_lib::database::db_initializer::{
    DbInitializationConfig, DbInitializer, DbInitializerReal, ExternalData,
};
use node_lib::database::rusqlite_wrappers::ConnectionWrapper;
use node_lib::db_config::config_dao::{ConfigDao, ConfigDaoReal};
use node_lib::neighborhood::node_record::NodeRecordInner_0v1;
use node_lib::neighborhood::AccessibleGossipRecord;
use node_lib::sub_lib::cryptde::{CryptData, PlainData};
use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{io, thread};

pub fn send_chunk(stream: &mut TcpStream, chunk: &[u8]) {
    stream
        .write_all(chunk)
        .unwrap_or_else(|_| panic!("Writing {} bytes", chunk.len()));
}

pub fn wait_for_chunk(stream: &mut TcpStream, timeout: &Duration) -> Result<Vec<u8>, io::Error> {
    let mut output: Vec<u8> = vec![];
    let mut buf: [u8; 65536] = [0; 65536];
    let mut begin = Instant::now();
    loop {
        let latency_so_far = Instant::now().duration_since(begin);
        if latency_so_far.ge(timeout) {
            if output.is_empty() {
                return Err(io::Error::from(ErrorKind::TimedOut));
            } else {
                // We got exactly buflen bytes in one chunk, so it looked like more was coming.
                // But we waited the full timeout for the rest of the data and didn't receive it,
                // so here's what we have; we hope it's complete.
                eprintln!("Received exactly {} bytes, timed out after waiting {:?} for more; assuming completion", output.len(), timeout);
                return Ok(output);
            }
        }

        match stream.read(&mut buf) {
            Ok(n) if n == buf.len() => {
                begin = Instant::now();
                output.extend(buf.iter())
            }
            Ok(n) => {
                output.extend(buf[0..n].iter());
                return Ok(output);
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                eprintln!("Couldn't read chunk; waiting for 100ms to retry");
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn database_conn(node_name: &str) -> Box<dyn ConnectionWrapper> {
    let db_initializer = DbInitializerReal::default();
    let path = std::path::PathBuf::from(node_chain_specific_data_directory(node_name));
    db_initializer
        .initialize(
            &path,
            DbInitializationConfig::create_or_migrate(ExternalData {
                chain: TEST_DEFAULT_MULTINODE_CHAIN,
                neighborhood_mode: NeighborhoodModeLight::Standard,
                db_password_opt: None,
            }),
        )
        .unwrap()
}

pub fn node_chain_specific_data_directory(node_name: &str) -> String {
    MASQRealNode::node_home_dir(&MASQNodeUtils::find_project_root(), node_name)
}

pub fn config_dao(node_name: &str) -> Box<dyn ConfigDao> {
    Box::new(ConfigDaoReal::new(database_conn(node_name)))
}

pub fn payable_dao(node_name: &str) -> Box<dyn PayableDao> {
    Box::new(PayableDaoReal::new(database_conn(node_name)))
}

pub fn receivable_dao(node_name: &str) -> Box<dyn ReceivableDao> {
    Box::new(ReceivableDaoReal::new(database_conn(node_name)))
}

pub fn wait_for_shutdown(stream: &mut TcpStream, timeout: &Duration) -> Result<(), io::Error> {
    stream.set_read_timeout(Some(*timeout)).unwrap();
    let mut buf = [0u8; 1];
    match stream.peek(&mut buf) {
        Ok(0) => Ok(()),
        Ok(_) => Err(io::Error::from(ErrorKind::Interrupted)),
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => Err(io::Error::from(e.kind())),
        Err(ref e) if e.kind() == ErrorKind::ConnectionReset => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn open_all_file_permissions(dir: PathBuf) {
    match Command::new(
        "chmod",
        Command::strings(vec!["-R", "777", dir.to_str().unwrap()]),
    )
    .wait_for_exit()
    {
        0 => (),
        _ => panic!(
            "Couldn't chmod 777 files in directory {}",
            dir.to_str().unwrap()
        ),
    }
}

impl From<&dyn MASQNode> for AccessibleGossipRecord {
    fn from(masq_node: &dyn MASQNode) -> Self {
        let cryptde = masq_node.signing_cryptde().unwrap_or_else (|| panic! ("You can only make an AccessibleGossipRecord from a MASQRealNode if it has a CryptDENull, not a CryptDEReal."));
        let mut agr = AccessibleGossipRecord {
            inner: NodeRecordInner_0v1 {
                public_key: masq_node.main_public_key().clone(),
                earning_wallet: masq_node.earning_wallet(),
                rate_pack: masq_node.rate_pack(),
                neighbors: BTreeSet::new(),
                accepts_connections: masq_node.accepts_connections(),
                routes_data: masq_node.routes_data(),
                version: 0,
            },
            node_addr_opt: Some(masq_node.node_addr()),
            signed_gossip: PlainData::new(b""),
            signature: CryptData::new(b""),
        };
        agr.regenerate_signed_gossip(cryptde);
        agr
    }
}
