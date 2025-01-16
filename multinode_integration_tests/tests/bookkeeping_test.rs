// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use multinode_integration_tests_lib::masq_node::{MASQNode, NodeReference};
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    make_consuming_wallet_info, make_earning_wallet_info, MASQRealNode, NodeStartupConfigBuilder,
    STANDARD_CLIENT_TIMEOUT_MILLIS,
};
use multinode_integration_tests_lib::utils::{payable_dao, receivable_dao};
use node_lib::accountant::db_access_objects::payable_dao::PayableAccount;
use node_lib::accountant::db_access_objects::receivable_dao::ReceivableAccount;
use node_lib::accountant::db_access_objects::utils::CustomQuery;
use node_lib::sub_lib::wallet::Wallet;
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, SystemTime};

#[test]
fn provided_and_consumed_services_are_recorded_in_databases() {
    let mut cluster = MASQNodeCluster::start().unwrap();

    let originating_node = start_lonely_real_node(&mut cluster);
    let non_originating_nodes = (0..6)
        .into_iter()
        .map(|_| start_real_node(&mut cluster, originating_node.node_reference()))
        .collect::<Vec<MASQRealNode>>();

    thread::sleep(Duration::from_secs(10));

    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    client.set_timeout(Duration::from_secs(10));
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();

    client.send_chunk(request);
    let response = String::from_utf8(client.wait_for_chunk()).unwrap();
    assert!(
        response.contains("<h1>Example Domain</h1>"),
        "Not from example.com:\n{}",
        response
    );

    // get all payables from originating node
    let payables = non_pending_payables(&originating_node);

    // Waiting until the serving nodes have finished accruing their receivables
    thread::sleep(Duration::from_secs(10));

    // get all receivables from all other nodes
    let receivable_balances = non_originating_nodes
        .iter()
        .flat_map(|node| {
            receivables(node)
                .into_iter()
                .map(move |receivable_account| {
                    (node.earning_wallet(), receivable_account.balance_wei)
                })
        })
        .collect::<HashMap<Wallet, i128>>();

    // check that each payable has a receivable
    assert_eq!(
        payables.len(),
        receivable_balances.len(),
        "Lengths of payables and receivables should match.\nPayables: {:?}\nReceivables: {:?}",
        payables,
        receivable_balances
    );
    assert!(
        receivable_balances.len() >= 3, // minimum service list: route, route, exit.
        "not enough receivables found {:?}",
        receivable_balances
    );

    payables.iter().for_each(|payable| {
        assert_eq!(
            payable.balance_wei,
            *receivable_balances.get(&payable.wallet).unwrap() as u128,
        );
    });
}

fn non_pending_payables(node: &MASQRealNode) -> Vec<PayableAccount> {
    let payable_dao = payable_dao(node.name());
    payable_dao.non_pending_payables()
}

fn receivables(node: &MASQRealNode) -> Vec<ReceivableAccount> {
    let receivable_dao = receivable_dao(node.name());
    receivable_dao
        .custom_query(CustomQuery::RangeQuery {
            min_age_s: 0,
            max_age_s: i64::MAX as u64,
            min_amount_gwei: i64::MIN,
            max_amount_gwei: i64::MAX,
            timestamp: SystemTime::now(),
        })
        .unwrap_or_default()
}

pub fn start_lonely_real_node(cluster: &mut MASQNodeCluster) -> MASQRealNode {
    let index = cluster.next_index();
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .earning_wallet_info(make_earning_wallet_info(&index.to_string()))
            .consuming_wallet_info(make_consuming_wallet_info(&index.to_string()))
            .chain(cluster.chain)
            .build(),
    )
}

pub fn start_real_node(cluster: &mut MASQNodeCluster, neighbor: NodeReference) -> MASQRealNode {
    let index = cluster.next_index();
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor)
            .earning_wallet_info(make_earning_wallet_info(&index.to_string()))
            .chain(cluster.chain)
            .build(),
    )
}
