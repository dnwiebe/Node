// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use log::Level;
use masq_lib::messages::{FromMessageBody, ScanType, ToMessageBody, UiScanRequest, UiScanResponse};
use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
use masq_lib::test_utils::utils::{is_running_under_github_actions, LogObject, UrlHolder};
use masq_lib::utils::find_free_port;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node::MASQNodeUtils;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    ConsumingWalletInfo, NodeStartupConfigBuilder,
};
use multinode_integration_tests_lib::utils::{
    config_dao, node_chain_specific_data_directory, open_all_file_permissions, receivable_dao,
};
use node_lib::accountant::db_access_objects::utils::CustomQuery;
use node_lib::sub_lib::wallet::Wallet;
use std::ops::Add;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

#[test]
fn debtors_are_credited_once_but_not_twice() {
    if is_running_under_github_actions() {
        eprintln!("This test doesn't pass under GitHub Actions; don't know why");
        return;
    }
    let mbcs_port = find_free_port();
    let ui_port = find_free_port();
    let mut cluster = MASQNodeCluster::start().unwrap();
    // Create and initialize mock blockchain client: prepare a receivable at block 2000
    eprintln!("Setting up mock blockchain client");
    let blockchain_client_server = MBCSBuilder::new(mbcs_port)
        .response("0x5DC", 1) // eth_blockNumber 1500
        .response(
            vec![LogObject {
                removed: false,
                log_index: Some("0x20".to_string()),
                transaction_index: Some("0x30".to_string()),
                transaction_hash: Some(
                    "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                ),
                block_hash: Some(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                ),
                block_number: Some("0x7D0".to_string()), // 2000 decimal
                address: "0x3333333333333333333333333333333333333333".to_string(),
                data: "0x000000000000000000000000000000000000000000000000000000003b5dc100"
                    .to_string(),
                topics: vec![
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                        .to_string(),
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                        .to_string(),
                ],
            }],
            1,
        )
        .run_in_docker()
        .start();
    // Start a real Node pointing at the mock blockchain client with a start block of 1000
    let node_config = NodeStartupConfigBuilder::standard()
        .log_level(Level::Debug)
        .scans(false)
        .blockchain_service_url(blockchain_client_server.url())
        .ui_port(ui_port)
        .build();
    let (node_name, node_index) = cluster.prepare_real_node(&node_config);
    let chain_specific_dir = node_chain_specific_data_directory(&node_name);
    open_all_file_permissions(PathBuf::from(chain_specific_dir));
    {
        let config_dao = config_dao(&node_name);
        config_dao
            .set("start_block", Some("1000".to_string()))
            .unwrap();
    }
    {
        let receivable_dao = receivable_dao(&node_name);
        receivable_dao
            .more_money_receivable(
                SystemTime::UNIX_EPOCH.add(Duration::from_secs(15_000_000)),
                &Wallet::new("0x3333333333333333333333333333333333333333"),
                9_000_000_000,
            )
            .unwrap();
    }
    // Use the receivable DAO to verify that the receivable's balance has been initialized
    {
        let receivable_dao = receivable_dao(&node_name);
        let receivable_accounts = receivable_dao
            .custom_query(CustomQuery::RangeQuery {
                min_age_s: 0,
                max_age_s: i64::MAX as u64,
                min_amount_gwei: 0,
                max_amount_gwei: i64::MAX,
                timestamp: SystemTime::now(),
            })
            .unwrap_or_default();
        assert_eq!(receivable_accounts.len(), 1);
        assert_eq!(receivable_accounts[0].balance_wei, 9_000_000_000);
    }
    // Use the config DAO to verify that the start block has been set to 1000
    {
        let config_dao = config_dao(&node_name);
        assert_eq!(
            config_dao.get("start_block").unwrap().value_opt.unwrap(),
            "1000"
        );
    }
    let node = cluster.start_named_real_node(&node_name, node_index, node_config);
    let ui_client = node.make_ui(ui_port);
    // Command a scan log
    ui_client.send_request(
        UiScanRequest {
            scan_type: ScanType::Receivables,
        }
        .tmb(1235),
    );
    let response = ui_client.wait_for_response(1235, Duration::from_secs(10));
    let (_, context_id) = UiScanResponse::fmb(response).unwrap();
    assert_eq!(context_id, 1235);
    // Kill the real Node
    node.kill_node();
    // Use the receivable DAO to verify that the receivable's balance has been adjusted
    {
        let receivable_dao = receivable_dao(&node_name);
        let receivable_accounts = receivable_dao
            .custom_query(CustomQuery::RangeQuery {
                min_age_s: 0,
                max_age_s: i64::MAX as u64,
                min_amount_gwei: i64::MIN,
                max_amount_gwei: i64::MAX,
                timestamp: SystemTime::now(),
            })
            .unwrap_or_default();
        assert_eq!(receivable_accounts.len(), 1);
        assert_eq!(receivable_accounts[0].balance_wei, 9_000_000_000);
    }
    // Use the config DAO to verify that the start block has been advanced to 2001
    {
        let config_dao = config_dao(&node_name);
        assert_eq!(
            config_dao.get("start_block").unwrap().value_opt.unwrap(),
            "2000"
        );
    }
}

#[test]
fn blockchain_bridge_starts_properly_on_bootstrap() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let private_key = "0011223300112233001122330011223300112233001122330011223300112233";
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .consuming_wallet_info(ConsumingWalletInfo::PrivateKey(private_key.to_string()))
            .chain(cluster.chain)
            .build(),
    );

    MASQNodeUtils::wrote_log_containing(
        subject.name(),
        "DEBUG: BlockchainBridge: Received BindMessage",
        Duration::from_millis(1000),
    )
}
