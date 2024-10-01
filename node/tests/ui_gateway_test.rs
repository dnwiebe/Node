// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::MASQNode;
use masq_lib::constants::DEFAULT_CHAIN;
use masq_lib::messages::SerializableLogLevel::Warn;
use masq_lib::messages::{
    UiChangePasswordRequest, UiCheckPasswordRequest, UiCheckPasswordResponse, UiLogBroadcast,
    UiRedirect, UiSetupRequest, UiSetupResponse, UiShutdownRequest, UiStartOrder, UiStartResponse,
    UiWalletAddressesRequest, NODE_UI_PROTOCOL,
};
use masq_lib::test_utils::ui_connection::UiConnection;
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use masq_lib::utils::{add_chain_specific_directory, find_free_port};
use utils::CommandConfig;

#[test]
fn ui_requests_something_and_gets_corresponding_response() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let home_dir = ensure_node_home_directory_exists(
        "ui_gateway_test",
        "ui_requests_something_and_gets_corresponding_response",
    );
    let mut node = utils::MASQNode::start_standard(
        "ui_requests_something_and_gets_corresponding_response",
        Some(
            CommandConfig::new()
                .pair("--ui-port", &port.to_string())
                .pair(
                    "--data-directory",
                    home_dir.into_os_string().to_str().unwrap(),
                ),
        ),
        true,
        true,
        false,
        true,
    );
    node.wait_for_log("UIGateway bound", Some(5000));
    let check_password_request = UiCheckPasswordRequest {
        db_password_opt: None,
    };
    let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);

    client.send(check_password_request);
    let response: UiCheckPasswordResponse = client.skip_until_received().unwrap();

    assert_eq!(response, UiCheckPasswordResponse { matches: true });
    client.send(UiShutdownRequest {});
    node.wait_for_exit();
}

#[test]
fn log_broadcasts_are_correctly_received_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(
        "log_broadcasts_are_correctly_received",
        Some(
            CommandConfig::new()
                .pair("--ui-port", &port.to_string())
                .pair("--chain", "polygon-mainnet"),
        ),
        true,
        true,
        false,
        true,
    );
    node.wait_for_log("UIGateway bound", Some(5000));
    let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);
    client.send(UiWalletAddressesRequest {
        db_password: "blah".to_string(),
    });
    client.send(UiChangePasswordRequest {
        old_password_opt: Some("blah".to_string()),
        new_password: "blah".to_string(),
    });

    let broadcasts: Vec<UiLogBroadcast> = (0..2)
        .map(|_| client.skip_until_received().unwrap())
        .collect();

    assert_eq!(broadcasts,
               vec![
                   UiLogBroadcast { msg: "Failed to obtain wallet addresses: 281474976710669, Wallet pair not yet configured".to_string(), log_level: Warn },
                   UiLogBroadcast { msg: "Failed to change password: PasswordError".to_string(), log_level: Warn }
               ]
    );
    client.send(UiShutdownRequest {});
    node.wait_for_exit();
}

#[test]
fn daemon_does_not_allow_node_to_keep_his_client_alive_integration() {
    //Daemon's probe to check if the Node is alive causes an unwanted new reference
    //for the Daemon's client, so we need to make the Daemon send a close message
    //breaking any reference to him immediately
    fdlimit::raise_fd_limit();
    let data_directory = ensure_node_home_directory_exists(
        "ui_gateway_test",
        "daemon_does_not_allow_node_to_keep_his_client_alive_integration",
    );
    let expected_chain_data_dir = add_chain_specific_directory(DEFAULT_CHAIN, &data_directory);
    let daemon_port = find_free_port();
    let mut daemon = utils::MASQNode::start_daemon(
        "daemon_does_not_allow_node_to_keep_his_client_alive_integration",
        Some(CommandConfig::new().pair("--ui-port", daemon_port.to_string().as_str())),
        true,
        true,
        false,
        true,
    );
    //for correct simulation we have to launch the Node through the Daemon
    let mut daemon_client = UiConnection::new(daemon_port, NODE_UI_PROTOCOL);
    let _: UiSetupResponse = daemon_client
        .transact(UiSetupRequest::new(vec![
            ("ip", Some("100.80.1.1")),
            ("chain", Some("polygon-mainnet")),
            ("neighborhood-mode", Some("standard")),
            ("log-level", Some("trace")),
            ("blockchain-service-url", Some("https://example.com")),
            ("data-directory", Some(&data_directory.to_str().unwrap())),
        ]))
        .unwrap();

    let _: UiStartResponse = daemon_client.transact(UiStartOrder {}).unwrap();

    let connected_and_disconnected_assertion =
        |how_many_occurrences_we_look_for: usize,
         make_regex_searching_for_port_in_logs: fn(port_spec: &str) -> String| {
            let port_number_regex_str = r"UI connected at 127\.0\.0\.1:([\d]*)";
            let log_file_directory = expected_chain_data_dir.clone();
            let all_uis_connected_so_far = MASQNode::capture_pieces_of_log_at_directory(
                port_number_regex_str,
                &log_file_directory.as_path(),
                how_many_occurrences_we_look_for,
                Some(5000),
            );
            //we want the last occurrence (last index in the first vec) and the second entry from the capturing groups
            let searched_port_of_ui =
                all_uis_connected_so_far[how_many_occurrences_we_look_for - 1][1].as_str();
            MASQNode::wait_for_match_at_directory(
                make_regex_searching_for_port_in_logs(searched_port_of_ui).as_str(),
                log_file_directory.as_path(),
                Some(1500),
            );
            searched_port_of_ui.parse::<u16>().unwrap()
        };
    let assertion_lookup_pattern_1 = |port_spec_ui: &str| {
        format!(
            r"UI at 127\.0\.0\.1:{} \(client ID 0\) disconnected from port ",
            port_spec_ui
        )
    };
    let first_port = connected_and_disconnected_assertion(1, assertion_lookup_pattern_1);
    //previous assertion means the Daemon was disconnected from the Node without any order from outside the box
    let shutdown_request = UiShutdownRequest {};
    let ui_redirect: UiRedirect = daemon_client.transact(shutdown_request.clone()).unwrap();
    let mut node_client = UiConnection::new(ui_redirect.port, NODE_UI_PROTOCOL);
    node_client.send(shutdown_request);
    let assertion_lookup_pattern_2 =
        |_port_spec_ui: &str| "Received shutdown order from client 1".to_string();
    let second_port = connected_and_disconnected_assertion(2, assertion_lookup_pattern_2);
    let _ = daemon.kill();
    daemon.wait_for_exit();
    //only an additional assertion checking the involved clients to have different port numbers
    assert_ne!(first_port, second_port)
}

#[test]
fn cleanup_after_deceased_clients_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(
        "cleanup_after_deceased_clients_integration",
        Some(
            CommandConfig::new()
                .pair("--chain", DEFAULT_CHAIN.rec().literal_identifier)
                .pair("--ui-port", &port.to_string()),
        ),
        true,
        true,
        false,
        true,
    );
    node.wait_for_log("UIGateway bound", Some(5000));
    let client_1 = UiConnection::new(port, NODE_UI_PROTOCOL);
    let client_1_addr = client_1.local_addr();
    let mut client_2 = UiConnection::new(port, NODE_UI_PROTOCOL);

    drop(client_1);

    //Windows doesn't admit the connection is broken until the second attempt
    //of data write into the presumed stream and so we do another attempt
    #[cfg(target_os = "windows")]
    client_2.send(UiChangePasswordRequest {
        old_password_opt: Some("boooga".to_string()),
        new_password: "wow".to_string(),
    });
    let expected_message_snippet_first = format!("UI at {} violated protocol", client_1_addr);
    node.wait_for_log(&expected_message_snippet_first, Some(2000));
    #[cfg(not(target_os = "windows"))]
    let expected_message_snippet_second =
        "Client 0 hit a fatal flush error: BrokenPipe, dropping the client".to_string();
    #[cfg(target_os = "windows")]
    let expected_message_snippet_second =
        "Client 0 hit a fatal flush error: ConnectionReset, dropping the client".to_string();
    node.wait_for_log(&expected_message_snippet_second, Some(1000));
    client_2.send(UiShutdownRequest {});
    node.wait_for_exit();
}
