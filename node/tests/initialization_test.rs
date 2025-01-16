// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use masq_lib::constants::{DEFAULT_CHAIN, NODE_NOT_RUNNING_ERROR};
use masq_lib::messages::{
    ToMessageBody, UiFinancialsResponse, UiSetupRequest, UiSetupResponse, UiShutdownRequest,
    NODE_UI_PROTOCOL,
};
use masq_lib::messages::{UiFinancialsRequest, UiRedirect, UiStartOrder, UiStartResponse};
use masq_lib::test_utils::ui_connection::UiConnection;
use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, node_home_directory};
use masq_lib::utils::find_free_port;
use node_lib::daemon::launch_verifier::{VerifierTools, VerifierToolsReal};
use node_lib::database::db_initializer::DATABASE_FILE;
#[cfg(not(target_os = "windows"))]
use node_lib::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use rusqlite::{Connection, OpenFlags};
use std::ops::Add;
use std::time::{Duration, SystemTime};
use utils::CommandConfig;
use utils::MASQNode;

#[cfg(not(target_os = "windows"))]
#[test]
fn expect_privilege_works_outside_windows_integration() {
    let subject = PrivilegeDropperReal::new();

    assert_eq!(subject.expect_privilege(true), true);
    assert_eq!(subject.expect_privilege(false), false);
}

#[test]
fn clap_help_does_not_initialize_database_integration() {
    match std::fs::remove_file(DATABASE_FILE) {
        Ok(_) => (),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(ref e) => panic!("{:?}", e),
    }

    let mut node = MASQNode::start_standard(
        "clap_help_does_not_initialize_database_integration",
        Some(
            CommandConfig::new().opt("--help"), // We don't specify --data-directory because the --help logic doesn't evaluate it
        ),
        true,
        true,
        false,
        false,
    );

    node.wait_for_exit().unwrap();
    let failure = std::fs::File::open(DATABASE_FILE);
    assert_eq!(failure.err().unwrap().kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn initialization_sequence_integration() {
    let daemon_port = find_free_port();
    let mut daemon = MASQNode::start_daemon(
        "initialization_sequence_integration",
        Some(CommandConfig::new().pair("--ui-port", format!("{}", daemon_port).as_str())),
        true,
        true,
        false,
        true,
    );
    let mut initialization_client = UiConnection::new(daemon_port, NODE_UI_PROTOCOL);
    let data_directory = ensure_node_home_directory_exists(
        "initialization_test",
        "initialization_sequence_integration",
    );
    let _: UiSetupResponse = initialization_client
        .transact(UiSetupRequest::new(vec![
            ("dns-servers", Some("1.1.1.1")),
            ("neighborhood-mode", Some("zero-hop")),
            ("log-level", Some("trace")),
            ("data-directory", Some(&data_directory.to_str().unwrap())),
            ("blockchain-service-url", Some("https://example.com")),
        ]))
        .unwrap();
    let financials_request = UiFinancialsRequest {
        stats_required: true,
        top_records_opt: None,
        custom_queries_opt: None,
    };
    let context_id = 1234;

    //<UiFinancialsRequest, UiFinancialsResponse>
    //newly a conversational message that can't reach the Node returns transformed into a response of the corresponding kind
    let not_running_financials_response = initialization_client
        .transact_with_context_id::<UiFinancialsRequest, UiFinancialsResponse>(
            financials_request.clone(),
            context_id,
        )
        .unwrap_err();
    let start_response: UiStartResponse = initialization_client.transact(UiStartOrder {}).unwrap();
    let running_financials_response: UiRedirect = initialization_client
        .transact_with_context_id(financials_request.clone(), context_id)
        .unwrap();

    assert_eq!(not_running_financials_response.0, NODE_NOT_RUNNING_ERROR);
    assert_eq!(
        not_running_financials_response.1,
        "Cannot handle financials request: Node is not running".to_string()
    );
    assert_eq!(running_financials_response.opcode, "financials".to_string());
    assert_eq!(
        running_financials_response.port,
        start_response.redirect_ui_port
    );
    let json = financials_request.tmb(context_id).payload.unwrap();
    let expected_payload: UiFinancialsRequest = serde_json::from_str(&json).unwrap();
    let actual_payload: UiFinancialsRequest =
        serde_json::from_str(&running_financials_response.payload).unwrap();
    assert_eq!(actual_payload, expected_payload);
    let mut service_client = UiConnection::new(start_response.redirect_ui_port, NODE_UI_PROTOCOL);
    service_client.send(UiShutdownRequest {});
    wait_for_process_end(start_response.new_process_id);
    let _ = daemon.kill();
    match daemon.wait_for_exit() {
        None => eprintln!("wait_for_exit produced no output: weird"),
        Some(output) => {
            eprintln!(
                "wait_for_exit produced exit status {:?} and stdout:\n------\n{}\n------\nstderr:\n------\n{}\n------\n",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        }
    }
}

fn wait_for_process_end(process_id: u32) {
    let tools = VerifierToolsReal::new();
    let deadline = SystemTime::now().add(Duration::from_millis(2000));
    loop {
        if SystemTime::now().gt(&deadline) {
            panic!(
                "Process {} not dead after receiving shutdownRequest",
                process_id
            )
        }
        if !tools.process_is_running(process_id) {
            break;
        }
        tools.delay(500);
    }
}

#[test]
fn incomplete_node_descriptor_is_refused_integration() {
    let chain_identifier = "polygon-mainnet";
    let mut node = utils::MASQNode::start_standard(
        "incomplete_node_descriptor_is_refused_integration",
        Some(
            CommandConfig::new()
                .pair(
                    "--neighbors",
                    &format!("masq://{chain_identifier}:12345vhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@12.23.34.45:5678,masq://{chain_identifier}:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@:")
                ),
        ),
        true,
        true,
        true,
        false
    );
    match node.wait_for_exit() {
        None => panic!("the process terminated in a strange way"),
        Some(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("Log is written to"),
                "we thought to see a note of the logs' location, instead we got: {}",
                stdout
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(&format!("neighbors - Neighbors supplied without ip addresses and ports are not valid: 'masq://{chain_identifier}:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@<N/A>:<N/A>")
            ), "instead we got: {}",stderr)
        }
    };
}

#[test]
fn started_without_explicit_chain_parameter_runs_fine_integration() {
    //defaulted chain - chosen on the lack of user specified chain - corresponds with descriptors
    //believed to be for the default chain
    let config = CommandConfig::new()
        .pair("--neighborhood-mode", "standard")
        .pair("--ip", "1.0.0.1")
        .pair("--log-level", "trace")
        .pair(
            "--neighbors",
            &format!(
                "masq://{}:UJNoZW5p_PDVqEjpr3b-8jZ_93yPG8i5dOAgE1bhK-A@12.23.34.45:5678",
                DEFAULT_CHAIN.rec().literal_identifier
            ),
        );

    let mut node = MASQNode::start_with_blank_config(
        "started_without_explicit_chain_parameter_runs_fine_integration",
        Some(config),
        true,
        true,
        false,
        false,
    );

    node.wait_for_log("UIGateway bound", Some(5000));
    //Node is dropped and killed
}

#[test]
fn requested_chain_meets_different_db_chain_and_panics_integration() {
    let chain_literal = DEFAULT_CHAIN.rec().literal_identifier;
    let test_name = "requested_chain_meets_different_db_chain_and_panics_integration";
    {
        //running Node just in order to create a new database which we can do testing on
        let port = find_free_port();
        let mut node = utils::MASQNode::start_standard(
            test_name,
            Some(
                CommandConfig::new()
                    .pair("--ui-port", &port.to_string())
                    .pair("--chain", &chain_literal),
            ),
            true,
            true,
            false,
            true,
        );
        node.wait_for_log("UIGateway bound", Some(5000));
        let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);
        let shutdown_request = UiShutdownRequest {};
        client.send(shutdown_request);
        node.wait_for_exit();
    }
    let db_dir = node_home_directory("integration", test_name);

    let conn = Connection::open_with_flags(
        &db_dir.join(DATABASE_FILE),
        OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .unwrap();
    conn.execute(
        "UPDATE config SET value='eth-mainnet' WHERE name='chain_name'",
        [],
    )
    .unwrap();
    let mut node = MASQNode::start_standard(
        test_name,
        Some(CommandConfig::new().pair("--chain", &chain_literal)),
        false,
        true,
        false,
        false,
    );

    let regex_pattern = &format!(
        r"ERROR: PanicHandler: src(/|\\)actor_system_factory\.rs.*- Database with a wrong chain name detected; expected: {}, was: eth-mainnet",
        &chain_literal
    );
    node.wait_for_log(&regex_pattern, Some(1000));
}

#[test]
fn node_creates_log_file_with_heading_integration() {
    let config = CommandConfig::new()
        .pair("--neighborhood-mode", "standard")
        .pair("--ip", "1.0.0.1")
        .pair(
            "--neighbors",
            &format!(
                "masq://{}:UJNoZW5p_PDVqEjpr3b-8jZ_93yPG8i5dOAgE1bhK-A@12.23.34.45:5678",
                DEFAULT_CHAIN.rec().literal_identifier
            ),
        );

    let mut node = MASQNode::start_standard(
        "node_creates_log_file_with_heading",
        Some(config),
        true,
        true,
        false,
        true,
    );

    let mut expected_heading_regex = format!(
        r#"^
          _____ ______  ________   ________   _______          Node Version: \d+\.\d+\.\d+
        /   _  | _   /|/  __   /|/  ______/|/   __   /|        Database Schema Version: \d+
       /  / /__///  / /  /|/  / /  /|_____|/  /|_/  / /        OS: [a-z]+
      /  / |__|//  / /  __   / /_____   /|/  / '/  / /         client_request_payload::MIGRATIONS \(\d+\.\d+\)
     /  / /    /  / /  / /  / |_____/  / /  /__/  / /          client_response_payload::MIGRATIONS \(\d+\.\d+\)
    /__/ /    /__/ /__/ /__/ /________/ /_____   / /           dns_resolve_failure::MIGRATIONS \(\d+\.\d+\)
    |__|/     |__|/|__|/|__|/|________|/|____/__/ /            gossip::MIGRATIONS \(\d+\.\d+\)
                                             |__|/             gossip_failure::MIGRATIONS \(\d+\.\d+\)
                                                               node_record_inner::MIGRATIONS \(\d+\.\d+\)\n
\d+\-\d+\-\d+ \d+:\d+:\d+\.\d+ Thd\d+:"#,
        //The last line represents the first log with its timestamp.
    );

    expected_heading_regex = expected_heading_regex.replace("|", "\\|");

    node.wait_for_log(&expected_heading_regex, Some(5000));
    //Node is dropped and killed
}
