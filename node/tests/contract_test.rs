// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethabi;
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::MASQ_TOTAL_SUPPLY;
use web3;
use web3::contract::{Contract, Options};
use web3::transports::Http;
use web3::types::U256;

fn assert_contract_existence(
    blockchain_service_url: &str,
    chain: &Chain,
    expected_token_name: &str,
    expected_decimals: u32,
) -> Result<(), String> {
    let min_abi_json = r#"[{
        "constant": true,
        "inputs": [],
        "name": "name",
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
        {
        "constant": true,
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {
                "name": "",
                "type": "uint8"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    }]"#;

    let (_event_loop, transport) = web3::transports::Http::new(blockchain_service_url).unwrap();
    let contract = create_contract_interface(transport, chain, min_abi_json);
    let token_name: String = match contract
        .query("name", (), None, Options::default(), None)
        .wait()
    {
        Ok(tn) => tn,
        Err(e) => {
            return Err(format!("Token name query failed due to: {:?}", e));
        }
    };
    let decimals: u32 = match contract
        .query("decimals", (), None, Options::default(), None)
        .wait()
    {
        Ok(dec) => dec,
        Err(e) => {
            return Err(format!("Decimals query failed due to: {:?}", e));
        }
    };

    match (
        (token_name == expected_token_name),
        (decimals == expected_decimals),
    ) {
        (true, true) => Ok(()),
        _ => panic!(
            "We failed to assert with values {}, {} and {}, {}",
            token_name, expected_token_name, decimals, expected_decimals
        ),
    }
}

fn create_contract_interface(transport: Http, chain: &Chain, min_abi_json: &str) -> Contract<Http> {
    let web3 = web3::Web3::new(transport);
    let address = chain.rec().contract;
    let abi = ethabi::Contract::load(min_abi_json.as_bytes()).unwrap();
    web3::contract::Contract::new(web3.eth(), address, abi)
}

fn assert_contract<'a, F>(blockchain_urls: Vec<&'static str>, chain: &'a Chain, test_performer: F)
where
    F: FnOnce(&'static str, &'a Chain) -> Result<(), String> + Copy,
{
    for blockchain_url in blockchain_urls {
        eprintln!("Starting a new attempt with: '{}'", blockchain_url);
        match test_performer(blockchain_url, chain) {
            Ok(()) => {
                eprintln!("Attempt Successful!");
                return;
            }
            Err(e) => {
                eprintln!("Attempt Failed: {:?}", e);
            }
        }
    }

    panic!("Test failed on all blockchain services");
}

#[test]
fn masq_erc20_contract_exists_on_polygon_amoy_integration() {
    let blockchain_urls = vec![
        "https://rpc-amoy.polygon.technology",
        "https://rpc.ankr.com/polygon_amoy",
        "https://80002.rpc.thirdweb.com",
    ];
    let chain = Chain::PolyAmoy;

    let assertion_body = |url, chain| assert_contract_existence(url, chain, "tMASQ", 18);
    assert_contract(blockchain_urls, &chain, assertion_body)
}

#[test]
fn masq_erc20_contract_exists_on_polygon_mainnet_integration() {
    let blockchain_urls = vec![
        "https://polygon-rpc.com/",
        "https://rpc-mainnet.maticvigil.com",
        "https://rpc-mainnet.matic.network",
        "https://rpc-mainnet.matic.quiknode.pro",
    ];
    let chain = Chain::PolyMainnet;

    let assertion_body = |url, chain| assert_contract_existence(url, chain, "MASQ (PoS)", 18);
    assert_contract(blockchain_urls, &chain, assertion_body)
}

#[test]
fn masq_erc20_contract_exists_on_ethereum_mainnet_integration() {
    let blockchain_urls = vec!["https://mainnet.infura.io/v3/0ead23143b174f6983c76f69ddcf4026"];
    let chain = Chain::EthMainnet;

    let assertion_body = |url, chain| assert_contract_existence(url, chain, "MASQ", 18);
    assert_contract(blockchain_urls, &chain, assertion_body)
}

#[test]
fn masq_erc20_contract_exists_on_base_mainnet_integration() {
    let blockchain_urls = vec![
        "https://base.rpc.subquery.network/public",
        "https://base-rpc.publicnode.com",
        "https://base.drpc.org",
        "https://base-pokt.nodies.app",
    ];
    let chain = Chain::BaseMainnet;

    let assertion_body = |url, chain| assert_contract_existence(url, chain, "MASQ", 18);
    assert_contract(blockchain_urls, &chain, assertion_body)
}

#[test]
fn masq_erc20_contract_exists_on_base_sepolia_integration() {
    let blockchain_urls = vec![
        "https://rpc.ankr.com/base_sepolia",
        "https://base-sepolia-rpc.publicnode.com",
        "https://base-sepolia.public.blastapi.io",
    ];
    let chain = Chain::BaseSepolia;

    let assertion_body = |url, chain| assert_contract_existence(url, chain, "tMASQ", 18);
    assert_contract(blockchain_urls, &chain, assertion_body)
}

fn assert_total_supply(
    blockchain_service_url: &str,
    chain: &Chain,
    expected_total_supply: u64,
) -> Result<(), String> {
    let min_abi_json = r#"[{
       "constant": true,
       "inputs": [],
       "name": "totalSupply",
       "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
       ],
       "payable": false,
       "stateMutability": "view",
       "type": "function"
   }]"#;

    let (_event_loop, transport) = web3::transports::Http::new(blockchain_service_url).unwrap();
    let contract = create_contract_interface(transport, chain, min_abi_json);
    let total_supply: U256 = match contract
        .query("totalSupply", (), None, Options::default(), None)
        .wait()
    {
        Ok(ts) => ts,
        Err(e) => {
            return Err(format!("Total supply query failed due to: {:?}", e));
        }
    };
    assert_eq!(
        total_supply,
        U256::from(expected_total_supply) * U256::from(10_u64.pow(18))
    );
    Ok(())
}

#[test]
fn max_token_supply_matches_corresponding_constant_integration() {
    let blockchain_urls = vec!["https://mainnet.infura.io/v3/0ead23143b174f6983c76f69ddcf4026"];
    let chain = Chain::EthMainnet;

    let assertion_body = |url, chain| assert_total_supply(url, chain, MASQ_TOTAL_SUPPLY);
    assert_contract(blockchain_urls, &chain, assertion_body)
}
