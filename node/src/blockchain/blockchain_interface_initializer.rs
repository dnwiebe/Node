// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
};
use crate::blockchain::blockchain_interface::BlockchainInterface;
use masq_lib::blockchains::chains::Chain;
use web3::transports::Http;

pub(in crate::blockchain) struct BlockchainInterfaceInitializer {}

impl BlockchainInterfaceInitializer {
    // TODO when we have multiple chains of fundamentally different architectures and are able to switch them,
    // this should probably be replaced by a HashMap of distinct interfaces for each chain
    pub fn initialize_interface(
        &self,
        blockchain_service_url: &str,
        chain: Chain,
    ) -> Box<dyn BlockchainInterface> {
        self.initialize_web3_interface(blockchain_service_url, chain)
    }

    fn initialize_web3_interface(
        &self,
        blockchain_service_url: &str,
        chain: Chain,
    ) -> Box<dyn BlockchainInterface> {
        match Http::with_max_parallel(blockchain_service_url, REQUESTS_IN_PARALLEL) {
            Ok((event_loop_handle, transport)) => Box::new(BlockchainInterfaceWeb3::new(
                transport,
                event_loop_handle,
                chain,
            )),
            Err(e) => panic!(
                "Invalid blockchain service URL \"{}\". Error: {:?}. Chain: {}",
                blockchain_service_url,
                e,
                chain.rec().literal_identifier
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface_initializer::BlockchainInterfaceInitializer;
    use masq_lib::blockchains::chains::Chain;

    use futures::Future;
    use std::net::Ipv4Addr;
    use web3::transports::Http;

    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
    };
    use crate::blockchain::blockchain_interface::BlockchainInterface;
    use crate::test_utils::make_wallet;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::utils::find_free_port;

    #[test]
    fn initialize_web3_interface_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x3B9ACA00".to_string(), 0) // gas_price = 10000000000
            .response("0xFF40".to_string(), 0)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .response("0x23".to_string(), 1)
            .start();
        let wallet = make_wallet("123");
        let chain = Chain::PolyMainnet;
        let server_url = &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port);
        let (event_loop_handle, transport) =
            Http::with_max_parallel(server_url, REQUESTS_IN_PARALLEL).unwrap();
        let subject = BlockchainInterfaceWeb3::new(transport, event_loop_handle, chain);

        let blockchain_agent = subject
            .build_blockchain_agent(wallet.clone())
            .wait()
            .unwrap();

        assert_eq!(blockchain_agent.consuming_wallet(), &wallet);
        assert_eq!(
            blockchain_agent.agreed_fee_per_computation_unit(),
            1_000_000_000
        );
    }

    #[test]
    #[should_panic(expected = "Invalid blockchain service URL \"http://λ:8545\". \
    Error: Transport(\"InvalidUri(InvalidUriChar)\"). Chain: polygon-mainnet")]
    fn invalid_blockchain_url_for_produces_panic_for_web3_interface() {
        let blockchain_service_url = "http://λ:8545";
        let subject = BlockchainInterfaceInitializer {};

        subject.initialize_web3_interface(blockchain_service_url, DEFAULT_CHAIN);
    }
}
