// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::msgs::QualifiedPayablesMessage;
use crate::accountant::{RequestTransactionReceipts, ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use masq_lib::blockchains::chains::Chain;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::fmt;
use std::fmt::{Debug, Formatter};
use web3::types::U256;

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BlockchainBridgeConfig {
    pub blockchain_service_url_opt: Option<String>,
    pub chain: Chain,
    // TODO: totally ignored during the setup of the BlockchainBridge actor!
    // Use it in the body or delete this field
    pub gas_price: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
    pub outbound_payments_instructions: Recipient<OutboundPaymentsInstructions>,
    pub qualified_payables: Recipient<QualifiedPayablesMessage>,
    pub retrieve_transactions: Recipient<RetrieveTransactions>,
    pub ui_sub: Recipient<NodeFromUiMessage>,
    pub request_transaction_receipts: Recipient<RequestTransactionReceipts>,
}

impl Debug for BlockchainBridgeSubs {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "BlockchainBridgeSubs")
    }
}

#[derive(Message)]
pub struct OutboundPaymentsInstructions {
    pub affordable_accounts: Vec<PayableAccount>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl OutboundPaymentsInstructions {
    pub fn new(
        affordable_accounts: Vec<PayableAccount>,
        agent: Box<dyn BlockchainAgent>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            affordable_accounts,
            agent,
            response_skeleton_opt,
        }
    }
}

impl SkeletonOptHolder for OutboundPaymentsInstructions {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumingWalletBalances {
    pub transaction_fee_balance_in_minor_units: U256,
    pub masq_token_balance_in_minor_units: U256,
}

impl ConsumingWalletBalances {
    pub fn new(transaction_fee: U256, masq_token: U256) -> Self {
        Self {
            transaction_fee_balance_in_minor_units: transaction_fee,
            masq_token_balance_in_minor_units: masq_token,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::actor_system_factory::SubsFactory;
    use crate::blockchain::blockchain_bridge::{BlockchainBridge, BlockchainBridgeSubsFactoryReal};
    use crate::blockchain::test_utils::make_blockchain_interface_web3;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_blockchain_bridge_subs_from_recorder, Recorder};
    use actix::Actor;
    use masq_lib::utils::find_free_port;
    use std::sync::{Arc, Mutex};

    #[test]
    fn blockchain_bridge_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = make_blockchain_bridge_subs_from_recorder(&recorder);

        assert_eq!(format!("{:?}", subject), "BlockchainBridgeSubs");
    }

    #[test]
    fn blockchain_bridge_subs_factory_produces_proper_subs() {
        let subject = BlockchainBridgeSubsFactoryReal {};
        let blockchain_interface = make_blockchain_interface_web3(find_free_port());
        let persistent_config = PersistentConfigurationMock::new();
        let accountant = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let addr = accountant.start();

        let subs = subject.make(&addr);

        assert_eq!(subs, BlockchainBridge::make_subs_from(&addr))
    }
}
