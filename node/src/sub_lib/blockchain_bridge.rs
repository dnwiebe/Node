// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::{RequestTransactionReceipts, ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_bridge::InitiatePPFingerprints;
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use ethereum_types::H256;
use jsonrpc_core as rpc;
use masq_lib::blockchains::chains::Chain;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::time::SystemTime;
use web3::futures::Future;
use web3::transports::Batch;
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::Web3;
use web3::{BatchTransport, Error as Web3Error};

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BlockchainBridgeConfig {
    pub blockchain_service_url_opt: Option<String>,
    pub chain: Chain,
    pub gas_price: u64,
}

#[derive(Clone)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
    pub report_accounts_payable: Recipient<ReportAccountsPayable>,
    pub retrieve_transactions: Recipient<RetrieveTransactions>,
    pub ui_sub: Recipient<NodeFromUiMessage>,
    pub request_transaction_receipts: Recipient<RequestTransactionReceipts>,
}

impl Debug for BlockchainBridgeSubs {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "BlockchainBridgeSubs")
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct ReportAccountsPayable {
    pub accounts: Vec<PayableAccount>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for ReportAccountsPayable {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct SetDbPasswordMsg {
    pub client_id: u64,
    pub password: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct SetGasPriceMsg {
    pub client_id: u64,
    pub gas_price: String,
}

pub trait BatchPayableTools<T>
where
    T: BatchTransport,
{
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn batch_wide_timestamp(&self) -> SystemTime;
    fn new_payable_fingerprints(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<InitiatePPFingerprints>,
        payable_attributes: &[(H256, u64)],
    );
    fn enter_raw_transaction_to_batch(&self, signed_transactions: Bytes, web3: &Web3<Batch<T>>);
    //calls internally 'send_batch()' that takes more parameters
    fn submit_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error>;
}

#[derive(Debug)]
pub struct BatchPayableToolsReal<T> {
    phantom: PhantomData<T>,
}

impl<T: BatchTransport> Default for BatchPayableToolsReal<T> {
    fn default() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: BatchTransport + Debug> BatchPayableTools<T> for BatchPayableToolsReal<T> {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        web3.accounts()
            .sign_transaction(transaction_params, key)
            .wait()
    }

    fn batch_wide_timestamp(&self) -> SystemTime {
        SystemTime::now()
    }

    fn new_payable_fingerprints(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<InitiatePPFingerprints>,
        chief_payable_attributes: &[(H256, u64)],
    ) {
        pp_fingerprint_sub
            .try_send(InitiatePPFingerprints {
                batch_wide_timestamp,
                init_params: chief_payable_attributes.to_vec(),
            })
            .expect("Accountant is dead");
    }

    fn enter_raw_transaction_to_batch(&self, signed_transactions: Bytes, web3: &Web3<Batch<T>>) {
        let _ = web3.eth().send_raw_transaction(signed_transactions);
    }

    fn submit_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error> {
        web3.transport().submit_batch().wait()
    }
}

#[derive(Debug)]
pub struct BatchedPayableToolsNull<T> {
    phantom: PhantomData<T>,
}

impl<T> Default for BatchedPayableToolsNull<T> {
    fn default() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: BatchTransport> BatchPayableTools<T> for BatchedPayableToolsNull<T> {
    fn sign_transaction(
        &self,
        _transaction_params: TransactionParameters,
        _web3: &Web3<Batch<T>>,
        _key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        panic!("sign_transaction() should never be called on the null object")
    }

    fn batch_wide_timestamp(&self) -> SystemTime {
        todo!()
    }

    fn new_payable_fingerprints(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<InitiatePPFingerprints>,
        payable_attributes: &[(H256, u64)],
    ) {
        panic!(
            "request_new_pending_payable_fingerprint() should never be called on the null object"
        )
    }

    fn enter_raw_transaction_to_batch(&self, signed_transactions: Bytes, web3: &Web3<Batch<T>>) {
        todo!()
    }

    fn submit_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error> {
        panic!("send_raw_transaction() should never be called on the null object")
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_bridge::InitiatePPFingerprints;
    use crate::blockchain::test_utils::{make_tx_hash, TestTransport};
    use crate::sub_lib::blockchain_bridge::{
        BatchPayableTools, BatchedPayableToolsNull, BatchPayableToolsReal,
    };
    use crate::test_utils::recorder::{make_blockchain_bridge_subs_from, make_recorder, Recorder};
    use actix::{Actor, System};
    use std::time::SystemTime;
    use web3::transports::Batch;
    use web3::types::{Bytes, TransactionParameters};
    use web3::Web3;

    #[test]
    #[should_panic(expected = "sign_transaction() should never be called on the null object")]
    fn null_sign_transaction_stops_the_run() {
        let transaction_parameters = TransactionParameters {
            nonce: None,
            to: None,
            gas: Default::default(),
            gas_price: None,
            value: Default::default(),
            data: Default::default(),
            chain_id: None,
        };
        let web3 = Web3::new(Batch::new(TestTransport::default()));
        let secret_key =
            secp256k1secrets::key::SecretKey::from_slice(b"000000000000000000000000000000aa")
                .unwrap();

        let _ = BatchedPayableToolsNull::<TestTransport>::default().sign_transaction(
            transaction_parameters,
            &web3,
            &secret_key,
        );
    }

    #[test]
    #[should_panic(expected = "send_batch() should never be called on the null object")]
    fn null_send_batch_stops_the_run() {
        let rlp = Bytes(b"data".to_vec());
        let web3 = Web3::new(Batch::new(TestTransport::default()));

        let _ = BatchedPayableToolsNull::<TestTransport>::default().submit_batch(&web3);
    }

    #[test]
    #[should_panic(
        expected = "request_new_pending_payable_fingerprint() should never be called on the null object"
    )]
    fn null_request_new_pending_payable_fingerprint_stops_the_run() {
        let recipient = Recorder::new().start().recipient();
        let _ = BatchedPayableToolsNull::<TestTransport>::default().new_payable_fingerprints(
            SystemTime::now(),
            &recipient,
            &[(Default::default(), 5)],
        );
    }

    #[test]
    fn request_new_payable_fingerprints_works() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let recipient = accountant.start().recipient();
        let timestamp = SystemTime::now();
        let chief_attributes_of_payables =
            vec![(Default::default(), 5), (make_tx_hash(45466), 444444)];

        let _ = BatchPayableToolsReal::<TestTransport>::default().new_payable_fingerprints(
            timestamp,
            &recipient,
            &chief_attributes_of_payables,
        );

        let system = System::new("new fingerprints");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<InitiatePPFingerprints>(0);
        assert_eq!(
            message,
            &InitiatePPFingerprints {
                batch_wide_timestamp: timestamp,
                init_params: chief_attributes_of_payables
            }
        )
    }

    #[test]
    fn batch_wide_timestamp_returns_current_now() {
        let subject = BatchPayableToolsReal::<TestTransport>::default();
        let before = SystemTime::now();

        let result = subject.batch_wide_timestamp();

        let after = SystemTime::now();
        assert!(before <= result && result <= after)
    }

    #[test]
    fn blockchain_bridge_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = make_blockchain_bridge_subs_from(&recorder);

        assert_eq!(format!("{:?}", subject), "BlockchainBridgeSubs");
    }
}
