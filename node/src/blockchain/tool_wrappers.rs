// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
use actix::prelude::SendError;
use actix::{Message, Recipient, SpawnHandle};
use ethereum_types::H256;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::{Duration, SystemTime};
use web3::futures::Future;
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::Error as Web3Error;
use web3::{Transport, Web3};

pub trait SendTransactionToolWrapper {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn demand_payment_backup_completion(&self, rowid: u64, transaction_hash: H256) -> SystemTime;
    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error>;
}

pub struct SendTransactionToolWrapperReal<'a, T: Transport + Debug> {
    web3: &'a Web3<T>,
    payment_backup_sub: &'a dyn PaymentBackupRecipientWrapper,
}

impl<'a, T: Transport + Debug> SendTransactionToolWrapperReal<'a, T> {
    pub fn new(
        web3: &'a Web3<T>,
        payment_backup_sub: &'a dyn PaymentBackupRecipientWrapper,
    ) -> Self {
        Self {
            web3,
            payment_backup_sub,
        }
    }
}

impl<'a, T: Transport + Debug> SendTransactionToolWrapper
    for SendTransactionToolWrapperReal<'a, T>
{
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        self.web3
            .accounts()
            .sign_transaction(transaction_params, key)
            .wait()
    }

    fn demand_payment_backup_completion(&self, rowid: u64, hash: H256) -> SystemTime {
        let now = SystemTime::now();
        self.payment_backup_sub
            .try_send(PaymentBackupRecord {
                amount: None,
                rowid,
                timestamp: now,
                hash,
                attempt: 0,
            })
            .expect("Accountant is dead");
        now
    }

    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error> {
        self.web3.eth().send_raw_transaction(rlp).wait()
    }
}

pub struct SendTransactionToolWrapperNull;

impl SendTransactionToolWrapper for SendTransactionToolWrapperNull {
    fn sign_transaction(
        &self,
        _transaction_params: TransactionParameters,
        _key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        panic!("sing_transaction() should never be called on the null object")
    }

    fn demand_payment_backup_completion(&self, _rowid: u64, _transaction_hash: H256) -> SystemTime {
        panic!("order_payment_backup() should never be called on the null object")
    }

    fn send_raw_transaction(&self, _rlp: Bytes) -> Result<H256, Web3Error> {
        panic!("send_raw_transaction() should never be called on the null object")
    }
}

//TODO this might be moved to somewhere else
pub trait NotifyLaterHandle<T> {
    fn notify_later<'a>(
        &'a self,
        msg: T,
        interval: Duration,
        closure: Box<dyn FnMut(T, Duration) -> SpawnHandle + 'a>,
    ) -> SpawnHandle;
}

pub struct NotifyLaterHandleReal<T> {
    phantom: PhantomData<T>,
}

impl<T: Message + 'static> Default for Box<dyn NotifyLaterHandle<T>> {
    fn default() -> Self {
        Box::new(NotifyLaterHandleReal {
            phantom: PhantomData::default(),
        })
    }
}

impl<T: Message> NotifyLaterHandle<T> for NotifyLaterHandleReal<T> {
    fn notify_later<'a>(
        &'a self,
        msg: T,
        interval: Duration,
        mut closure: Box<dyn FnMut(T, Duration) -> SpawnHandle + 'a>,
    ) -> SpawnHandle {
        closure(msg, interval)
    }
}

pub trait NotifyHandle<T> {
    fn notify<'a>(&'a self, msg: T, closure: Box<dyn FnMut(T) + 'a>);
}

impl<T: Message + 'static> Default for Box<dyn NotifyHandle<T>> {
    fn default() -> Self {
        Box::new(NotifyHandleReal {
            phantom: PhantomData::default(),
        })
    }
}

pub struct NotifyHandleReal<T> {
    phantom: PhantomData<T>,
}

impl<T: Message> NotifyHandle<T> for NotifyHandleReal<T> {
    fn notify<'a>(&'a self, msg: T, mut closure: Box<dyn FnMut(T) + 'a>) {
        closure(msg)
    }
}

pub trait PaymentBackupRecipientWrapper {
    fn try_send(&self, msg: PaymentBackupRecord) -> Result<(), SendError<PaymentBackupRecord>>;
}

pub struct PaymentBackupRecipientWrapperReal<'a> {
    recipient: &'a Recipient<PaymentBackupRecord>,
}

impl<'a> PaymentBackupRecipientWrapperReal<'a> {
    pub fn new(recipient: &'a Recipient<PaymentBackupRecord>) -> Self {
        Self { recipient }
    }
}

impl PaymentBackupRecipientWrapper for PaymentBackupRecipientWrapperReal<'_> {
    fn try_send(&self, msg: PaymentBackupRecord) -> Result<(), SendError<PaymentBackupRecord>> {
        self.recipient.try_send(msg)
    }
}

pub struct PaymentBackupRecipientWrapperNull;

impl PaymentBackupRecipientWrapper for PaymentBackupRecipientWrapperNull {
    fn try_send(&self, _msg: PaymentBackupRecord) -> Result<(), SendError<PaymentBackupRecord>> {
        panic!("try_send() for PaymentBackupRecipientWrapper should never be called on the null object")
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
    use crate::blockchain::tool_wrappers::{
        PaymentBackupRecipientWrapper, PaymentBackupRecipientWrapperNull,
        SendTransactionToolWrapper, SendTransactionToolWrapperNull,
    };
    use std::time::SystemTime;
    use web3::types::{Bytes, TransactionParameters};

    #[test]
    #[should_panic(expected = "sing_transaction() should never be called on the null object")]
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
        let secret_key =
            secp256k1secrets::key::SecretKey::from_slice(b"000000000000000000000000000000aa")
                .unwrap();

        let _ =
            SendTransactionToolWrapperNull.sign_transaction(transaction_parameters, &secret_key);
    }

    #[test]
    #[should_panic(expected = "send_raw_transaction() should never be called on the null object")]
    fn null_send_raw_transaction_stops_the_run() {
        let rlp = Bytes(b"data".to_vec());

        let _ = SendTransactionToolWrapperNull.send_raw_transaction(rlp);
    }

    #[test]
    #[should_panic(expected = "order_payment_backup() should never be called on the null object")]
    fn null_trigger_payment_backup_completion_stops_the_run() {
        let _ =
            SendTransactionToolWrapperNull.demand_payment_backup_completion(5, Default::default());
    }

    #[test]
    #[should_panic(
        expected = "try_send() for PaymentBackupRecipientWrapper should never be called on the null object"
    )]
    fn null_try_send_stops_the_run() {
        let msg = PaymentBackupRecord {
            rowid: 1,
            timestamp: SystemTime::now(),
            hash: Default::default(),
            attempt: 0,
            amount: None,
        };

        let _ = PaymentBackupRecipientWrapperNull.try_send(msg);
    }
}
