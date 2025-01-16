// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::accountant::{PaymentThresholds, ScanIntervals};
use crate::sub_lib::neighborhood::{Hops, NodeDescriptor, RatePack};
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use masq_lib::utils::AutomapProtocol;
use masq_lib::utils::NeighborhoodModeLight;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::u64;

#[allow(clippy::type_complexity)]
#[derive(Clone, Default)]
pub struct PersistentConfigurationMock {
    blockchain_service_url_results: RefCell<Vec<Result<Option<String>, PersistentConfigError>>>,
    set_blockchain_service_url_params: Arc<Mutex<Vec<String>>>,
    set_blockchain_service_url_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    current_schema_version_results: RefCell<Vec<String>>,
    chain_name_params: Arc<Mutex<Vec<()>>>,
    chain_name_results: RefCell<Vec<String>>,
    check_password_params: Arc<Mutex<Vec<Option<String>>>>,
    check_password_results: RefCell<Vec<Result<bool, PersistentConfigError>>>,
    change_password_params: Arc<Mutex<Vec<(Option<String>, String)>>>,
    change_password_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    clandestine_port_results: RefCell<Vec<Result<u16, PersistentConfigError>>>,
    set_clandestine_port_params: Arc<Mutex<Vec<u16>>>,
    set_clandestine_port_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    gas_price_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_gas_price_params: Arc<Mutex<Vec<u64>>>,
    set_gas_price_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    consuming_wallet_params: Arc<Mutex<Vec<String>>>,
    consuming_wallet_results: RefCell<Vec<Result<Option<Wallet>, PersistentConfigError>>>,
    consuming_wallet_private_key_params: Arc<Mutex<Vec<String>>>,
    consuming_wallet_private_key_results:
        RefCell<Vec<Result<Option<String>, PersistentConfigError>>>,
    earning_wallet_results: RefCell<Vec<Result<Option<Wallet>, PersistentConfigError>>>,
    earning_wallet_address_results: RefCell<Vec<Result<Option<String>, PersistentConfigError>>>,
    set_wallet_info_params: Arc<Mutex<Vec<(String, String, String)>>>,
    set_wallet_info_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    mapping_protocol_results: RefCell<Vec<Result<Option<AutomapProtocol>, PersistentConfigError>>>,
    set_mapping_protocol_params: Arc<Mutex<Vec<Option<AutomapProtocol>>>>,
    set_mapping_protocol_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    min_hops_results: RefCell<Vec<Result<Hops, PersistentConfigError>>>,
    set_min_hops_params: Arc<Mutex<Vec<Hops>>>,
    set_min_hops_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    neighborhood_mode_results: RefCell<Vec<Result<NeighborhoodModeLight, PersistentConfigError>>>,
    set_neighborhood_mode_params: Arc<Mutex<Vec<NeighborhoodModeLight>>>,
    set_neighborhood_mode_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    past_neighbors_params: Arc<Mutex<Vec<String>>>,
    past_neighbors_results:
        RefCell<Vec<Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>>>,
    set_past_neighbors_params: Arc<Mutex<Vec<(Option<Vec<NodeDescriptor>>, String)>>>,
    set_past_neighbors_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    start_block_params: Arc<Mutex<Vec<()>>>,
    start_block_results: RefCell<Vec<Result<Option<u64>, PersistentConfigError>>>,
    set_start_block_params: Arc<Mutex<Vec<Option<u64>>>>,
    set_start_block_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    max_block_count_params: Arc<Mutex<Vec<()>>>,
    max_block_count_results: RefCell<Vec<Result<Option<u64>, PersistentConfigError>>>,
    set_max_block_count_params: Arc<Mutex<Vec<Option<u64>>>>,
    set_max_block_count_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    set_start_block_from_txn_params: Arc<Mutex<Vec<(Option<u64>, ArbitraryIdStamp)>>>,
    set_start_block_from_txn_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    payment_thresholds_results: RefCell<Vec<Result<PaymentThresholds, PersistentConfigError>>>,
    set_payment_thresholds_params: Arc<Mutex<Vec<String>>>,
    set_payment_thresholds_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    rate_pack_results: RefCell<Vec<Result<RatePack, PersistentConfigError>>>,
    set_rate_pack_params: Arc<Mutex<Vec<String>>>,
    set_rate_pack_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    scan_intervals_results: RefCell<Vec<Result<ScanIntervals, PersistentConfigError>>>,
    set_scan_intervals_params: Arc<Mutex<Vec<String>>>,
    set_scan_intervals_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl PersistentConfiguration for PersistentConfigurationMock {
    fn blockchain_service_url(&self) -> Result<Option<String>, PersistentConfigError> {
        self.blockchain_service_url_results.borrow_mut().remove(0)
    }

    fn set_blockchain_service_url(&mut self, url: &str) -> Result<(), PersistentConfigError> {
        self.set_blockchain_service_url_params
            .lock()
            .unwrap()
            .push(url.to_string());
        self.set_blockchain_service_url_results
            .borrow_mut()
            .remove(0)
    }

    fn current_schema_version(&self) -> String {
        Self::result_from(&self.current_schema_version_results)
    }

    fn chain_name(&self) -> String {
        self.chain_name_params.lock().unwrap().push(());
        self.chain_name_results.borrow_mut().remove(0)
    }

    fn check_password(
        &self,
        db_password_opt: Option<String>,
    ) -> Result<bool, PersistentConfigError> {
        self.check_password_params
            .lock()
            .unwrap()
            .push(db_password_opt);
        self.check_password_results.borrow_mut().remove(0)
    }

    fn change_password(
        &mut self,
        old_password_opt: Option<String>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        self.change_password_params
            .lock()
            .unwrap()
            .push((old_password_opt, db_password.to_string()));
        self.change_password_results.borrow_mut().remove(0)
    }

    fn consuming_wallet(&self, db_password: &str) -> Result<Option<Wallet>, PersistentConfigError> {
        self.consuming_wallet_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        Self::result_from(&self.consuming_wallet_results)
    }

    fn consuming_wallet_private_key(
        &self,
        db_password: &str,
    ) -> Result<Option<String>, PersistentConfigError> {
        self.consuming_wallet_private_key_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        Self::result_from(&self.consuming_wallet_private_key_results)
    }

    fn clandestine_port(&self) -> Result<u16, PersistentConfigError> {
        Self::result_from(&self.clandestine_port_results)
    }

    fn set_clandestine_port(&mut self, port: u16) -> Result<(), PersistentConfigError> {
        self.set_clandestine_port_params.lock().unwrap().push(port);
        self.set_clandestine_port_results.borrow_mut().remove(0)
    }

    fn earning_wallet(&self) -> Result<Option<Wallet>, PersistentConfigError> {
        Self::result_from(&self.earning_wallet_results)
    }

    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError> {
        Self::result_from(&self.earning_wallet_address_results)
    }

    fn gas_price(&self) -> Result<u64, PersistentConfigError> {
        Self::result_from(&self.gas_price_results)
    }

    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError> {
        self.set_gas_price_params.lock().unwrap().push(gas_price);
        self.set_gas_price_results.borrow_mut().remove(0)
    }

    fn mapping_protocol(&self) -> Result<Option<AutomapProtocol>, PersistentConfigError> {
        self.mapping_protocol_results.borrow_mut().remove(0)
    }

    fn set_mapping_protocol(
        &mut self,
        value: Option<AutomapProtocol>,
    ) -> Result<(), PersistentConfigError> {
        self.set_mapping_protocol_params.lock().unwrap().push(value);
        self.set_mapping_protocol_results.borrow_mut().remove(0)
    }

    fn min_hops(&self) -> Result<Hops, PersistentConfigError> {
        self.min_hops_results.borrow_mut().remove(0)
    }

    fn set_min_hops(&mut self, value: Hops) -> Result<(), PersistentConfigError> {
        self.set_min_hops_params.lock().unwrap().push(value);
        self.set_min_hops_results.borrow_mut().remove(0)
    }

    fn neighborhood_mode(&self) -> Result<NeighborhoodModeLight, PersistentConfigError> {
        self.neighborhood_mode_results.borrow_mut().remove(0)
    }

    fn set_neighborhood_mode(
        &mut self,
        value: NeighborhoodModeLight,
    ) -> Result<(), PersistentConfigError> {
        self.set_neighborhood_mode_params
            .lock()
            .unwrap()
            .push(value);
        self.set_neighborhood_mode_results.borrow_mut().remove(0)
    }

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError> {
        self.past_neighbors_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        self.past_neighbors_results.borrow_mut().remove(0)
    }

    fn set_past_neighbors(
        &mut self,
        node_descriptors_opt: Option<Vec<NodeDescriptor>>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        self.set_past_neighbors_params
            .lock()
            .unwrap()
            .push((node_descriptors_opt, db_password.to_string()));
        self.set_past_neighbors_results.borrow_mut().remove(0)
    }

    fn start_block(&self) -> Result<Option<u64>, PersistentConfigError> {
        self.start_block_params.lock().unwrap().push(());
        Self::result_from(&self.start_block_results)
    }

    fn set_start_block(&mut self, value: Option<u64>) -> Result<(), PersistentConfigError> {
        self.set_start_block_params.lock().unwrap().push(value);
        Self::result_from(&self.set_start_block_results)
    }

    fn max_block_count(&self) -> Result<Option<u64>, PersistentConfigError> {
        self.max_block_count_params.lock().unwrap().push(());
        Self::result_from(&self.max_block_count_results)
    }

    fn set_max_block_count(&mut self, value: Option<u64>) -> Result<(), PersistentConfigError> {
        self.set_max_block_count_params.lock().unwrap().push(value);
        Self::result_from(&self.set_max_block_count_results)
    }

    fn set_start_block_from_txn(
        &mut self,
        value: Option<u64>,
        transaction: &mut TransactionSafeWrapper,
    ) -> Result<(), PersistentConfigError> {
        self.set_start_block_from_txn_params
            .lock()
            .unwrap()
            .push((value, transaction.arbitrary_id_stamp()));
        Self::result_from(&self.set_start_block_from_txn_results)
    }
    fn set_wallet_info(
        &mut self,
        consuming_wallet_private_key: &str,
        earning_wallet_address: &str,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        self.set_wallet_info_params.lock().unwrap().push((
            consuming_wallet_private_key.to_string(),
            earning_wallet_address.to_string(),
            db_password.to_string(),
        ));
        self.set_wallet_info_results.borrow_mut().remove(0)
    }

    fn payment_thresholds(&self) -> Result<PaymentThresholds, PersistentConfigError> {
        self.payment_thresholds_results.borrow_mut().remove(0)
    }

    fn set_payment_thresholds(&mut self, curves: String) -> Result<(), PersistentConfigError> {
        self.set_payment_thresholds_params
            .lock()
            .unwrap()
            .push(curves);
        self.set_payment_thresholds_results.borrow_mut().remove(0)
    }

    fn rate_pack(&self) -> Result<RatePack, PersistentConfigError> {
        self.rate_pack_results.borrow_mut().remove(0)
    }

    fn set_rate_pack(&mut self, rate_pack: String) -> Result<(), PersistentConfigError> {
        self.set_rate_pack_params.lock().unwrap().push(rate_pack);
        self.set_rate_pack_results.borrow_mut().remove(0)
    }

    fn scan_intervals(&self) -> Result<ScanIntervals, PersistentConfigError> {
        self.scan_intervals_results.borrow_mut().remove(0)
    }

    fn set_scan_intervals(&mut self, intervals: String) -> Result<(), PersistentConfigError> {
        self.set_scan_intervals_params
            .lock()
            .unwrap()
            .push(intervals);
        self.set_scan_intervals_results.borrow_mut().remove(0)
    }

    arbitrary_id_stamp_in_trait_impl!();
}

impl PersistentConfigurationMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn blockchain_service_url_result(
        self,
        result: Result<Option<String>, PersistentConfigError>,
    ) -> Self {
        self.blockchain_service_url_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_blockchain_service_url_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.set_blockchain_service_url_params = params.clone();
        self
    }

    pub fn set_blockchain_service_url_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_blockchain_service_url_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn current_schema_version_result(self, result: &str) -> Self {
        self.current_schema_version_results
            .borrow_mut()
            .push(result.to_string());
        self
    }

    pub fn chain_name_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.chain_name_params = params.clone();
        self
    }

    pub fn chain_name_result(self, result: String) -> Self {
        self.chain_name_results.borrow_mut().push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn change_password_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<String>, String)>>>,
    ) -> Self {
        self.change_password_params = params.clone();
        self
    }

    pub fn change_password_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.change_password_results.borrow_mut().push(result);
        self
    }

    pub fn check_password_params(mut self, params: &Arc<Mutex<Vec<Option<String>>>>) -> Self {
        self.check_password_params = params.clone();
        self
    }

    pub fn check_password_result(self, result: Result<bool, PersistentConfigError>) -> Self {
        self.check_password_results.borrow_mut().push(result);
        self
    }

    pub fn clandestine_port_result(self, result: Result<u16, PersistentConfigError>) -> Self {
        self.clandestine_port_results.borrow_mut().push(result);
        self
    }

    pub fn set_clandestine_port_params(mut self, params: &Arc<Mutex<Vec<u16>>>) -> Self {
        self.set_clandestine_port_params = params.clone();
        self
    }

    pub fn set_clandestine_port_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_clandestine_port_results.borrow_mut().push(result);
        self
    }

    pub fn min_hops_result(self, result: Result<Hops, PersistentConfigError>) -> Self {
        self.min_hops_results.borrow_mut().push(result);
        self
    }

    pub fn set_min_hops_params(
        mut self,
        params: &Arc<Mutex<Vec<Hops>>>,
    ) -> PersistentConfigurationMock {
        self.set_min_hops_params = params.clone();
        self
    }

    pub fn set_min_hops_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.set_min_hops_results.borrow_mut().push(result);
        self
    }

    pub fn neighborhood_mode_result(
        self,
        result: Result<NeighborhoodModeLight, PersistentConfigError>,
    ) -> Self {
        self.neighborhood_mode_results.borrow_mut().push(result);
        self
    }

    pub fn set_neighborhood_mode_params(
        mut self,
        params: &Arc<Mutex<Vec<NeighborhoodModeLight>>>,
    ) -> Self {
        self.set_neighborhood_mode_params = params.clone();
        self
    }

    pub fn set_neighborhood_mode_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_neighborhood_mode_results.borrow_mut().push(result);
        self
    }

    pub fn consuming_wallet_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.consuming_wallet_params = params.clone();
        self
    }

    pub fn consuming_wallet_result(
        self,
        result: Result<Option<Wallet>, PersistentConfigError>,
    ) -> Self {
        self.consuming_wallet_results.borrow_mut().push(result);
        self
    }

    pub fn consuming_wallet_private_key_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.consuming_wallet_private_key_params = params.clone();
        self
    }

    pub fn consuming_wallet_private_key_result(
        self,
        result: Result<Option<String>, PersistentConfigError>,
    ) -> Self {
        self.consuming_wallet_private_key_results
            .borrow_mut()
            .push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn set_wallet_info_params(
        mut self,
        params: &Arc<Mutex<Vec<(String, String, String)>>>,
    ) -> Self {
        self.set_wallet_info_params = params.clone();
        self
    }

    pub fn set_wallet_info_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_wallet_info_results.borrow_mut().push(result);
        self
    }

    pub fn gas_price_result(self, result: Result<u64, PersistentConfigError>) -> Self {
        self.gas_price_results.borrow_mut().push(result);
        self
    }

    pub fn set_gas_price_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_gas_price_params = params.clone();
        self
    }

    pub fn set_gas_price_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_gas_price_results.borrow_mut().push(result);
        self
    }

    pub fn past_neighbors_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.past_neighbors_params = params.clone();
        self
    }

    pub fn past_neighbors_result(
        self,
        result: Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>,
    ) -> Self {
        self.past_neighbors_results.borrow_mut().push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn set_past_neighbors_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<Vec<NodeDescriptor>>, String)>>>,
    ) -> Self {
        self.set_past_neighbors_params = params.clone();
        self
    }

    pub fn set_past_neighbors_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_past_neighbors_results.borrow_mut().push(result);
        self
    }

    pub fn earning_wallet_result(
        self,
        result: Result<Option<Wallet>, PersistentConfigError>,
    ) -> Self {
        self.earning_wallet_results.borrow_mut().push(result);
        self
    }

    pub fn earning_wallet_address_result(
        self,
        result: Result<Option<String>, PersistentConfigError>,
    ) -> Self {
        self.earning_wallet_address_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn start_block_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.start_block_params = params.clone();
        self
    }

    pub fn start_block_result(self, result: Result<Option<u64>, PersistentConfigError>) -> Self {
        self.start_block_results.borrow_mut().push(result);
        self
    }

    pub fn set_start_block_params(mut self, params: &Arc<Mutex<Vec<Option<u64>>>>) -> Self {
        self.set_start_block_params = params.clone();
        self
    }

    pub fn set_start_block_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_start_block_results.borrow_mut().push(result);
        self
    }

    pub fn max_block_count_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.max_block_count_params = params.clone();
        self
    }

    pub fn max_block_count_result(
        self,
        result: Result<Option<u64>, PersistentConfigError>,
    ) -> Self {
        self.max_block_count_results.borrow_mut().push(result);
        self
    }

    pub fn set_max_block_count_params(mut self, params: &Arc<Mutex<Vec<Option<u64>>>>) -> Self {
        self.set_max_block_count_params = params.clone();
        self
    }

    pub fn set_max_block_count_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_max_block_count_results.borrow_mut().push(result);
        self
    }

    pub fn set_start_block_from_txn_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<u64>, ArbitraryIdStamp)>>>,
    ) -> Self {
        self.set_start_block_from_txn_params = params.clone();
        self
    }

    pub fn set_start_block_from_txn_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_start_block_from_txn_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn payment_thresholds_result(
        self,
        result: Result<PaymentThresholds, PersistentConfigError>,
    ) -> Self {
        self.payment_thresholds_results.borrow_mut().push(result);
        self
    }

    pub fn set_payment_thresholds_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.set_payment_thresholds_params = params.clone();
        self
    }

    pub fn set_payment_thresholds_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_payment_thresholds_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn rate_pack_result(self, result: Result<RatePack, PersistentConfigError>) -> Self {
        self.rate_pack_results.borrow_mut().push(result);
        self
    }

    pub fn set_rate_pack_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.set_rate_pack_params = params.clone();
        self
    }

    pub fn set_rate_pack_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_rate_pack_results.borrow_mut().push(result);
        self
    }

    pub fn scan_intervals_result(
        self,
        result: Result<ScanIntervals, PersistentConfigError>,
    ) -> Self {
        self.scan_intervals_results.borrow_mut().push(result);
        self
    }

    pub fn set_scan_intervals_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.set_scan_intervals_params = params.clone();
        self
    }

    pub fn set_scan_intervals_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_scan_intervals_results.borrow_mut().push(result);
        self
    }

    pub fn mapping_protocol_result(
        self,
        result: Result<Option<AutomapProtocol>, PersistentConfigError>,
    ) -> Self {
        self.mapping_protocol_results.borrow_mut().push(result);
        self
    }

    pub fn set_mapping_protocol_params(
        mut self,
        params: &Arc<Mutex<Vec<Option<AutomapProtocol>>>>,
    ) -> Self {
        self.set_mapping_protocol_params = params.clone();
        self
    }

    pub fn set_mapping_protocol_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_mapping_protocol_results.borrow_mut().push(result);
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();

    // result_from allows a tester to push only a single value that can then be called multiple times.
    // as opposed to pushing the same value for every call.
    fn result_from<T: Clone>(results: &RefCell<Vec<T>>) -> T {
        let mut borrowed = results.borrow_mut();
        if borrowed.is_empty() {
            panic!("No mock results prepared")
        } else if borrowed.len() == 1 {
            borrowed[0].clone()
        } else {
            borrowed.remove(0)
        }
    }
}
