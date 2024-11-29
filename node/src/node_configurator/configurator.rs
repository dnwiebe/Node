// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::path::PathBuf;
use std::str::FromStr;

use actix::{Actor, Context, Handler, Recipient};

use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse,
    UiCheckPasswordRequest, UiCheckPasswordResponse, UiConfigurationRequest,
    UiConfigurationResponse, UiGenerateSeedSpec, UiGenerateWalletsRequest,
    UiGenerateWalletsResponse, UiNewPasswordBroadcast, UiPaymentThresholds, UiRatePack,
    UiRecoverWalletsRequest, UiRecoverWalletsResponse, UiScanIntervals, UiSetConfigurationRequest,
    UiSetConfigurationResponse, UiWalletAddressesRequest, UiWalletAddressesResponse,
};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{
    MessageBody, MessagePath, MessageTarget, NodeFromUiMessage, NodeToUiMessage,
};

use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
use crate::blockchain::bip39::Bip39;
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfigError, PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::neighborhood::{ConfigChange, ConfigChangeMsg, Hops, WalletPair};
use crate::sub_lib::peer_actors::{BindMessage, ConfigChangeSubs};
use crate::sub_lib::utils::{db_connection_launch_panic, handle_ui_crash_request};
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::main_cryptde;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use masq_lib::constants::{
    BAD_PASSWORD_ERROR, CONFIGURATOR_READ_ERROR, CONFIGURATOR_WRITE_ERROR, DERIVATION_PATH_ERROR,
    ILLEGAL_MNEMONIC_WORD_COUNT_ERROR, MISSING_DATA, MNEMONIC_PHRASE_ERROR, NON_PARSABLE_VALUE,
    UNKNOWN_ERROR, UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR, UNRECOGNIZED_PARAMETER,
};
use masq_lib::logger::Logger;
use masq_lib::utils::{derivation_path, to_string};
use rustc_hex::{FromHex, ToHex};
use tiny_hderive::bip32::ExtendedPrivKey;

pub const CRASH_KEY: &str = "CONFIGURATOR";

pub struct Configurator {
    persistent_config: Box<dyn PersistentConfiguration>,
    node_to_ui_sub_opt: Option<Recipient<NodeToUiMessage>>,
    config_change_subs_opt: Option<ConfigChangeSubs>,
    crashable: bool,
    logger: Logger,
}

impl Actor for Configurator {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Configurator {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.node_to_ui_sub_opt = Some(msg.peer_actors.ui_gateway.node_to_ui_message_sub.clone());
        self.config_change_subs_opt = Some(msg.peer_actors.config_change_subs());
    }
}

impl Handler<NodeFromUiMessage> for Configurator {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        if let Ok((body, context_id)) = UiChangePasswordRequest::fmb(msg.body.clone()) {
            let client_id = msg.client_id;
            self.call_handler(msg, |c| {
                c.handle_change_password(body, client_id, context_id)
            });
        } else if let Ok((body, context_id)) = UiCheckPasswordRequest::fmb(msg.body.clone()) {
            self.call_handler(msg, |c| c.handle_check_password(body, context_id));
        } else if let Ok((body, context_id)) = UiConfigurationRequest::fmb(msg.body.clone()) {
            self.call_handler(msg, |c| c.handle_configuration(body, context_id));
        } else if let Ok((body, context_id)) = UiGenerateWalletsRequest::fmb(msg.body.clone()) {
            self.call_handler(msg, |c| c.handle_generate_wallets(body, context_id));
        } else if let Ok((body, context_id)) = UiRecoverWalletsRequest::fmb(msg.body.clone()) {
            self.call_handler(msg, |c| c.handle_recover_wallets(body, context_id));
        } else if let Ok((body, context_id)) = UiSetConfigurationRequest::fmb(msg.body.clone()) {
            self.call_handler(msg, |c| c.handle_set_configuration(body, context_id));
        } else if let Ok((body, context_id)) = UiWalletAddressesRequest::fmb(msg.body.clone()) {
            self.call_handler(msg, |c| c.handle_wallet_addresses(body, context_id));
        } else {
            handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
        }
    }
}

type MessageError = (u64, String);

impl Configurator {
    pub fn new(data_directory: PathBuf, crashable: bool) -> Self {
        let initializer = DbInitializerReal::default();
        let conn = initializer
            .initialize(
                &data_directory,
                DbInitializationConfig::panic_on_migration(),
            )
            .unwrap_or_else(|err| db_connection_launch_panic(err, &data_directory));
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao)));
        Configurator {
            persistent_config,
            node_to_ui_sub_opt: None,
            config_change_subs_opt: None,
            crashable,
            logger: Logger::new("Configurator"),
        }
    }

    fn handle_check_password(
        &mut self,
        msg: UiCheckPasswordRequest,
        context_id: u64,
    ) -> MessageBody {
        match self
            .persistent_config
            .check_password(msg.db_password_opt.clone())
        {
            Ok(matches) => UiCheckPasswordResponse { matches }.tmb(context_id),
            Err(e) => {
                warning!(self.logger, "Failed to check password: {:?}", e);
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((CONFIGURATOR_READ_ERROR, format!("{:?}", e))),
                }
            }
        }
    }

    fn handle_change_password(
        &mut self,
        msg: UiChangePasswordRequest,
        client_id: u64,
        context_id: u64,
    ) -> MessageBody {
        match self
            .persistent_config
            .change_password(msg.old_password_opt.clone(), &msg.new_password)
        {
            Ok(_) => {
                let broadcast = UiNewPasswordBroadcast {}.tmb(0);
                self.send_new_password_to_subs(msg.new_password);
                self.send_to_ui_gateway(MessageTarget::AllExcept(client_id), broadcast);
                UiChangePasswordResponse {}.tmb(context_id)
            }

            Err(e) => {
                let error_m = Self::inspect_reason_of_password_error(e, &msg);
                warning!(self.logger, "Failed to change password: {}", error_m);
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((CONFIGURATOR_WRITE_ERROR, error_m)),
                }
            }
        }
    }

    fn inspect_reason_of_password_error(
        e: PersistentConfigError,
        msg: &UiChangePasswordRequest,
    ) -> String {
        if msg.old_password_opt.is_none() && e == PersistentConfigError::PasswordError {
            "The database already has a password. You may only change it".to_string()
        } else {
            format!("{:?}", e)
        }
    }

    fn handle_wallet_addresses(
        &self,
        msg: UiWalletAddressesRequest,
        context_id: u64,
    ) -> MessageBody {
        match self.get_wallet_addresses(msg.db_password.clone()) {
            Ok((consuming, earning)) => UiWalletAddressesResponse {
                consuming_wallet_address: consuming,
                earning_wallet_address: earning,
            }
            .tmb(context_id),
            Err((code, e_msg)) => {
                warning!(
                    self.logger,
                    "Failed to obtain wallet addresses: {}, {}",
                    code,
                    e_msg
                );
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((code, e_msg)),
                }
            }
        }
    }

    fn get_wallet_addresses(&self, db_password: String) -> Result<(String, String), (u64, String)> {
        let consuming_wallet_opt_result = self.persistent_config.consuming_wallet(&db_password);
        let earning_wallet_opt_result = self.persistent_config.earning_wallet();
        match (consuming_wallet_opt_result, earning_wallet_opt_result) {
            (Ok(None), Ok(None)) => {
                Err((MISSING_DATA, "Wallet pair not yet configured".to_string()))
            }
            (Ok(Some(consuming_wallet)), Ok(Some(earning_wallet))) => Ok((
                format!("{:?}", consuming_wallet.address()),
                format!("{:?}", earning_wallet.address()),
            )),
            (Ok(None), Ok(Some(_))) => {
                panic!("Database corrupted: earning wallet exists but consuming wallet does not")
            }
            (Ok(Some(_)), Ok(None)) => {
                panic!("Database corrupted: consuming wallet exists but earning wallet does not")
            }
            (Err(ce), _) => Err((
                CONFIGURATOR_READ_ERROR,
                format!("Consuming wallet error: {:?}", ce),
            )),
            (_, Err(ee)) => Err((
                CONFIGURATOR_READ_ERROR,
                format!("Earning wallet error: {:?}", ee),
            )),
        }
    }

    fn handle_generate_wallets(
        &mut self,
        msg: UiGenerateWalletsRequest,
        context_id: u64,
    ) -> MessageBody {
        let db_password = msg.db_password.clone();
        match Self::unfriendly_handle_generate_wallets(msg, context_id, &mut self.persistent_config)
        {
            Ok(message_body) => {
                self.send_updated_wallets_to_subs(&db_password);
                message_body
            }
            Err((code, msg)) => MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((code, msg)),
            },
        }
    }

    fn handle_recover_wallets(
        &mut self,
        msg: UiRecoverWalletsRequest,
        context_id: u64,
    ) -> MessageBody {
        let db_password = msg.db_password.clone();
        match Self::unfriendly_handle_recover_wallets(msg, context_id, &mut self.persistent_config)
        {
            Ok(message_body) => {
                self.send_updated_wallets_to_subs(&db_password);
                message_body
            }
            Err((code, msg)) => MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((code, msg)),
            },
        }
    }

    fn unfriendly_handle_generate_wallets(
        msg: UiGenerateWalletsRequest,
        context_id: u64,
        persistent_config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<MessageBody, MessageError> {
        Self::check_database_preconditions(
            persistent_config.as_ref(),
            "generate",
            &msg.db_password,
        )?;
        let seed_spec = msg.seed_spec_opt.clone().unwrap_or(UiGenerateSeedSpec {
            mnemonic_phrase_size_opt: Some(24),
            mnemonic_phrase_language_opt: Some("English".to_string()),
            mnemonic_passphrase_opt: None,
        });
        let (seed, mnemonic_phrase) = Self::generate_seed_and_mnemonic_phrase(
            &seed_spec.mnemonic_passphrase_opt,
            &seed_spec
                .mnemonic_phrase_language_opt
                .unwrap_or_else(|| "English".to_string()),
            seed_spec.mnemonic_phrase_size_opt.unwrap_or(24),
        )?;
        let consuming_derivation_path = match &msg.consuming_derivation_path_opt {
            Some(cdp) => {
                if msg.seed_spec_opt.is_none() {
                    return Err ((MISSING_DATA, "Cannot generate consuming wallet from derivation path without seed specification".to_string()));
                }
                cdp.clone()
            }
            None => derivation_path(0, 0),
        };
        let consuming_wallet = Self::generate_wallet(&seed, &consuming_derivation_path)?;
        let consuming_private_key =
            Self::generate_private_key(seed.as_bytes(), &consuming_derivation_path)?;
        let earning_derivation_path = match &msg.earning_derivation_path_opt {
            Some(edp) => {
                if msg.seed_spec_opt.is_none() {
                    return Err ((MISSING_DATA, "Cannot generate earning wallet from derivation path without seed specification".to_string()));
                }
                edp.clone()
            }
            None => derivation_path(0, 1),
        };
        let earning_wallet = Self::generate_wallet(&seed, &earning_derivation_path)?;
        let earning_private_key =
            Self::generate_private_key(seed.as_bytes(), &earning_derivation_path)?;
        Self::set_wallet_info(
            persistent_config,
            consuming_private_key.as_str(),
            &earning_wallet.string_address_from_keypair(),
            &msg.db_password,
        )?;
        Ok(UiGenerateWalletsResponse {
            mnemonic_phrase_opt: Some(mnemonic_phrase),
            consuming_wallet_address: consuming_wallet.string_address_from_keypair(),
            consuming_wallet_private_key: consuming_private_key,
            earning_wallet_address: earning_wallet.string_address_from_keypair(),
            earning_wallet_private_key: earning_private_key,
        }
        .tmb(context_id))
    }

    fn unfriendly_handle_recover_wallets(
        msg: UiRecoverWalletsRequest,
        context_id: u64,
        persistent_config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<MessageBody, MessageError> {
        Self::check_database_preconditions(
            persistent_config.as_ref(),
            "recover",
            &msg.db_password,
        )?;
        let (consuming_wallet_private_key, earning_wallet_address) = match msg.seed_spec_opt {
            None => match (&msg.consuming_private_key_opt, msg.earning_address_opt) {
                (Some (consuming_private_key), Some (earning_address)) => (consuming_private_key.clone(), earning_address),
                _ => return Err ((MISSING_DATA, "If you supply no seed information, you must supply both consuming wallet private key and earning wallet address".to_string())),
            },
            Some (seed_spec) => {
                let seed = Self::make_seed(
                    &seed_spec.mnemonic_passphrase_opt,
                    &seed_spec.mnemonic_phrase_language_opt.unwrap_or_else (|| "English".to_string()),
                    &seed_spec.mnemonic_phrase,
                )?;
                let consuming_private_key = match (msg.consuming_private_key_opt, msg.consuming_derivation_path_opt) {
                    (Some (consuming_private_key), _) => consuming_private_key,
                    (None, Some (consuming_derivation_path)) => {
                        Self::generate_private_key(seed.as_bytes(), consuming_derivation_path.as_str())?
                    },
                    _ => return Err((MISSING_DATA, "If you supply seed information, you must supply either the consuming wallet derivation path or the consuming wallet private key".to_string())),
                };
                let earning_address = match (msg.earning_address_opt, msg.earning_derivation_path_opt) {
                    (Some (earning_address), _) => earning_address,
                    (None, Some (earning_derivation_path)) =>  {
                        let wallet = Self::generate_wallet(&seed, earning_derivation_path.as_str())?;
                        wallet.string_address_from_keypair()
                    },
                    _ => return Err((MISSING_DATA, "If you supply seed information, you must supply either the earning wallet derivation path or the earning wallet address".to_string())),
                };
                (consuming_private_key, earning_address)
            },
        };
        Self::set_wallet_info(
            persistent_config,
            consuming_wallet_private_key.as_str(),
            earning_wallet_address.as_str(),
            &msg.db_password,
        )?;
        Ok(UiRecoverWalletsResponse {}.tmb(context_id))
    }

    fn check_database_preconditions(
        persistent_config: &dyn PersistentConfiguration,
        operation: &str,
        db_password: &str,
    ) -> Result<(), MessageError> {
        match persistent_config.check_password(Some(db_password.to_string())) {
            Err(e) => {
                return Err((
                    CONFIGURATOR_READ_ERROR,
                    format!("Error checking password: {:?}", e),
                ))
            }
            Ok(true) => (),
            Ok(false) => {
                return Err((
                    BAD_PASSWORD_ERROR,
                    format!("Bad password; can't {} wallets", operation),
                ))
            }
        }
        Ok(())
    }

    fn make_passphrase(passphrase_opt: &Option<String>) -> String {
        match passphrase_opt {
            Some(phrase) => phrase.to_string(),
            None => "".to_string(),
        }
    }

    fn make_seed(
        passphrase_opt: &Option<String>,
        language_str: &str,
        mnemonic_phrase: &[String],
    ) -> Result<Seed, MessageError> {
        let language = Self::parse_language(language_str)?;
        let mnemonic_passphrase = Self::make_passphrase(passphrase_opt);
        let mnemonic = match Mnemonic::from_phrase(&mnemonic_phrase.join(" "), language) {
            Ok(m) => m,
            Err(e) => {
                return Err((
                    MNEMONIC_PHRASE_ERROR,
                    format!("Couldn't make a mnemonic out of the supplied phrase: {}", e),
                ))
            }
        };
        Ok(Bip39::seed(&mnemonic, &mnemonic_passphrase))
    }

    fn generate_seed_and_mnemonic_phrase(
        passphrase_opt: &Option<String>,
        language_str: &str,
        word_count: usize,
    ) -> Result<(Seed, Vec<String>), MessageError> {
        let language = Self::parse_language(language_str)?;
        let mnemonic_type = Self::parse_word_count(word_count)?;
        let mnemonic = Bip39::mnemonic(mnemonic_type, language);
        let mnemonic_passphrase = Self::make_passphrase(passphrase_opt);
        let seed = Bip39::seed(&mnemonic, &mnemonic_passphrase);
        let phrase_words: Vec<String> = mnemonic.into_phrase().split(' ').map(to_string).collect();
        Ok((seed, phrase_words))
    }

    fn parse_language(language_str: &str) -> Result<Language, MessageError> {
        match vec![
            ("English", Language::English),
            ("Chinese", Language::ChineseSimplified),
            ("Traditional Chinese", Language::ChineseTraditional),
            ("French", Language::French),
            ("Italian", Language::Italian),
            ("Japanese", Language::Japanese),
            ("Korean", Language::Korean),
            ("Spanish", Language::Spanish),
        ]
        .into_iter()
        .find(|(name, _)| name == &language_str)
        {
            Some((_, language)) => Ok(language),
            None => Err((
                UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR,
                language_str.to_string(),
            )),
        }
    }

    fn parse_word_count(word_count: usize) -> Result<MnemonicType, MessageError> {
        match vec![
            MnemonicType::Words12,
            MnemonicType::Words15,
            MnemonicType::Words18,
            MnemonicType::Words21,
            MnemonicType::Words24,
        ]
        .into_iter()
        .find(|mt| mt.word_count() == word_count)
        {
            Some(mt) => Ok(mt),
            None => Err((ILLEGAL_MNEMONIC_WORD_COUNT_ERROR, word_count.to_string())),
        }
    }

    fn generate_wallet(seed: &Seed, derivation_path: &str) -> Result<Wallet, MessageError> {
        match Bip32EncryptionKeyProvider::try_from((seed.as_bytes(), derivation_path)) {
            Err(e) => Err((
                DERIVATION_PATH_ERROR,
                format!("Bad derivation-path syntax: {}: {}", e, derivation_path),
            )),
            Ok(kp) => Ok(Wallet::from(kp)),
        }
    }

    fn generate_private_key(seed: &[u8], derivation_path: &str) -> Result<String, MessageError> {
        let binary = match ExtendedPrivKey::derive(seed, derivation_path) {
            Ok(epk) => epk.secret(),
            Err(e) => {
                let err_string = format!("{:?}", e);
                return match err_string.as_str() {
                    "InvalidDerivationPath" => {
                        Err((DERIVATION_PATH_ERROR, derivation_path.to_string()))
                    }
                    e => Err((UNKNOWN_ERROR, e.to_string())), // Note: don't know how to test this
                };
            }
        };
        Ok((&binary).to_hex::<String>().to_uppercase())
    }

    fn handle_configuration(
        &mut self,
        msg: UiConfigurationRequest,
        context_id: u64,
    ) -> MessageBody {
        match Self::unfriendly_handle_configuration(msg, context_id, &mut self.persistent_config) {
            Ok(message_body) => message_body,
            Err((code, msg)) => MessageBody {
                opcode: "configuration".to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((code, msg)),
            },
        }
    }

    fn unfriendly_handle_configuration(
        msg: UiConfigurationRequest,
        context_id: u64,
        persistent_config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<MessageBody, MessageError> {
        let good_password_opt = match &msg.db_password_opt {
            None => None,
            Some(db_password) => {
                match persistent_config.check_password(Some(db_password.clone())) {
                    Ok(true) => Some(db_password),
                    Ok(false) => None,
                    Err(_) => return Err((CONFIGURATOR_READ_ERROR, "dbPassword".to_string())),
                }
            }
        };
        let blockchain_service_url_opt = Self::value_not_required(
            persistent_config.blockchain_service_url(),
            "blockchainServiceUrl",
        )?;
        let current_schema_version = persistent_config.current_schema_version();
        let clandestine_port =
            Self::value_required(persistent_config.clandestine_port(), "clandestinePort")?;
        let chain_name = persistent_config.chain_name();
        let gas_price = Self::value_required(persistent_config.gas_price(), "gasPrice")?;
        let earning_wallet_address_opt = Self::value_not_required(
            persistent_config.earning_wallet_address(),
            "earningWalletAddressOpt",
        )?;
        let start_block_opt =
            Self::value_not_required(persistent_config.start_block(), "startBlock")?;
        let max_block_count_opt = match persistent_config.max_block_count() {
            Ok(value) => value,
            Err(e) => panic!(
                "Database corruption: Could not read max block count: {:?}",
                e
            ),
        };
        let neighborhood_mode =
            Self::value_required(persistent_config.neighborhood_mode(), "neighborhoodMode")?
                .to_string();
        let port_mapping_protocol_opt =
            Self::value_not_required(persistent_config.mapping_protocol(), "portMappingProtocol")?
                .map(to_string);
        let (consuming_wallet_private_key_opt, consuming_wallet_address_opt, past_neighbors) =
            match good_password_opt {
                Some(password) => {
                    let (consuming_wallet_private_key_opt, consuming_wallet_address_opt) = {
                        match persistent_config.consuming_wallet_private_key(password) {
                        Ok(Some (private_key_hex)) => {
                            let private_key_bytes = match private_key_hex.from_hex::<Vec<u8>>() {
                                Ok(bytes) => bytes,
                                Err(e) => panic! ("Database corruption: consuming wallet private key '{}' cannot be converted from hexadecimal: {:?}", private_key_hex, e),
                            };
                            let key_pair = match Bip32EncryptionKeyProvider::from_raw_secret(private_key_bytes.as_slice()) {
                                Ok(pair) => pair,
                                Err(e) => panic!("Database corruption: consuming wallet private key '{}' is invalid: {:?}", private_key_hex, e),
                            };
                            (Some(private_key_hex), Some(format!("{:?}", key_pair.address())))
                        },
                        Ok(None) => (None, None),
                        Err (e) => panic!("Database corruption: error retrieving consuming wallet private key: {:?}", e),
                    }
                    };
                    let past_neighbors_opt = Self::value_not_required(
                        persistent_config.past_neighbors(password),
                        "pastNeighbors",
                    )?;
                    let past_neighbors = match past_neighbors_opt {
                        None => vec![],
                        Some(pns) => pns
                            .into_iter()
                            .map(|nd| nd.to_string(main_cryptde()))
                            .collect::<Vec<String>>(),
                    };
                    (
                        consuming_wallet_private_key_opt,
                        consuming_wallet_address_opt,
                        past_neighbors,
                    )
                }
                None => (None, None, vec![]),
            };
        let rate_pack = Self::value_required(persistent_config.rate_pack(), "ratePack")?;
        let scan_intervals =
            Self::value_required(persistent_config.scan_intervals(), "scanIntervals")?;
        let payment_thresholds =
            Self::value_required(persistent_config.payment_thresholds(), "paymentThresholds")?;
        let routing_byte_rate = rate_pack.routing_byte_rate;
        let routing_service_rate = rate_pack.routing_service_rate;
        let exit_byte_rate = rate_pack.exit_byte_rate;
        let exit_service_rate = rate_pack.exit_service_rate;
        let pending_payable_sec = scan_intervals.pending_payable_scan_interval.as_secs();
        let payable_sec = scan_intervals.payable_scan_interval.as_secs();
        let receivable_sec = scan_intervals.receivable_scan_interval.as_secs();
        let threshold_interval_sec = payment_thresholds.threshold_interval_sec;
        let debt_threshold_gwei = payment_thresholds.debt_threshold_gwei;
        let payment_grace_period_sec = payment_thresholds.payment_grace_period_sec;
        let maturity_threshold_sec = payment_thresholds.maturity_threshold_sec;
        let permanent_debt_allowed_gwei = payment_thresholds.permanent_debt_allowed_gwei;
        let unban_below_gwei = payment_thresholds.unban_below_gwei;
        let response = UiConfigurationResponse {
            blockchain_service_url_opt,
            current_schema_version,
            clandestine_port,
            chain_name,
            gas_price,
            max_block_count_opt,
            neighborhood_mode,
            consuming_wallet_private_key_opt,
            consuming_wallet_address_opt,
            earning_wallet_address_opt,
            port_mapping_protocol_opt,
            past_neighbors,
            payment_thresholds: UiPaymentThresholds {
                threshold_interval_sec,
                debt_threshold_gwei,
                maturity_threshold_sec,
                payment_grace_period_sec,
                permanent_debt_allowed_gwei,
                unban_below_gwei,
            },
            rate_pack: UiRatePack {
                routing_byte_rate,
                routing_service_rate,
                exit_byte_rate,
                exit_service_rate,
            },
            start_block_opt,
            scan_intervals: UiScanIntervals {
                pending_payable_sec,
                payable_sec,
                receivable_sec,
            },
        };
        Ok(response.tmb(context_id))
    }

    fn value_required<T>(
        result: Result<T, PersistentConfigError>,
        field_name: &str,
    ) -> Result<T, MessageError> {
        match result {
            Ok(v) => Ok(v),
            Err(_) => Err((CONFIGURATOR_READ_ERROR, field_name.to_string())),
        }
    }

    fn value_not_required<T>(
        result: Result<Option<T>, PersistentConfigError>,
        field_name: &str,
    ) -> Result<Option<T>, MessageError> {
        match result {
            Ok(option) => Ok(option),
            Err(_) => Err((CONFIGURATOR_READ_ERROR, field_name.to_string())),
        }
    }

    fn set_wallet_info(
        persistent_config: &mut Box<dyn PersistentConfiguration>,
        consuming_wallet_private_key: &str,
        earning_wallet_address: &str,
        db_password: &str,
    ) -> Result<(), MessageError> {
        if let Err(e) = persistent_config.set_wallet_info(
            consuming_wallet_private_key,
            earning_wallet_address,
            db_password,
        ) {
            return Err((
                CONFIGURATOR_WRITE_ERROR,
                format!("Wallet information could not be set: {:?}", e),
            ));
        }
        Ok(())
    }

    fn handle_set_configuration(
        &mut self,
        msg: UiSetConfigurationRequest,
        context_id: u64,
    ) -> MessageBody {
        debug!(
            self.logger,
            "A request from UI received: {:?} from context id: {}", msg, context_id
        );
        match self.unfriendly_handle_set_configuration(msg, context_id) {
            Ok(response) => response,
            Err((code, msg)) => {
                error!(
                    self.logger,
                    "{}",
                    format!("The UiSetConfigurationRequest failed with an error {code}: {msg}")
                );
                MessageBody {
                    opcode: "setConfiguration".to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((code, msg)),
                }
            }
        }
    }

    fn unfriendly_handle_set_configuration(
        &mut self,
        msg: UiSetConfigurationRequest,
        context_id: u64,
    ) -> Result<MessageBody, MessageError> {
        let password: Option<String> = None; //prepared for an upgrade with parameters requiring the password

        match password {
            None => match msg.name.as_str() {
                "gas-price" => self.set_gas_price(msg.value)?,
                "min-hops" => self.set_min_hops(msg.value)?,
                "start-block" => self.set_start_block(msg.value)?,
                _ => {
                    return Err((
                        UNRECOGNIZED_PARAMETER,
                        format!("This parameter name is not known: {}", &msg.name),
                    ))
                }
            },
            Some(_password) => {
                unimplemented!();
            }
        };

        Ok(UiSetConfigurationResponse {}.tmb(context_id))
    }

    fn set_gas_price(&mut self, string_price: String) -> Result<(), (u64, String)> {
        let price_number = match string_price.parse::<u64>() {
            Ok(num) => num,
            Err(e) => return Err((NON_PARSABLE_VALUE, format!("gas price: {:?}", e))),
        };
        match self.persistent_config.set_gas_price(price_number) {
            Ok(_) => Ok(()),
            Err(e) => Err((CONFIGURATOR_WRITE_ERROR, format!("gas price: {:?}", e))),
        }
    }

    fn set_min_hops(&mut self, min_hops_value: String) -> Result<(), (u64, String)> {
        let min_hops = match Hops::from_str(&min_hops_value) {
            Ok(min_hops) => min_hops,
            Err(e) => {
                return Err((NON_PARSABLE_VALUE, format!("min hops: {:?}", e)));
            }
        };
        match self.persistent_config.set_min_hops(min_hops) {
            Ok(_) => {
                debug!(
                    self.logger,
                    "The value of min-hops has been changed to {}-hop inside the database",
                    min_hops
                );
                self.send_config_change_msg(ConfigChangeMsg {
                    change: ConfigChange::UpdateMinHops(min_hops),
                });
                Ok(())
            }
            Err(e) => Err((CONFIGURATOR_WRITE_ERROR, format!("min hops: {:?}", e))),
        }
    }

    fn set_start_block(&mut self, string_number: String) -> Result<(), (u64, String)> {
        let block_number_opt = if "none".eq_ignore_ascii_case(&string_number) {
            None
        } else {
            match string_number.parse::<u64>() {
                Ok(num) => Some(num),
                Err(e) => return Err((NON_PARSABLE_VALUE, format!("start block: {:?}", e))),
            }
        };
        match self.persistent_config.set_start_block(block_number_opt) {
            Ok(_) => Ok(()),
            Err(e) => Err((CONFIGURATOR_WRITE_ERROR, format!("start block: {:?}", e))),
        }
    }

    fn send_to_ui_gateway(&self, target: MessageTarget, body: MessageBody) {
        let msg = NodeToUiMessage { target, body };
        self.node_to_ui_sub_opt
            .as_ref()
            .expect("Configurator is unbound")
            .try_send(msg)
            .expect("UiGateway is dead");
    }

    fn send_config_change_msg(&self, msg: ConfigChangeMsg) {
        self.config_change_subs_opt
            .as_ref()
            .expect("ConfigChangeSubs are uninitialized")
            .iter()
            .for_each(|recipient| {
                recipient
                    .try_send(msg.clone())
                    .expect("ConfigChangeMsg recipient is dead")
            })
    }

    fn send_new_password_to_subs(&self, new_password: String) {
        let msg = ConfigChangeMsg {
            change: ConfigChange::UpdatePassword(new_password),
        };
        self.send_config_change_msg(msg);
    }

    fn send_updated_wallets_to_subs(&self, db_password: &str) {
        let consuming_wallet_result_opt = self
            .persistent_config
            .as_ref()
            .consuming_wallet(db_password);
        let earning_wallet_result_opt = self.persistent_config.as_ref().earning_wallet();
        if let (Ok(Some(new_consuming_wallet)), Ok(Some(new_earning_wallet))) =
            (consuming_wallet_result_opt, earning_wallet_result_opt)
        {
            self.send_config_change_msg(ConfigChangeMsg {
                change: ConfigChange::UpdateWallets(WalletPair {
                    consuming_wallet: new_consuming_wallet,
                    earning_wallet: new_earning_wallet,
                }),
            });
        } else {
            panic!("Unable to retrieve wallets from persistent configuration")
        };
    }

    fn call_handler<F: FnOnce(&mut Configurator) -> MessageBody>(
        &mut self,
        msg: NodeFromUiMessage,
        handler: F,
    ) {
        self.log_begin_handle(&msg);
        let response = handler(self);
        self.log_end_handle(&response);
        self.send_to_ui_gateway(ClientId(msg.client_id), response);
    }

    fn log_begin_handle(&self, msg: &NodeFromUiMessage) {
        debug!(
            &self.logger,
            "Handling {} message from client {}", msg.body.opcode, msg.client_id
        );
    }

    fn log_end_handle(&self, body: &MessageBody) {
        debug!(&self.logger, "Sending response to {} command:", body.opcode);
    }
}

#[cfg(test)]
mod tests {
    use actix::System;
    use masq_lib::messages::{
        ToMessageBody, UiCheckPasswordRequest, UiCheckPasswordResponse, UiGenerateSeedSpec,
        UiGenerateWalletsResponse, UiPaymentThresholds, UiRatePack, UiRecoverSeedSpec,
        UiScanIntervals, UiStartOrder, UiWalletAddressesRequest, UiWalletAddressesResponse,
    };
    use masq_lib::ui_gateway::{MessagePath, MessageTarget};
    use std::path::Path;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::db_config::persistent_configuration::{
        PersistentConfigError, PersistentConfigurationReal,
    };
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};

    use super::*;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::bip39::Bip39;
    use crate::blockchain::test_utils::make_meaningless_phrase_words;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::sub_lib::accountant::{PaymentThresholds, ScanIntervals};
    use crate::sub_lib::cryptde::PublicKey as PK;
    use crate::sub_lib::cryptde::{CryptDE, PlainData};
    use crate::sub_lib::neighborhood::{ConfigChange, NodeDescriptor, RatePack};
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::unshared_test_utils::{
        assert_on_initialization_with_panic_on_migration, configure_default_persistent_config,
        prove_that_crash_request_handler_is_hooked_up, ZERO,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use bip39::{Language, Mnemonic};
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::MISSING_DATA;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::{derivation_path, AutomapProtocol, NeighborhoodModeLight};
    use rustc_hex::FromHex;
    use tiny_hderive::bip32::ExtendedPrivKey;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "CONFIGURATOR")
    }

    #[test]
    fn constructor_connects_with_database() {
        let data_dir =
            ensure_node_home_directory_exists("configurator", "constructor_connects_with_database");
        let verifier = PersistentConfigurationReal::new(Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&data_dir, DbInitializationConfig::test_default())
                .unwrap(),
        )));
        let peer_actors = peer_actors_builder().build();
        let mut subject = Configurator::new(data_dir, false);
        subject.config_change_subs_opt = Some(peer_actors.config_change_subs());
        subject.node_to_ui_sub_opt = Some(peer_actors.ui_gateway.node_to_ui_message_sub);

        let _ = subject.handle_change_password(
            UiChangePasswordRequest {
                old_password_opt: None,
                new_password: "password".to_string(),
            },
            0,
            0,
        );

        assert_eq!(
            verifier.check_password(Some("password".to_string())),
            Ok(true)
        )
    }

    #[test]
    fn constructor_panics_on_database_migration() {
        let data_dir = ensure_node_home_directory_exists(
            "configurator",
            "constructor_panics_on_database_migration",
        );

        let act = |data_dir: &Path| {
            Configurator::new(data_dir.to_path_buf(), false);
        };

        assert_on_initialization_with_panic_on_migration(&data_dir, &act);
    }

    #[test]
    fn ignores_unexpected_message() {
        let system = System::new("test");
        let subject = make_subject(None);
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording) = make_recorder();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let recording = ui_gateway_recording.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    #[test]
    fn check_password_works() {
        let system = System::new("test");
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(false));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiCheckPasswordRequest {
                    db_password_opt: Some("password".to_string()),
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(*check_password_params, vec![Some("password".to_string())]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiCheckPasswordResponse { matches: false }.tmb(4321)
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    #[test]
    fn handle_check_password_handles_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiCheckPasswordRequest {
            db_password_opt: None,
        };

        let result = subject.handle_check_password(msg, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "checkPassword".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((CONFIGURATOR_READ_ERROR, "NotPresent".to_string()))
            }
        );
        TestLogHandler::new()
            .exists_log_containing("WARN: Configurator: Failed to check password: NotPresent");
    }

    #[test]
    fn the_password_is_synchronised_among_other_actors_when_modified() {
        let system = System::new("the_password_is_synchronised_among_other_actors_when_modified");
        let new_password = "omae wa mou shindeiru";
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .change_password_result(Ok(()));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood)
            .ui_gateway(ui_gateway)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiChangePasswordRequest {
                    old_password_opt: None,
                    new_password: new_password.to_string(),
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let expected_configuration_msg = ConfigChangeMsg {
            change: ConfigChange::UpdatePassword(new_password.to_string()),
        };
        assert_eq!(
            neighborhood_recording.get_record::<ConfigChangeMsg>(0),
            &expected_configuration_msg
        );
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: MessageTarget::AllExcept(1234),
                body: UiNewPasswordBroadcast {}.tmb(0)
            }
        );
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(1),
            &NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiChangePasswordResponse {}.tmb(4321)
            }
        );
    }

    #[test]
    fn the_wallets_are_synchronised_among_other_actors_when_modified() {
        assert_wallets_synchronisation_among_other_actors(NodeFromUiMessage {
            client_id: 1234,
            body: make_example_generate_wallets_request().tmb(4321),
        });
        assert_wallets_synchronisation_among_other_actors(NodeFromUiMessage {
            client_id: 1234,
            body: make_example_recover_wallets_request_with_paths().tmb(4321),
        });
    }

    fn assert_wallets_synchronisation_among_other_actors(msg: NodeFromUiMessage) {
        let system = System::new("assert_wallets_synchronisation_among_other_actors");
        let consuming_wallet = make_paying_wallet(b"consuming");
        let earning_wallet = make_wallet("earning");
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .set_wallet_info_result(Ok(()))
            .consuming_wallet_result(Ok(Some(consuming_wallet.clone())))
            .earning_wallet_result(Ok(Some(earning_wallet.clone())));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood)
            .accountant(accountant)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(msg).unwrap();

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let expected_configuration_msg = ConfigChangeMsg {
            change: ConfigChange::UpdateWallets(WalletPair {
                consuming_wallet,
                earning_wallet,
            }),
        };
        assert_eq!(
            accountant_recording.get_record::<ConfigChangeMsg>(0),
            &expected_configuration_msg
        );
        assert_eq!(
            neighborhood_recording.get_record::<ConfigChangeMsg>(0),
            &expected_configuration_msg
        );
    }

    #[test]
    #[should_panic(expected = "Unable to retrieve wallets from persistent configuration")]
    fn panics_if_consuming_wallet_can_not_be_retrieved_before_sending_to_subs() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .set_wallet_info_result(Ok(()))
            .consuming_wallet_result(Ok(None))
            .earning_wallet_result(Ok(Some(make_wallet("earning"))));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: make_example_generate_wallets_request().tmb(4321),
            })
            .unwrap();

        let system = System::new("test");
        System::current().stop();
        system.run();
    }

    #[test]
    fn handle_change_password_can_process_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new().change_password_result(Err(
            PersistentConfigError::DatabaseError("Didn't work good".to_string()),
        ));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "".to_string(),
        };

        let result = subject.handle_change_password(msg, 1234, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "changePassword".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    r#"DatabaseError("Didn't work good")"#.to_string()
                )),
            }
        );
        TestLogHandler::new().exists_log_containing(
            r#"WARN: Configurator: Failed to change password: DatabaseError("Didn't work good")"#,
        );
    }

    #[test]
    fn handle_set_password_used_repeatedly_recommends_change_password_command_for_next_time() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .change_password_result(Err(PersistentConfigError::PasswordError));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "IAmSureThisPasswordMustBeRightDamn".to_string(),
        };

        let result = subject.handle_change_password(msg, 1234, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "changePassword".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "The database already has a password. You may only change it".to_string()
                )),
            }
        );
        TestLogHandler::new().exists_log_containing(
            "WARN: Configurator: Failed to change password: \
            The database already has a password. You may only change it",
        );
    }

    #[test]
    fn handle_wallet_addresses_works() {
        let system = System::new("test");
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .consuming_wallet_result(Ok(Some(
                Wallet::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            )))
            .earning_wallet_result(Ok(Some(
                Wallet::from_str("0x01234567890aa345678901234567890123456789").unwrap(),
            )));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiWalletAddressesRequest {
                    db_password: "123password".to_string(),
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiWalletAddressesResponse {
                    consuming_wallet_address: "0x1234567890123456789012345678901234567890"
                        .to_string(),
                    earning_wallet_address: "0x01234567890aa345678901234567890123456789"
                        .to_string()
                }
                .tmb(4321)
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    #[test]
    fn handle_wallet_addresses_works_if_consuming_wallet_private_key_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .consuming_wallet_result(Err(PersistentConfigError::DatabaseError(
                "Unknown error 3".to_string(),
            )))
            .earning_wallet_result(Ok(Some(
                Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap(),
            )));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let result = subject.handle_wallet_addresses(msg, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "walletAddresses".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    r#"Consuming wallet error: DatabaseError("Unknown error 3")"#.to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(
            r#"WARN: Configurator: Failed to obtain wallet addresses: 281474976710657, Consuming wallet error: DatabaseError("Unknown error 3")"#,
        );
    }

    #[test]
    fn handle_wallet_addresses_works_if_earning_wallet_address_triggers_database_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .consuming_wallet_result(Ok(Some(
                Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap(),
            )))
            .earning_wallet_result(Err(PersistentConfigError::DatabaseError(
                "Unknown error 3".to_string(),
            )));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let result = subject.handle_wallet_addresses(msg, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "walletAddresses".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    r#"Earning wallet error: DatabaseError("Unknown error 3")"#.to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(
            r#"WARN: Configurator: Failed to obtain wallet addresses: 281474976710657, Earning wallet error: DatabaseError("Unknown error 3")"#,
        );
    }

    #[test]
    #[should_panic(
        expected = "Database corrupted: consuming wallet exists but earning wallet does not"
    )]
    fn handle_wallet_addresses_panics_if_earning_wallet_address_is_missing() {
        let persistent_config = PersistentConfigurationMock::new()
            .consuming_wallet_result(Ok(Some(
                Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap(),
            )))
            .earning_wallet_result(Ok(None));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let _ = subject.handle_wallet_addresses(msg, 1234);
    }

    #[test]
    #[should_panic(
        expected = "Database corrupted: earning wallet exists but consuming wallet does not"
    )]
    fn handle_wallet_addresses_panics_if_consuming_wallet_address_is_missing() {
        let persistent_config = PersistentConfigurationMock::new()
            .consuming_wallet_result(Ok(None))
            .earning_wallet_result(Ok(Some(
                Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap(),
            )));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let _ = subject.handle_wallet_addresses(msg, 1234);
    }

    #[test]
    fn generate_private_key_handles_bad_derivation_path() {
        let seed = PlainData::new(b"0123456789ABCDEF0123456789ABCDEF");
        let derivation_path = "booga";

        let result = Configurator::generate_private_key(seed.as_ref(), derivation_path);

        assert_eq!(result, Err((DERIVATION_PATH_ERROR, "booga".to_string())));
    }

    #[test]
    fn handle_generate_wallets_works() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let consuming_wallet_for_mock = make_paying_wallet(b"consuming");
        let earning_wallet_for_mock = make_wallet("earning");
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(true))
            .set_wallet_info_params(&set_wallet_info_params_arc)
            .set_wallet_info_result(Ok(()))
            .consuming_wallet_result(Ok(Some(consuming_wallet_for_mock)))
            .earning_wallet_result(Ok(Some(earning_wallet_for_mock)));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: make_example_generate_wallets_request().tmb(4321),
            })
            .unwrap();

        let system = System::new("test");
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        let (generated_wallets, context_id) =
            UiGenerateWalletsResponse::fmb(response.body.clone()).unwrap();
        assert_eq!(context_id, 4321);
        let mnemonic_phrase = generated_wallets.mnemonic_phrase_opt.unwrap();
        assert_eq!(mnemonic_phrase.len(), 24);
        let mnemonic_phrase_string = mnemonic_phrase.join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase_string, Language::English).unwrap();
        let seed = PlainData::new(Bip39::seed(&mnemonic, "booga").as_ref());
        let consuming_epk =
            ExtendedPrivKey::derive(seed.as_slice(), derivation_path(0, 4).as_str()).unwrap();
        let consuming_private_key = consuming_epk.secret().to_hex::<String>().to_uppercase();
        let consuming_wallet = Wallet::from(
            Bip32EncryptionKeyProvider::try_from((seed.as_slice(), derivation_path(0, 4).as_str()))
                .unwrap(),
        );
        assert_eq!(
            generated_wallets.consuming_wallet_address,
            consuming_wallet.string_address_from_keypair()
        );
        assert_eq!(
            generated_wallets.consuming_wallet_private_key,
            Configurator::generate_private_key(
                &Bip39::seed(&mnemonic, "booga").as_bytes(),
                derivation_path(0, 4).as_str()
            )
            .unwrap()
        );
        let earning_wallet = Wallet::from(
            Bip32EncryptionKeyProvider::try_from((seed.as_slice(), derivation_path(0, 5).as_str()))
                .unwrap(),
        );
        assert_eq!(
            generated_wallets.earning_wallet_address,
            earning_wallet.string_address_from_keypair()
        );
        assert_eq!(
            generated_wallets.earning_wallet_private_key,
            Configurator::generate_private_key(
                &Bip39::seed(&mnemonic, "booga").as_bytes(),
                derivation_path(0, 5).as_str()
            )
            .unwrap()
        );
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(*check_password_params, vec![Some("password".to_string())]);
        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(
                consuming_private_key,
                earning_wallet.string_address_from_keypair(),
                "password".to_string(),
            )]
        );
    }

    #[test]
    fn handle_generate_wallets_works_if_check_password_fails() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_generate_wallets(make_example_generate_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    "Error checking password: NotPresent".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_generate_wallets_works_if_password_is_incorrect() {
        let persistent_config = PersistentConfigurationMock::new().check_password_result(Ok(false));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_generate_wallets(make_example_generate_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    BAD_PASSWORD_ERROR,
                    "Bad password; can't generate wallets".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_generate_wallets_manages_error_if_chosen_language_isnt_in_list() {
        let persistent_config = PersistentConfigurationMock::new().check_password_result(Ok(true));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiGenerateWalletsRequest {
            db_password: "blabla".to_string(),
            seed_spec_opt: Some(UiGenerateSeedSpec {
                mnemonic_phrase_size_opt: Some(24),
                mnemonic_phrase_language_opt: Some("SuperSpecial".to_string()),
                mnemonic_passphrase_opt: None,
            }),
            consuming_derivation_path_opt: Some(derivation_path(0, 4)),
            earning_derivation_path_opt: Some(derivation_path(0, 5)),
        };

        let result = subject.handle_generate_wallets(msg, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR,
                    "SuperSpecial".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_generate_wallets_works_if_wallet_info_cant_be_set() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .set_wallet_info_result(Err(PersistentConfigError::BadDerivationPathFormat(
                "booga".to_string(),
            )));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_generate_wallets(make_example_generate_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "Wallet information could not be set: BadDerivationPathFormat(\"booga\")"
                        .to_string()
                ))
            }
        )
    }

    #[test]
    fn unfriendly_handle_generate_wallets_handles_consuming_path_without_seed_spec() {
        let mut persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(PersistentConfigurationMock::new().check_password_result(Ok(true)));
        let msg = UiGenerateWalletsRequest {
            db_password: "password".to_string(),
            seed_spec_opt: None,
            consuming_derivation_path_opt: Some("doesn't matter".to_string()),
            earning_derivation_path_opt: None,
        };

        let result =
            Configurator::unfriendly_handle_generate_wallets(msg, 1234, &mut persistent_config)
                .err()
                .unwrap();

        assert_eq!(
            result,
            (
                MISSING_DATA,
                "Cannot generate consuming wallet from derivation path without seed specification"
                    .to_string()
            )
        )
    }

    #[test]
    fn unfriendly_handle_generate_wallets_handles_earning_path_without_seed_spec() {
        let mut persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(PersistentConfigurationMock::new().check_password_result(Ok(true)));
        let msg = UiGenerateWalletsRequest {
            db_password: "password".to_string(),
            seed_spec_opt: None,
            consuming_derivation_path_opt: None,
            earning_derivation_path_opt: Some("doesn't matter".to_string()),
        };

        let result =
            Configurator::unfriendly_handle_generate_wallets(msg, 1234, &mut persistent_config)
                .err()
                .unwrap();

        assert_eq!(
            result,
            (
                MISSING_DATA,
                "Cannot generate earning wallet from derivation path without seed specification"
                    .to_string()
            )
        )
    }

    #[test]
    fn unfriendly_handle_generate_wallets_defaults_language_to_english_and_words_to_24() {
        let mut persistent_config: Box<dyn PersistentConfiguration> = Box::new(
            PersistentConfigurationMock::new()
                .check_password_result(Ok(true))
                .set_wallet_info_result(Ok(())),
        );
        let derivation_path = derivation_path(10, 20);
        let msg = UiGenerateWalletsRequest {
            db_password: "password".to_string(),
            seed_spec_opt: Some(UiGenerateSeedSpec {
                mnemonic_phrase_size_opt: None,
                mnemonic_phrase_language_opt: None,
                mnemonic_passphrase_opt: None,
            }),
            consuming_derivation_path_opt: Some(derivation_path.clone()),
            earning_derivation_path_opt: None,
        };

        let result =
            Configurator::unfriendly_handle_generate_wallets(msg, 1234, &mut persistent_config)
                .unwrap();

        let response = UiGenerateWalletsResponse::fmb(result).unwrap().0;
        assert_eq!(response.mnemonic_phrase_opt.as_ref().unwrap().len(), 24);
        let phrase_str = response.mnemonic_phrase_opt.unwrap().join(" ");
        // only works if phrase is in English
        let _ = Mnemonic::from_phrase(&phrase_str, Language::English).unwrap();
    }

    #[test]
    fn handle_recover_wallets_works_with_earning_wallet_address() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(true))
            .set_wallet_info_params(&set_wallet_info_params_arc)
            .set_wallet_info_result(Ok(()))
            .consuming_wallet_result(Ok(Some(make_paying_wallet(b"consuming"))))
            .earning_wallet_result(Ok(Some(make_wallet("earning"))));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let mut request = make_example_recover_wallets_request_with_paths();
        request.earning_derivation_path_opt = None;
        request.earning_address_opt =
            Some("0x005e288d713a5fb3d7c9cf1b43810a98688c7223".to_string());

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: request.clone().tmb(4321),
            })
            .unwrap();

        let system = System::new("test");
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        let (_, context_id) = UiRecoverWalletsResponse::fmb(response.body.clone()).unwrap();
        assert_eq!(context_id, 4321);
        let mnemonic_phrase = request
            .seed_spec_opt
            .as_ref()
            .unwrap()
            .mnemonic_phrase
            .join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let seed = PlainData::new(
            Bip39::seed(
                &mnemonic,
                request
                    .seed_spec_opt
                    .as_ref()
                    .unwrap()
                    .mnemonic_passphrase_opt
                    .as_ref()
                    .unwrap(),
            )
            .as_ref(),
        );
        let consuming_epk = ExtendedPrivKey::derive(
            seed.as_slice(),
            request.consuming_derivation_path_opt.unwrap().as_str(),
        )
        .unwrap();
        let consuming_private_key = consuming_epk.secret().to_hex::<String>().to_uppercase();
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(
            *check_password_params,
            vec![Some(request.db_password.clone())]
        );

        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(
                consuming_private_key,
                request.earning_address_opt.unwrap(),
                request.db_password,
            )]
        );
    }

    fn make_config_change_subs() -> ConfigChangeSubs {
        let peer_actors = peer_actors_builder().build();
        peer_actors.config_change_subs()
    }

    #[test]
    fn handle_recover_wallets_works_with_earning_wallet_derivation_path() {
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .set_wallet_info_params(&set_wallet_info_params_arc)
            .set_wallet_info_result(Ok(()))
            .consuming_wallet_result(Ok(Some(make_paying_wallet(b"consuming"))))
            .earning_wallet_result(Ok(Some(make_wallet("earning"))));
        let mut subject = make_subject(Some(persistent_config));
        subject.config_change_subs_opt = Some(make_config_change_subs());
        let mut request = make_example_recover_wallets_request_with_paths();
        request.earning_derivation_path_opt = Some(derivation_path(0, 5));

        let result = subject.handle_recover_wallets(request.clone(), 1234);

        assert_eq!(result, UiRecoverWalletsResponse {}.tmb(1234));
        let mnemonic_phrase = request
            .seed_spec_opt
            .as_ref()
            .unwrap()
            .mnemonic_phrase
            .join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let seed = Bip39::seed(
            &mnemonic,
            request
                .seed_spec_opt
                .as_ref()
                .unwrap()
                .mnemonic_passphrase_opt
                .as_ref()
                .unwrap(),
        );
        let consuming_epk = ExtendedPrivKey::derive(
            seed.as_bytes(),
            request.consuming_derivation_path_opt.unwrap().as_str(),
        )
        .unwrap();
        let consuming_private_key = consuming_epk.secret().to_hex::<String>().to_uppercase();
        let earning_wallet = Configurator::generate_wallet(
            &seed,
            request.earning_derivation_path_opt.as_ref().unwrap(),
        )
        .unwrap();
        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(
                consuming_private_key,
                earning_wallet.string_address_from_keypair(),
                request.db_password,
            )]
        );
    }

    #[test]
    fn handle_recover_wallets_works_without_passphrase() {
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .set_wallet_info_params(&set_wallet_info_params_arc)
            .set_wallet_info_result(Ok(()))
            .consuming_wallet_result(Ok(Some(make_paying_wallet(b"consuming"))))
            .earning_wallet_result(Ok(Some(make_wallet("earning"))));
        let mut subject = make_subject(Some(persistent_config));
        subject.config_change_subs_opt = Some(make_config_change_subs());
        let mut request = make_example_recover_wallets_request_with_paths();
        request
            .seed_spec_opt
            .as_mut()
            .unwrap()
            .mnemonic_passphrase_opt = None;

        let result = subject.handle_recover_wallets(request.clone(), 1234);

        assert_eq!(result, UiRecoverWalletsResponse {}.tmb(1234));
        let mnemonic_phrase = request
            .seed_spec_opt
            .as_ref()
            .unwrap()
            .mnemonic_phrase
            .join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let seed = Bip39::seed(&mnemonic, "");
        let consuming_epk = ExtendedPrivKey::derive(
            seed.as_bytes(),
            request.consuming_derivation_path_opt.unwrap().as_str(),
        )
        .unwrap();
        let consuming_private_key = consuming_epk.secret().to_hex::<String>().to_uppercase();
        let earning_private_key = ExtendedPrivKey::derive(
            seed.as_bytes(),
            request
                .earning_derivation_path_opt
                .as_ref()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        let earning_keypair =
            Bip32EncryptionKeyProvider::from_raw_secret(&earning_private_key.secret()).unwrap();
        let earning_wallet = Wallet::from(earning_keypair);
        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(
                consuming_private_key,
                format!("{:?}", earning_wallet.address()),
                request.db_password,
            )]
        );
    }

    #[test]
    fn handle_recover_wallets_works_with_check_password_error() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));
        let request = make_example_recover_wallets_request_with_paths();

        let result = subject.handle_recover_wallets(request, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    "Error checking password: NotPresent".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_works_with_incorrect_password() {
        let persistent_config = PersistentConfigurationMock::new().check_password_result(Ok(false));
        let mut subject = make_subject(Some(persistent_config));
        let request = make_example_recover_wallets_request_with_paths();

        let result = subject.handle_recover_wallets(request, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    BAD_PASSWORD_ERROR,
                    "Bad password; can't recover wallets".to_string(),
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_works_if_mnemonic_cant_be_generated_from_phrase() {
        let persistent_config = PersistentConfigurationMock::new().check_password_result(Ok(true));
        let mut subject = make_subject(Some(persistent_config));
        let mut request = make_example_recover_wallets_request_with_paths();
        request.seed_spec_opt.as_mut().unwrap().mnemonic_phrase =
            vec!["ooga".to_string(), "booga".to_string()];

        let result = subject.handle_recover_wallets(request, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    MNEMONIC_PHRASE_ERROR,
                    "Couldn't make a mnemonic out of the supplied phrase: invalid word in phrase"
                        .to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_works_if_wallet_info_cant_be_set() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .set_wallet_info_result(Err(PersistentConfigError::BadDerivationPathFormat(
                "booga".to_string(),
            )));
        let mut subject = make_subject(Some(persistent_config));

        let result =
            subject.handle_recover_wallets(make_example_recover_wallets_request_with_paths(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "Wallet information could not be set: BadDerivationPathFormat(\"booga\")"
                        .to_string()
                ))
            }
        )
    }

    #[test]
    fn unfriendly_handle_recover_wallets_handles_useless_seed_spec_with_key_and_address() {
        let db_password = "password".to_string();
        let consuming_private_key =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string();
        let earning_address = "0x0123456789012345678901234567890123456789".to_string();
        let msg = UiRecoverWalletsRequest {
            db_password: db_password.clone(),
            seed_spec_opt: Some(UiRecoverSeedSpec {
                mnemonic_phrase: make_meaningless_phrase_words(),
                mnemonic_phrase_language_opt: Some("English".to_string()),
                mnemonic_passphrase_opt: None,
            }),
            consuming_derivation_path_opt: None,
            consuming_private_key_opt: Some(consuming_private_key.clone()),
            earning_derivation_path_opt: None,
            earning_address_opt: Some(earning_address.clone()),
        };
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config: Box<dyn PersistentConfiguration> = Box::new(
            configure_default_persistent_config(ZERO)
                .check_password_result(Ok(true))
                .set_wallet_info_params(&set_wallet_info_params_arc)
                .set_wallet_info_result(Ok(())),
        );

        let _ = Configurator::unfriendly_handle_recover_wallets(msg, 1234, &mut persistent_config)
            .unwrap();

        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(consuming_private_key, earning_address, db_password)]
        )
    }

    #[test]
    fn unfriendly_handle_recover_wallets_handles_no_seed_spec_and_only_earning_wallet_address() {
        let msg = UiRecoverWalletsRequest {
            db_password: "password".to_string(),
            seed_spec_opt: None,
            consuming_derivation_path_opt: None,
            consuming_private_key_opt: None,
            earning_derivation_path_opt: None,
            earning_address_opt: Some("0x0123456789012345678901234567890123456789".to_string()),
        };
        let mut persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(configure_default_persistent_config(ZERO).check_password_result(Ok(true)));

        let result =
            Configurator::unfriendly_handle_recover_wallets(msg, 1234, &mut persistent_config);

        assert_eq! (result, Err((MISSING_DATA, "If you supply no seed information, you must supply both consuming wallet private key and earning wallet address".to_string())));
    }

    #[test]
    fn unfriendly_handle_recover_wallets_handles_seed_but_nothing_about_consuming_wallet() {
        let db_password = "password".to_string();
        let earning_address = "0x0123456789012345678901234567890123456789".to_string();
        let msg = UiRecoverWalletsRequest {
            db_password,
            seed_spec_opt: Some(UiRecoverSeedSpec {
                mnemonic_phrase: make_meaningless_phrase_words(),
                mnemonic_phrase_language_opt: Some("English".to_string()),
                mnemonic_passphrase_opt: None,
            }),
            consuming_derivation_path_opt: None,
            consuming_private_key_opt: None,
            earning_derivation_path_opt: None,
            earning_address_opt: Some(earning_address),
        };
        let mut persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(configure_default_persistent_config(ZERO).check_password_result(Ok(true)));

        let result =
            Configurator::unfriendly_handle_recover_wallets(msg, 1234, &mut persistent_config);

        assert_eq! (result, Err((MISSING_DATA, "If you supply seed information, you must supply either the consuming wallet derivation path or the consuming wallet private key".to_string())));
    }

    #[test]
    fn unfriendly_handle_recover_wallets_handles_seed_but_nothing_about_earning_wallet() {
        let db_password = "password".to_string();
        let consuming_private_key =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string();
        let msg = UiRecoverWalletsRequest {
            db_password,
            seed_spec_opt: Some(UiRecoverSeedSpec {
                mnemonic_phrase: make_meaningless_phrase_words(),
                mnemonic_phrase_language_opt: Some("English".to_string()),
                mnemonic_passphrase_opt: None,
            }),
            consuming_derivation_path_opt: None,
            consuming_private_key_opt: Some(consuming_private_key),
            earning_derivation_path_opt: None,
            earning_address_opt: None,
        };
        let mut persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(configure_default_persistent_config(ZERO).check_password_result(Ok(true)));

        let result =
            Configurator::unfriendly_handle_recover_wallets(msg, 1234, &mut persistent_config);

        assert_eq! (result, Err((MISSING_DATA, "If you supply seed information, you must supply either the earning wallet derivation path or the earning wallet address".to_string())));
    }

    #[test]
    fn unfriendly_handle_recover_wallets_defaults_language_to_english() {
        let db_password = "password".to_string();
        let msg = UiRecoverWalletsRequest {
            db_password,
            seed_spec_opt: Some(UiRecoverSeedSpec {
                mnemonic_phrase: make_meaningless_phrase_words(),
                mnemonic_phrase_language_opt: None,
                mnemonic_passphrase_opt: None,
            }),
            consuming_derivation_path_opt: Some(derivation_path(10, 20)),
            consuming_private_key_opt: None,
            earning_derivation_path_opt: None,
            earning_address_opt: Some("0x0123456789012345678901234567890123456789".to_string()),
        };
        let mut persistent_config: Box<dyn PersistentConfiguration> = Box::new(
            configure_default_persistent_config(ZERO)
                .check_password_result(Ok(true))
                .set_wallet_info_result(Ok(())),
        );

        let result =
            Configurator::unfriendly_handle_recover_wallets(msg, 1234, &mut persistent_config);

        assert_eq!(result.is_ok(), true); // phrase is in English; if language didn't default there, test would blow up
    }

    #[test]
    fn handle_set_configuration_works() {
        init_test_logging();
        let test_name = "handle_set_configuration_works";
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let persistent_config = PersistentConfigurationMock::new()
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Ok(()));
        let mut subject = make_subject(Some(persistent_config));
        subject.logger = Logger::new(test_name);
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let msg = UiSetConfigurationRequest {
            name: "start-block".to_string(),
            value: "166666".to_string(),
        };
        let context_id = 4444;

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: msg.clone().tmb(context_id),
            })
            .unwrap();

        let system = System::new("test");
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        let (_, context_id) = UiSetConfigurationResponse::fmb(response.body.clone()).unwrap();
        assert_eq!(context_id, 4444);
        let check_start_block_params = set_start_block_params_arc.lock().unwrap();
        assert_eq!(*check_start_block_params, vec![Some(166666)]);
    }

    #[test]
    fn handle_none_cases() {
        vec!["none", "None", "nOnE", "NoNe", "NONE"]
            .iter()
            .for_each(|value| handle_set_configuration_accepts_none_to_unset_start_block(value));
    }

    fn handle_set_configuration_accepts_none_to_unset_start_block(cfg_value: &str) {
        init_test_logging();
        let test_name = format!(
            "handle_set_configuration_accepts_{}_to_unset_start_block",
            &cfg_value
        );
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let persistent_config = PersistentConfigurationMock::new()
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Ok(()));
        let mut subject = make_subject(Some(persistent_config));
        subject.logger = Logger::new(test_name.as_str());
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let msg = UiSetConfigurationRequest {
            name: "start-block".to_string(),
            value: cfg_value.to_string(),
        };
        let context_id = 4444;

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: msg.clone().tmb(context_id),
            })
            .unwrap();

        let system = System::new("test");
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        let (_, context_id) = UiSetConfigurationResponse::fmb(response.body.clone()).unwrap();
        assert_eq!(context_id, 4444);
        let check_start_block_params = set_start_block_params_arc.lock().unwrap();
        assert_eq!(*check_start_block_params, vec![None]);
    }

    #[test]
    fn handle_set_configuration_works_for_gas_price() {
        let set_gas_price_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_gas_price_params(&set_gas_price_params_arc)
            .set_gas_price_result(Ok(()));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "gas-price".to_string(),
                value: "68".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Ok(r#"{}"#.to_string())
            }
        );
        let set_gas_price_params = set_gas_price_params_arc.lock().unwrap();
        assert_eq!(*set_gas_price_params, vec![68])
    }

    #[test]
    fn handle_set_configuration_handles_failure_on_gas_price_database_issue() {
        let persistent_config = PersistentConfigurationMock::new()
            .set_gas_price_result(Err(PersistentConfigError::TransactionError));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "gas-price".to_string(),
                value: "55".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "gas price: TransactionError".to_string()
                ))
            }
        );
    }

    #[test]
    fn handle_set_configuration_handle_gas_price_non_parsable_value_issue() {
        let persistent_config = PersistentConfigurationMock::new();
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "gas-price".to_string(),
                value: "fiftyfive".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    NON_PARSABLE_VALUE,
                    "gas price: ParseIntError { kind: InvalidDigit }".to_string()
                ))
            }
        );
    }

    #[test]
    fn handle_set_configuration_terminates_after_failure_on_start_block() {
        let persistent_config = PersistentConfigurationMock::new().set_start_block_result(Err(
            PersistentConfigError::DatabaseError("dunno".to_string()),
        ));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "start-block".to_string(),
                value: "166666".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    r#"start block: DatabaseError("dunno")"#.to_string()
                ))
            }
        );
    }

    #[test]
    fn handle_set_configuration_argue_decently_about_non_parsable_value_at_start_block() {
        let persistent_config = PersistentConfigurationMock::new();
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "start-block".to_string(),
                value: "hundred_and_half".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    NON_PARSABLE_VALUE,
                    r#"start block: ParseIntError { kind: InvalidDigit }"#.to_string()
                ))
            }
        );
    }

    #[test]
    fn handle_set_configuration_works_for_min_hops() {
        init_test_logging();
        let test_name = "handle_set_configuration_works_for_min_hops";
        let new_min_hops = Hops::SixHops;
        let set_min_hops_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_min_hops_params(&set_min_hops_params_arc)
            .set_min_hops_result(Ok(()));
        let system = System::new("handle_set_configuration_works_for_min_hops");
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
        let mut subject = make_subject(Some(persistent_config));
        subject.logger = Logger::new(test_name);
        subject.config_change_subs_opt = Some(peer_actors.config_change_subs());

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "min-hops".to_string(),
                value: new_min_hops.to_string(),
            },
            4000,
        );

        System::current().stop();
        system.run();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let message_to_neighborhood = neighborhood_recording.get_record::<ConfigChangeMsg>(0);
        let set_min_hops_params = set_min_hops_params_arc.lock().unwrap();
        let min_hops_in_db = set_min_hops_params.get(0).unwrap();
        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Ok(r#"{}"#.to_string())
            }
        );
        assert_eq!(
            message_to_neighborhood,
            &ConfigChangeMsg {
                change: ConfigChange::UpdateMinHops(new_min_hops)
            }
        );
        assert_eq!(*min_hops_in_db, new_min_hops);
        TestLogHandler::new().exists_log_containing(&format!(
           "DEBUG: {test_name}: The value of min-hops has been changed to {new_min_hops}-hop inside the database"
        ));
    }

    #[test]
    fn handle_set_configuration_throws_err_for_invalid_min_hops() {
        init_test_logging();
        let test_name = "handle_set_configuration_throws_err_for_invalid_min_hops";
        let mut subject = make_subject(None);
        subject.logger = Logger::new(test_name);

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "min-hops".to_string(),
                value: "600".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    NON_PARSABLE_VALUE,
                    "min hops: \"Invalid value for min hops provided\"".to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: The UiSetConfigurationRequest failed with an error \
             281474976710668: min hops: \"Invalid value for min hops provided\""
        ));
    }

    #[test]
    fn handle_set_configuration_handles_failure_on_min_hops_database_issue() {
        init_test_logging();
        let test_name = "handle_set_configuration_handles_failure_on_min_hops_database_issue";
        let persistent_config = PersistentConfigurationMock::new()
            .set_min_hops_result(Err(PersistentConfigError::TransactionError));
        let system = System::new(test_name);
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
        let mut subject = make_subject(Some(persistent_config));
        subject.logger = Logger::new(test_name);
        subject.config_change_subs_opt = Some(peer_actors.config_change_subs());

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "min-hops".to_string(),
                value: "4".to_string(),
            },
            4000,
        );

        System::current().stop();
        system.run();
        let recording = neighborhood_recording_arc.lock().unwrap();
        assert!(recording.is_empty());
        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "min hops: TransactionError".to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: The UiSetConfigurationRequest failed with an error \
                281474976710658: min hops: TransactionError"
        ));
    }

    #[test]
    fn handle_set_configuration_complains_about_unexpected_parameter() {
        let persistent_config = PersistentConfigurationMock::new();
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "blabla".to_string(),
                value: "166666".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    UNRECOGNIZED_PARAMETER,
                    "This parameter name is not known: blabla".to_string()
                ))
            }
        );
    }

    #[test]
    fn parse_language_handles_expected_languages() {
        vec![
            "English",
            "Chinese",
            "Traditional Chinese",
            "French",
            "Italian",
            "Japanese",
            "Korean",
            "Spanish",
        ]
        .into_iter()
        .for_each(|input| {
            let result = Configurator::parse_language(input)
                .expect(format!("{} didn't parse", input).as_str());

            // I can't believe that PartialEq is not implemented for Language. Sheesh!
            match result {
                Language::English => assert_eq!(input, "English"),
                Language::ChineseSimplified => assert_eq!(input, "Chinese"),
                Language::ChineseTraditional => assert_eq!(input, "Traditional Chinese"),
                Language::French => assert_eq!(input, "French"),
                Language::Italian => assert_eq!(input, "Italian"),
                Language::Japanese => assert_eq!(input, "Japanese"),
                Language::Korean => assert_eq!(input, "Korean"),
                Language::Spanish => assert_eq!(input, "Spanish"),
            }
        })
    }

    #[test]
    fn parse_word_count_handles_expected_counts() {
        vec![12, 15, 18, 21, 24].into_iter().for_each(|input| {
            let result = Configurator::parse_word_count(input)
                .expect(format!("{} didn't parse", input).as_str());

            assert_eq!(result.word_count(), input);
        })
    }

    #[test]
    fn parse_word_count_handles_unexpected_count() {
        let result = Configurator::parse_word_count(13).err().unwrap();

        assert_eq!(
            result,
            (ILLEGAL_MNEMONIC_WORD_COUNT_ERROR, "13".to_string())
        );
    }

    #[test]
    fn generate_seed_and_mnemonic_phrase_works_without_passphrase() {
        let (actual_seed, phrase_words) =
            Configurator::generate_seed_and_mnemonic_phrase(&None, "English", 12).unwrap();

        let mnemonic_phrase = phrase_words.join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let expected_seed = Bip39::seed(&mnemonic, "");
        assert_eq!(actual_seed.as_ref(), expected_seed.as_ref());
    }

    #[test]
    fn configuration_works_with_no_password() {
        let consuming_wallet_private_key =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string();
        let earning_wallet_address = "4a5e43b54c6C56Ebf7".to_string();
        let public_key = PK::from(&b"xaca4sf4a56"[..]);
        let node_addr = NodeAddr::from_str("1.2.1.3:4545").unwrap();
        let node_descriptor = NodeDescriptor::from((
            &public_key,
            &node_addr,
            Chain::EthRopsten,
            main_cryptde() as &dyn CryptDE,
        ));
        let persistent_config = PersistentConfigurationMock::new()
            .blockchain_service_url_result(Ok(None))
            .check_password_result(Ok(true))
            .chain_name_result("ropsten".to_string())
            .current_schema_version_result("3")
            .clandestine_port_result(Ok(1234))
            .gas_price_result(Ok(2345))
            .consuming_wallet_private_key_result(Ok(Some(consuming_wallet_private_key)))
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Igdp)))
            .max_block_count_result(Ok(Some(100000)))
            .neighborhood_mode_result(Ok(NeighborhoodModeLight::Standard))
            .past_neighbors_result(Ok(Some(vec![node_descriptor.clone()])))
            .earning_wallet_address_result(Ok(Some(earning_wallet_address.clone())))
            .start_block_result(Ok(Some(3456)));
        let persistent_config = payment_thresholds_scan_intervals_rate_pack(persistent_config);
        let mut subject = make_subject(Some(persistent_config));

        let (configuration, context_id) =
            UiConfigurationResponse::fmb(subject.handle_configuration(
                UiConfigurationRequest {
                    db_password_opt: None,
                },
                4321,
            ))
            .unwrap();

        assert_eq!(context_id, 4321);
        assert_eq!(
            configuration,
            UiConfigurationResponse {
                blockchain_service_url_opt: None,
                current_schema_version: "3".to_string(),
                clandestine_port: 1234,
                chain_name: "ropsten".to_string(),
                gas_price: 2345,
                max_block_count_opt: Some(100000),
                neighborhood_mode: String::from("standard"),
                consuming_wallet_private_key_opt: None,
                consuming_wallet_address_opt: None,
                earning_wallet_address_opt: Some(earning_wallet_address),
                port_mapping_protocol_opt: Some("IGDP".to_string()),
                past_neighbors: vec![],
                payment_thresholds: UiPaymentThresholds {
                    threshold_interval_sec: 10_000,
                    debt_threshold_gwei: 5_000_000,
                    maturity_threshold_sec: 1200,
                    payment_grace_period_sec: 1000,
                    permanent_debt_allowed_gwei: 20_000,
                    unban_below_gwei: 20_000
                },
                rate_pack: UiRatePack {
                    routing_byte_rate: 6,
                    routing_service_rate: 8,
                    exit_byte_rate: 10,
                    exit_service_rate: 13
                },
                start_block_opt: Some(3456),
                scan_intervals: UiScanIntervals {
                    pending_payable_sec: 122,
                    payable_sec: 125,
                    receivable_sec: 128
                }
            }
        );
    }

    fn payment_thresholds_scan_intervals_rate_pack(
        persistent_config: PersistentConfigurationMock,
    ) -> PersistentConfigurationMock {
        persistent_config
            .rate_pack_result(Ok(RatePack {
                routing_byte_rate: 6,
                routing_service_rate: 8,
                exit_byte_rate: 10,
                exit_service_rate: 13,
            }))
            .scan_intervals_result(Ok(ScanIntervals {
                pending_payable_scan_interval: Duration::from_secs(122),
                payable_scan_interval: Duration::from_secs(125),
                receivable_scan_interval: Duration::from_secs(128),
            }))
            .payment_thresholds_result(Ok(PaymentThresholds {
                threshold_interval_sec: 10000,
                debt_threshold_gwei: 5000000,
                payment_grace_period_sec: 1000,
                maturity_threshold_sec: 1200,
                permanent_debt_allowed_gwei: 20000,
                unban_below_gwei: 20000,
            }))
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn configurator_can_be_crashed_properly_but_not_improperly() {
        let persistent_config = PersistentConfigurationMock::new();
        let mut configurator = make_subject(Some(persistent_config));
        configurator.crashable = true;

        prove_that_crash_request_handler_is_hooked_up(configurator, CRASH_KEY);
    }

    #[test]
    fn configuration_works_with_secrets() {
        let consuming_wallet_private_key_params_arc = Arc::new(Mutex::new(vec![]));
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let consuming_wallet_private_key =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string();
        let consuming_wallet_address = format!(
            "{:?}",
            Bip32EncryptionKeyProvider::from_raw_secret(
                consuming_wallet_private_key
                    .from_hex::<Vec<u8>>()
                    .unwrap()
                    .as_slice()
            )
            .unwrap()
            .address()
        );
        let earning_wallet_address = "4a5e43b54c6C56Ebf7".to_string();
        let public_key = PK::from(&b"xaca4sf4a56"[..]);
        let node_addr = NodeAddr::from_str("1.2.1.3:4545").unwrap();
        let node_descriptor = NodeDescriptor::from((
            &public_key,
            &node_addr,
            Chain::EthRopsten,
            main_cryptde() as &dyn CryptDE,
        ));
        let persistent_config = PersistentConfigurationMock::new()
            .blockchain_service_url_result(Ok(None))
            .check_password_result(Ok(true))
            .chain_name_result("ropsten".to_string())
            .current_schema_version_result("3")
            .clandestine_port_result(Ok(1234))
            .gas_price_result(Ok(2345))
            .consuming_wallet_private_key_params(&consuming_wallet_private_key_params_arc)
            .consuming_wallet_private_key_result(Ok(Some(consuming_wallet_private_key.clone())))
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Igdp)))
            .max_block_count_result(Ok(None))
            .neighborhood_mode_result(Ok(NeighborhoodModeLight::ConsumeOnly))
            .past_neighbors_params(&past_neighbors_params_arc)
            .past_neighbors_result(Ok(Some(vec![node_descriptor.clone()])))
            .earning_wallet_address_result(Ok(Some(earning_wallet_address.clone())))
            .start_block_result(Ok(Some(3456)));
        let persistent_config = payment_thresholds_scan_intervals_rate_pack(persistent_config);
        let mut subject = make_subject(Some(persistent_config));

        let (configuration, context_id) =
            UiConfigurationResponse::fmb(subject.handle_configuration(
                UiConfigurationRequest {
                    db_password_opt: Some("password".to_string()),
                },
                4321,
            ))
            .unwrap();

        assert_eq!(context_id, 4321);
        assert_eq!(
            configuration,
            UiConfigurationResponse {
                blockchain_service_url_opt: None,
                current_schema_version: "3".to_string(),
                clandestine_port: 1234,
                chain_name: "ropsten".to_string(),
                gas_price: 2345,
                max_block_count_opt: None,
                neighborhood_mode: String::from("consume-only"),
                consuming_wallet_private_key_opt: Some(consuming_wallet_private_key),
                consuming_wallet_address_opt: Some(consuming_wallet_address),
                earning_wallet_address_opt: Some(earning_wallet_address),
                port_mapping_protocol_opt: Some(AutomapProtocol::Igdp.to_string()),
                past_neighbors: vec![node_descriptor.to_string(main_cryptde())],
                payment_thresholds: UiPaymentThresholds {
                    threshold_interval_sec: 10_000,
                    debt_threshold_gwei: 5_000_000,
                    maturity_threshold_sec: 1200,
                    payment_grace_period_sec: 1000,
                    permanent_debt_allowed_gwei: 20_000,
                    unban_below_gwei: 20_000
                },
                rate_pack: UiRatePack {
                    routing_byte_rate: 6,
                    routing_service_rate: 8,
                    exit_byte_rate: 10,
                    exit_service_rate: 13
                },
                start_block_opt: Some(3456),
                scan_intervals: UiScanIntervals {
                    pending_payable_sec: 122,
                    payable_sec: 125,
                    receivable_sec: 128
                }
            }
        );
        let consuming_wallet_private_key_params =
            consuming_wallet_private_key_params_arc.lock().unwrap();
        assert_eq!(
            *consuming_wallet_private_key_params,
            vec!["password".to_string()]
        );
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(*past_neighbors_params, vec!["password".to_string()])
    }

    #[test]
    fn configuration_handles_retrieving_all_possible_none_values() {
        let persistent_config = PersistentConfigurationMock::new()
            .blockchain_service_url_result(Ok(None))
            .current_schema_version_result("3")
            .clandestine_port_result(Ok(1234))
            .chain_name_result("ropsten".to_string())
            .gas_price_result(Ok(2345))
            .earning_wallet_address_result(Ok(None))
            .start_block_result(Ok(Some(3456)))
            .max_block_count_result(Ok(None))
            .neighborhood_mode_result(Ok(NeighborhoodModeLight::ZeroHop))
            .mapping_protocol_result(Ok(None))
            .consuming_wallet_private_key_result(Ok(None))
            .past_neighbors_result(Ok(None))
            .rate_pack_result(Ok(RatePack {
                routing_byte_rate: 0,
                routing_service_rate: 0,
                exit_byte_rate: 0,
                exit_service_rate: 0,
            }))
            .scan_intervals_result(Ok(ScanIntervals {
                pending_payable_scan_interval: Default::default(),
                payable_scan_interval: Default::default(),
                receivable_scan_interval: Default::default(),
            }))
            .payment_thresholds_result(Ok(PaymentThresholds {
                debt_threshold_gwei: 0,
                maturity_threshold_sec: 0,
                payment_grace_period_sec: 0,
                permanent_debt_allowed_gwei: 0,
                threshold_interval_sec: 0,
                unban_below_gwei: 0,
            }));
        let mut subject = make_subject(Some(persistent_config));

        let (configuration, context_id) =
            UiConfigurationResponse::fmb(subject.handle_configuration(
                UiConfigurationRequest {
                    db_password_opt: None,
                },
                4321,
            ))
            .unwrap();

        assert_eq!(context_id, 4321);
        assert_eq!(
            configuration,
            UiConfigurationResponse {
                blockchain_service_url_opt: None,
                current_schema_version: "3".to_string(),
                clandestine_port: 1234,
                chain_name: "ropsten".to_string(),
                gas_price: 2345,
                max_block_count_opt: None,
                neighborhood_mode: String::from("zero-hop"),
                consuming_wallet_private_key_opt: None,
                consuming_wallet_address_opt: None,
                earning_wallet_address_opt: None,
                port_mapping_protocol_opt: None,
                past_neighbors: vec![],
                payment_thresholds: UiPaymentThresholds {
                    threshold_interval_sec: 0,
                    debt_threshold_gwei: 0,
                    maturity_threshold_sec: 0,
                    payment_grace_period_sec: 0,
                    permanent_debt_allowed_gwei: 0,
                    unban_below_gwei: 0
                },
                rate_pack: UiRatePack {
                    routing_byte_rate: 0,
                    routing_service_rate: 0,
                    exit_byte_rate: 0,
                    exit_service_rate: 0
                },
                start_block_opt: Some(3456),
                scan_intervals: UiScanIntervals {
                    pending_payable_sec: 0,
                    payable_sec: 0,
                    receivable_sec: 0
                }
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "Database corruption: Could not read max block count: DatabaseError(\"Corruption\")"
    )]
    fn configuration_panic_on_error_retrieving_max_block_count() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .blockchain_service_url_result(Ok(None))
            .current_schema_version_result("3")
            .clandestine_port_result(Ok(1234))
            .chain_name_result("ropsten".to_string())
            .gas_price_result(Ok(2345))
            .earning_wallet_address_result(Ok(Some("4a5e43b54c6C56Ebf7".to_string())))
            .start_block_result(Ok(Some(3456)))
            .max_block_count_result(Err(PersistentConfigError::DatabaseError(
                "Corruption".to_string(),
            )));
        let mut subject = make_subject(Some(persistent_config));

        let _result = subject.handle_configuration(
            UiConfigurationRequest {
                db_password_opt: Some("password".to_string()),
            },
            4321,
        );
    }

    #[test]
    fn configuration_handles_check_password_error() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_configuration(
            UiConfigurationRequest {
                db_password_opt: Some("password".to_string()),
            },
            4321,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "configuration".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((CONFIGURATOR_READ_ERROR, "dbPassword".to_string()))
            }
        );
    }

    fn check_configuration_handles_unexpected_consuming_wallet_private_key(
        cwpk: Result<Option<String>, PersistentConfigError>,
    ) {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .blockchain_service_url_result(Ok(None))
            .current_schema_version_result("1.2.3")
            .clandestine_port_result(Ok(1234))
            .chain_name_result("ropsten".to_string())
            .gas_price_result(Ok(2345))
            .earning_wallet_address_result(Ok(Some(
                "0x0123456789012345678901234567890123456789".to_string(),
            )))
            .start_block_result(Ok(Some(3456)))
            .max_block_count_result(Ok(Some(100000)))
            .neighborhood_mode_result(Ok(NeighborhoodModeLight::ConsumeOnly))
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Igdp)))
            .consuming_wallet_private_key_result(cwpk);
        let mut subject = make_subject(Some(persistent_config));

        let _ = subject.handle_configuration(
            UiConfigurationRequest {
                db_password_opt: Some("password".to_string()),
            },
            4321,
        );
    }

    #[test]
    #[should_panic(
        expected = "Database corruption: error retrieving consuming wallet private key: NotPresent"
    )]
    fn configuration_handles_error_retrieving_consuming_wallet_private_key() {
        check_configuration_handles_unexpected_consuming_wallet_private_key(Err(
            PersistentConfigError::NotPresent,
        ));
    }

    #[test]
    #[should_panic(
        expected = "Database corruption: consuming wallet private key 'Look, Ma, I'm not hexadecimal!' cannot be converted from hexadecimal: Invalid character 'L' at position 0"
    )]
    fn configuration_handles_consuming_wallet_private_key_that_is_not_hexadecimal() {
        check_configuration_handles_unexpected_consuming_wallet_private_key(Ok(Some(
            "Look, Ma, I'm not hexadecimal!".to_string(),
        )));
    }

    #[test]
    #[should_panic(
        expected = "Database corruption: consuming wallet private key 'CAFEBABE' is invalid: \"Number of bytes of the secret differs from 32: 4\""
    )]
    fn configuration_handles_consuming_wallet_private_key_that_is_an_invalid_private_key() {
        check_configuration_handles_unexpected_consuming_wallet_private_key(Ok(Some(
            "CAFEBABE".to_string(),
        )));
    }

    #[test]
    fn value_required_plain_works() {
        let result: Result<u64, MessageError> = Configurator::value_required(Ok(6), "Field");

        assert_eq!(result, Ok(6))
    }

    #[test]
    fn value_required_plain_handles_error() {
        let result: Result<u64, MessageError> =
            Configurator::value_required(Err(PersistentConfigError::NotPresent), "Field");

        assert_eq!(result, Err((CONFIGURATOR_READ_ERROR, "Field".to_string())))
    }

    #[test]
    fn value_required_handles_read_error() {
        let result: Result<String, MessageError> =
            Configurator::value_required(Err(PersistentConfigError::NotPresent), "Field");

        assert_eq!(result, Err((CONFIGURATOR_READ_ERROR, "Field".to_string())))
    }

    #[test]
    fn value_not_required_handles_read_error() {
        let result: Result<Option<String>, MessageError> =
            Configurator::value_not_required(Err(PersistentConfigError::NotPresent), "Field");

        assert_eq!(result, Err((CONFIGURATOR_READ_ERROR, "Field".to_string())))
    }

    fn make_example_generate_wallets_request() -> UiGenerateWalletsRequest {
        UiGenerateWalletsRequest {
            db_password: "password".to_string(),
            seed_spec_opt: Some(UiGenerateSeedSpec {
                mnemonic_phrase_size_opt: Some(24),
                mnemonic_phrase_language_opt: Some("English".to_string()),
                mnemonic_passphrase_opt: Some("booga".to_string()),
            }),
            consuming_derivation_path_opt: Some(derivation_path(0, 4)),
            earning_derivation_path_opt: Some(derivation_path(0, 5)),
        }
    }

    fn make_example_recover_wallets_request_with_paths() -> UiRecoverWalletsRequest {
        UiRecoverWalletsRequest {
            db_password: "password".to_string(),
            seed_spec_opt: Some(UiRecoverSeedSpec {
                mnemonic_phrase: make_meaningless_phrase_words(),
                mnemonic_passphrase_opt: Some("ebullient".to_string()),
                mnemonic_phrase_language_opt: Some("English".to_string()),
            }),
            consuming_derivation_path_opt: Some(derivation_path(0, 4)),
            consuming_private_key_opt: None,
            earning_derivation_path_opt: Some(derivation_path(0, 5)),
            earning_address_opt: None,
        }
    }

    impl From<Box<dyn PersistentConfiguration>> for Configurator {
        fn from(persistent_config: Box<dyn PersistentConfiguration>) -> Self {
            Configurator {
                persistent_config,
                node_to_ui_sub_opt: None,
                config_change_subs_opt: None,
                crashable: false,
                logger: Logger::new("Configurator"),
            }
        }
    }

    fn make_subject(persistent_config_opt: Option<PersistentConfigurationMock>) -> Configurator {
        let persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(persistent_config_opt.unwrap_or(PersistentConfigurationMock::new()));
        Configurator::from(persistent_config)
    }
}
