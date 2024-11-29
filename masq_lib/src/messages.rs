// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::UiMessageError::{DeserializationError, PayloadError, UnexpectedMessage};
use crate::shared_schema::ConfiguratorError;
use crate::ui_gateway::MessageBody;
use crate::ui_gateway::MessagePath::{Conversation, FireAndForget};
use crate::utils::to_string;
use itertools::Itertools;
use serde::de::DeserializeOwned;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::str::FromStr;

pub const NODE_UI_PROTOCOL: &str = "MASQNode-UIv2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiMessageError {
    UnexpectedMessage(MessageBody),
    PayloadError(MessageBody),
    DeserializationError(String, MessageBody),
}

impl fmt::Display for UiMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            UnexpectedMessage(message_body) if message_body.path == FireAndForget => {
                write!(f, "Unexpected one-way message with opcode '{}'\n{:?}", message_body.opcode,
                    message_body.payload)
            }
            UnexpectedMessage(message_body) => {
                let context_id = if let Conversation(context_id) = message_body.path {
                    context_id
                }
                else {
                    panic! ("MessageBody::Path suddenly switched from Conversation to FireAndForget")
                };
                write!(
                    f,
                    "Unexpected two-way message from context {} with opcode '{}'\n{:?}",
                    context_id, message_body.opcode, message_body.payload
                )
            },
            PayloadError(message_body) => {
                match &message_body.payload {
                    Ok (json) => write! (
                        f,
                        "Daemon or Node is acting erratically: PayloadError received for '{}' message with path '{:?}', but payload contained no error\n{}",
                        message_body.opcode,
                        message_body.path,
                        json
                    ),
                    Err ((code, message)) => write!(
                        f,
                        "Daemon or Node complained about your command with opcode '{}'. Error code {}: {}",
                        message_body.opcode, code, message
                    ),
                }
            },
            DeserializationError(message, message_body) => write!(
                f,
                "Could not deserialize message from Daemon or Node: {}\n{:?}",
                message, message_body.payload
            ),
        }
    }
}

pub trait ToMessageBody: serde::Serialize {
    fn tmb(self, context_id: u64) -> MessageBody;
    fn opcode(&self) -> &str;
    fn is_conversational(&self) -> bool;
}

pub trait FromMessageBody: DeserializeOwned + Debug {
    fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError>;
}

macro_rules! fire_and_forget_message {
    ($message_type: ty, $opcode: expr) => {
        impl ToMessageBody for $message_type {
            fn tmb(self, _irrelevant: u64) -> MessageBody {
                let json = serde_json::to_string(&self).expect("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: FireAndForget,
                    payload: Ok(json),
                }
            }

            fn opcode(&self) -> &'static str {
                Self::type_opcode()
            }

            fn is_conversational(&self) -> bool {
                Self::type_is_conversational()
            }
        }

        impl FromMessageBody for $message_type {
            fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError> {
                if body.opcode != $opcode {
                    return Err(UiMessageError::UnexpectedMessage(body));
                };
                let payload = match &body.payload {
                    Ok(json) => match serde_json::from_str::<Self>(json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e), body)),
                    },
                    Err(_) => return Err(PayloadError(body)),
                };
                if let Conversation(_) = &body.path {
                    return Err(UiMessageError::UnexpectedMessage(body));
                }
                Ok((payload, 0))
            }
        }

        impl $message_type {
            pub fn type_opcode() -> &'static str {
                $opcode
            }

            pub fn type_is_conversational() -> bool {
                false
            }
        }
    };
}

macro_rules! conversation_message {
    ($message_type: ty, $opcode: expr) => {
        impl ToMessageBody for $message_type {
            fn tmb(self, context_id: u64) -> MessageBody {
                let json = serde_json::to_string(&self).expect("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: Conversation(context_id),
                    payload: Ok(json),
                }
            }

            fn opcode(&self) -> &'static str {
                Self::type_opcode()
            }

            fn is_conversational(&self) -> bool {
                Self::type_is_conversational()
            }
        }

        impl FromMessageBody for $message_type {
            fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError> {
                if body.opcode != $opcode {
                    return Err(UiMessageError::UnexpectedMessage(body));
                };
                let payload = match &body.payload {
                    Ok(json) => match serde_json::from_str::<Self>(json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e), body)),
                    },
                    Err(_) => return Err(PayloadError(body)),
                };
                let context_id = match &body.path {
                    Conversation(context_id) => context_id,
                    FireAndForget => return Err(UiMessageError::UnexpectedMessage(body)),
                };
                Ok((payload, *context_id))
            }
        }

        impl $message_type {
            pub fn type_opcode() -> &'static str {
                $opcode
            }

            pub fn type_is_conversational() -> bool {
                true
            }
        }
    };
}

///////////////////////////////////////////////////////////////////////
// These messages are sent only to and/or by the Daemon, not the Node
///////////////////////////////////////////////////////////////////////
// if a fire-and-forget message for the Node was detected but the Node is down
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiUndeliveredFireAndForget {
    pub opcode: String,
}
fire_and_forget_message!(UiUndeliveredFireAndForget, "undelivered");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiCrashRequest {
    pub actor: String,
    #[serde(rename = "panicMessage")]
    pub panic_message: String,
}
fire_and_forget_message!(UiCrashRequest, "crash");

impl UiCrashRequest {
    pub fn new(actor: &str, panic_message: &str) -> Self {
        Self {
            actor: actor.to_string(),
            panic_message: panic_message.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiSetupRequestValue {
    pub name: String,
    pub value: Option<String>,
}

impl UiSetupRequestValue {
    pub fn new(name: &str, value: &str) -> Self {
        UiSetupRequestValue {
            name: name.to_string(),
            value: Some(value.to_string()),
        }
    }

    pub fn clear(name: &str) -> Self {
        UiSetupRequestValue {
            name: name.to_string(),
            value: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiSetupRequest {
    pub values: Vec<UiSetupRequestValue>,
}
conversation_message!(UiSetupRequest, "setup");

impl UiSetupRequest {
    pub fn new(pairs: Vec<(&str, Option<&str>)>) -> UiSetupRequest {
        UiSetupRequest {
            values: pairs
                .into_iter()
                .map(|(name, value)| UiSetupRequestValue {
                    name: name.to_string(),
                    value: value.map(to_string),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub enum UiSetupResponseValueStatus {
    Default,
    Configured,
    Set,
    Blank,
    Required,
}

impl UiSetupResponseValueStatus {
    pub fn priority(self) -> u8 {
        match self {
            UiSetupResponseValueStatus::Blank => 0,
            UiSetupResponseValueStatus::Required => 0,
            UiSetupResponseValueStatus::Default => 1,
            UiSetupResponseValueStatus::Configured => 2,
            UiSetupResponseValueStatus::Set => 3,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiSetupResponseValue {
    pub name: String,
    pub value: String,
    pub status: UiSetupResponseValueStatus,
}

impl UiSetupResponseValue {
    pub fn new(
        name: &str,
        value: &str,
        status: UiSetupResponseValueStatus,
    ) -> UiSetupResponseValue {
        UiSetupResponseValue {
            name: name.to_string(),
            value: value.to_string(),
            status,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiSetupResponse {
    pub running: bool,
    pub values: Vec<UiSetupResponseValue>,
    pub errors: Vec<(String, String)>,
}
conversation_message!(UiSetupResponse, "setup");
impl UiSetupResponse {
    pub fn new(
        running: bool,
        values: HashMap<String, UiSetupResponseValue>,
        errors: ConfiguratorError,
    ) -> UiSetupResponse {
        UiSetupResponse {
            running,
            values: values
                .into_iter()
                .sorted_by(|a, b| Ord::cmp(&a.0, &b.0))
                .map(|(_, v)| v)
                .collect(),
            errors: errors
                .param_errors
                .into_iter()
                .map(|pe| (pe.parameter, pe.reason))
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiSetupBroadcast {
    pub running: bool,
    pub values: Vec<UiSetupResponseValue>,
    pub errors: Vec<(String, String)>,
}
fire_and_forget_message!(UiSetupBroadcast, "setup");
impl UiSetupBroadcast {
    pub fn new(
        running: bool,
        values: HashMap<String, UiSetupResponseValue>,
        errors: ConfiguratorError,
    ) -> UiSetupBroadcast {
        UiSetupBroadcast {
            running,
            values: values
                .into_iter()
                .sorted_by(|a, b| Ord::cmp(&a.0, &b.0))
                .map(|(_, v)| v)
                .collect(),
            errors: errors
                .param_errors
                .into_iter()
                .map(|pe| (pe.parameter, pe.reason))
                .collect(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UiSetupInner {
    pub running: bool,
    pub values: Vec<UiSetupResponseValue>,
    pub errors: Vec<(String, String)>,
}

impl From<UiSetupResponse> for UiSetupInner {
    fn from(input: UiSetupResponse) -> Self {
        Self {
            running: input.running,
            values: input.values,
            errors: input.errors,
        }
    }
}

impl From<UiSetupBroadcast> for UiSetupInner {
    fn from(input: UiSetupBroadcast) -> Self {
        Self {
            running: input.running,
            values: input.values,
            errors: input.errors,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UiStartOrder {}
conversation_message!(UiStartOrder, "start");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UiStartResponse {
    #[serde(rename = "newProcessId")]
    pub new_process_id: u32,
    #[serde(rename = "redirectUiPort")]
    pub redirect_ui_port: u16,
}
conversation_message!(UiStartResponse, "start");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum CrashReason {
    ChildWaitFailure(String),
    NoInformation,
    Unrecognized(String),
    DaemonCrashed,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiNodeCrashedBroadcast {
    #[serde(rename = "processId")]
    pub process_id: u32,
    #[serde(rename = "crashReason")]
    pub crash_reason: CrashReason,
}
fire_and_forget_message!(UiNodeCrashedBroadcast, "crashed");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UiRedirect {
    pub port: u16,
    pub opcode: String,
    #[serde(rename = "contextId")]
    pub context_id: Option<u64>,
    pub payload: String,
}
fire_and_forget_message!(UiRedirect, "redirect");

///////////////////////////////////////////////////////////////////
// These messages are sent to or by both the Daemon and the Node
///////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiUnmarshalError {
    pub message: String,
    #[serde(rename = "badData")]
    pub bad_data: String,
}
fire_and_forget_message!(UiUnmarshalError, "unmarshalError");

///////////////////////////////////////////////////////////////////
// These messages are sent to or by the Node only
///////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiChangePasswordRequest {
    #[serde(rename = "oldPasswordOpt")]
    pub old_password_opt: Option<String>,
    #[serde(rename = "newPassword")]
    pub new_password: String,
}
conversation_message!(UiChangePasswordRequest, "changePassword");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiChangePasswordResponse {}
conversation_message!(UiChangePasswordResponse, "changePassword");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiCheckPasswordRequest {
    #[serde(rename = "dbPasswordOpt")]
    pub db_password_opt: Option<String>,
}
conversation_message!(UiCheckPasswordRequest, "checkPassword");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiCheckPasswordResponse {
    pub matches: bool,
}
conversation_message!(UiCheckPasswordResponse, "checkPassword");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiConfigurationChangedBroadcast {}
fire_and_forget_message!(UiConfigurationChangedBroadcast, "configurationChanged");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiConfigurationRequest {
    #[serde(rename = "dbPasswordOpt")]
    pub db_password_opt: Option<String>,
}
conversation_message!(UiConfigurationRequest, "configuration");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiConfigurationResponse {
    #[serde(rename = "blockchainServiceUrlOpt")]
    pub blockchain_service_url_opt: Option<String>,
    #[serde(rename = "chainName")]
    pub chain_name: String,
    #[serde(rename = "clandestinePort")]
    pub clandestine_port: u16,
    #[serde(rename = "currentSchemaVersion")]
    pub current_schema_version: String,
    #[serde(rename = "earningWalletAddressOpt")]
    pub earning_wallet_address_opt: Option<String>,
    #[serde(rename = "gasPrice")]
    pub gas_price: u64,
    #[serde(rename = "maxBlockCount")]
    pub max_block_count_opt: Option<u64>,
    #[serde(rename = "neighborhoodMode")]
    pub neighborhood_mode: String,
    #[serde(rename = "portMappingProtocol")]
    pub port_mapping_protocol_opt: Option<String>,
    #[serde(rename = "startBlock")]
    pub start_block_opt: Option<u64>,
    #[serde(rename = "consumingWalletPrivateKeyOpt")]
    pub consuming_wallet_private_key_opt: Option<String>,
    // This item is calculated from the private key, not stored in the database, so that
    // the UI doesn't need the code to derive address from private key.
    #[serde(rename = "consumingWalletAddressOpt")]
    pub consuming_wallet_address_opt: Option<String>,
    #[serde(rename = "pastNeighbors")]
    pub past_neighbors: Vec<String>,
    #[serde(rename = "paymentThresholds")]
    pub payment_thresholds: UiPaymentThresholds,
    #[serde(rename = "ratePack")]
    pub rate_pack: UiRatePack,
    #[serde(rename = "scanIntervals")]
    pub scan_intervals: UiScanIntervals,
}

conversation_message!(UiConfigurationResponse, "configuration");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiRatePack {
    #[serde(rename = "routingByteRate")]
    pub routing_byte_rate: u64,
    #[serde(rename = "routingServiceRate")]
    pub routing_service_rate: u64,
    #[serde(rename = "exitByteRate")]
    pub exit_byte_rate: u64,
    #[serde(rename = "exitServiceRate")]
    pub exit_service_rate: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiScanIntervals {
    #[serde(rename = "pendingPayableSec")]
    pub pending_payable_sec: u64,
    #[serde(rename = "payableSec")]
    pub payable_sec: u64,
    #[serde(rename = "receivableSec")]
    pub receivable_sec: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiPaymentThresholds {
    #[serde(rename = "thresholdIntervalSec")]
    pub threshold_interval_sec: u64,
    #[serde(rename = "debtThresholdGwei")]
    pub debt_threshold_gwei: u64,
    #[serde(rename = "paymentGracePeriodSec")]
    pub payment_grace_period_sec: u64,
    #[serde(rename = "maturityThresholdSec")]
    pub maturity_threshold_sec: u64,
    #[serde(rename = "permanentDebtAllowedGwei")]
    pub permanent_debt_allowed_gwei: u64,
    #[serde(rename = "unbanBelowGwei")]
    pub unban_below_gwei: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum UiConnectionStage {
    NotConnected,
    ConnectedToNeighbor,
    RouteFound,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiConnectionChangeBroadcast {
    pub stage: UiConnectionStage,
}
fire_and_forget_message!(UiConnectionChangeBroadcast, "connectionChange");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiConnectionStatusRequest {}

conversation_message!(UiConnectionStatusRequest, "connectionStatus");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiConnectionStatusResponse {
    pub stage: UiConnectionStage,
}

conversation_message!(UiConnectionStatusResponse, "connectionStatus");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiDescriptorRequest {}
conversation_message!(UiDescriptorRequest, "descriptor");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiDescriptorResponse {
    #[serde(rename = "nodeDescriptorOpt")]
    pub node_descriptor_opt: Option<String>,
}
conversation_message!(UiDescriptorResponse, "descriptor");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiFinancialsRequest {
    #[serde(rename = "statsRequired")]
    pub stats_required: bool,
    #[serde(rename = "topRecordsOpt")]
    pub top_records_opt: Option<TopRecordsConfig>,
    #[serde(rename = "customQueriesOpt")]
    pub custom_queries_opt: Option<CustomQueries>,
}
conversation_message!(UiFinancialsRequest, "financials");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct TopRecordsConfig {
    pub count: u16,
    #[serde(rename = "orderedBy")]
    pub ordered_by: TopRecordsOrdering,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum TopRecordsOrdering {
    Age,
    Balance,
}

impl TryFrom<&str> for TopRecordsOrdering {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "balance" => Self::Balance,
            "age" => Self::Age,
            x => return Err(format!("Unrecognized ordering: '{}'", x)),
        })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CustomQueries {
    #[serde(rename = "payableOpt")]
    pub payable_opt: Option<RangeQuery<u64>>,
    #[serde(rename = "receivableOpt")]
    pub receivable_opt: Option<RangeQuery<i64>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct RangeQuery<T> {
    #[serde(rename = "minAgeS")]
    pub min_age_s: u64,
    #[serde(rename = "maxAgeS")]
    pub max_age_s: u64,
    #[serde(rename = "minAmountGwei")]
    pub min_amount_gwei: T,
    #[serde(rename = "maxAmountGwei")]
    pub max_amount_gwei: T,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UiFinancialsResponse {
    #[serde(rename = "statsOpt")]
    pub stats_opt: Option<UiFinancialStatistics>,
    #[serde(rename = "queryResultsOpt")]
    pub query_results_opt: Option<QueryResults>,
}
conversation_message!(UiFinancialsResponse, "financials");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UiFinancialStatistics {
    #[serde(rename = "totalUnpaidAndPendingPayableGwei")]
    pub total_unpaid_and_pending_payable_gwei: u64,
    #[serde(rename = "totalPaidPayableGwei")]
    pub total_paid_payable_gwei: u64,
    #[serde(rename = "totalUnpaidReceivableGwei")]
    pub total_unpaid_receivable_gwei: i64,
    #[serde(rename = "totalPaidReceivableGwei")]
    pub total_paid_receivable_gwei: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct QueryResults {
    #[serde(rename = "payableOpt")]
    pub payable_opt: Option<Vec<UiPayableAccount>>,
    #[serde(rename = "receivableOpt")]
    pub receivable_opt: Option<Vec<UiReceivableAccount>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UiPayableAccount {
    pub wallet: String,
    #[serde(rename = "ageS")]
    pub age_s: u64,
    #[serde(rename = "balanceGwei")]
    pub balance_gwei: u64,
    #[serde(rename = "pendingPayableHashOpt")]
    pub pending_payable_hash_opt: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UiReceivableAccount {
    pub wallet: String,
    #[serde(rename = "ageS")]
    pub age_s: u64,
    #[serde(rename = "balanceGwei")]
    pub balance_gwei: i64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiGenerateSeedSpec {
    #[serde(rename = "mnemonicPhraseSizeOpt")]
    pub mnemonic_phrase_size_opt: Option<usize>,
    #[serde(rename = "mnemonicPhraseLanguageOpt")]
    pub mnemonic_phrase_language_opt: Option<String>,
    #[serde(rename = "mnemonicPassphraseOpt")]
    pub mnemonic_passphrase_opt: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiGenerateWalletsRequest {
    #[serde(rename = "dbPassword")]
    pub db_password: String,
    #[serde(rename = "seedSpecOpt")]
    pub seed_spec_opt: Option<UiGenerateSeedSpec>,
    #[serde(rename = "consumingDerivationPathOpt")]
    pub consuming_derivation_path_opt: Option<String>,
    #[serde(rename = "earningDerivationPathOpt")]
    pub earning_derivation_path_opt: Option<String>,
}
conversation_message!(UiGenerateWalletsRequest, "generateWallets");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiGenerateWalletsResponse {
    #[serde(rename = "mnemonicPhraseOpt")]
    pub mnemonic_phrase_opt: Option<Vec<String>>,
    #[serde(rename = "consumingWalletAddress")]
    pub consuming_wallet_address: String,
    #[serde(rename = "consumingWalletPrivateKey")]
    pub consuming_wallet_private_key: String,
    #[serde(rename = "earningWalletAddress")]
    pub earning_wallet_address: String,
    #[serde(rename = "earningWalletPrivateKey")]
    pub earning_wallet_private_key: String,
}
conversation_message!(UiGenerateWalletsResponse, "generateWallets");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiLogBroadcast {
    pub msg: String,
    #[serde(rename = "logLevel")]
    pub log_level: SerializableLogLevel,
}
fire_and_forget_message!(UiLogBroadcast, "logBroadcast");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SerializableLogLevel {
    Error,
    Warn,
    Info,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiNewPasswordBroadcast {}
fire_and_forget_message!(UiNewPasswordBroadcast, "newPassword");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiRecoverSeedSpec {
    #[serde(rename = "mnemonicPhrase")]
    pub mnemonic_phrase: Vec<String>,
    #[serde(rename = "mnemonicPhraseLanguageOpt")]
    pub mnemonic_phrase_language_opt: Option<String>,
    #[serde(rename = "mnemonicPassphraseOpt")]
    pub mnemonic_passphrase_opt: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiRecoverWalletsRequest {
    #[serde(rename = "dbPassword")]
    pub db_password: String,
    #[serde(rename = "seedSpecOpt")]
    pub seed_spec_opt: Option<UiRecoverSeedSpec>,
    #[serde(rename = "consumingDerivationPathOpt")]
    pub consuming_derivation_path_opt: Option<String>,
    #[serde(rename = "consumingPrivateKeyOpt")]
    pub consuming_private_key_opt: Option<String>,
    #[serde(rename = "earningDerivationPathOpt")]
    pub earning_derivation_path_opt: Option<String>,
    #[serde(rename = "earningAddressOpt")]
    pub earning_address_opt: Option<String>,
}
conversation_message!(UiRecoverWalletsRequest, "recoverWallets");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiRecoverWalletsResponse {}
conversation_message!(UiRecoverWalletsResponse, "recoverWallets");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ScanType {
    Payables,
    Receivables,
    PendingPayables,
}

impl FromStr for ScanType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            s if &s.to_lowercase() == "payables" => Ok(ScanType::Payables),
            s if &s.to_lowercase() == "receivables" => Ok(ScanType::Receivables),
            s if &s.to_lowercase() == "pendingpayables" => Ok(ScanType::PendingPayables),
            s => Err(format!("Unrecognized ScanType: '{}'", s)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiScanRequest {
    #[serde(rename = "scanType")]
    pub scan_type: ScanType,
}
conversation_message!(UiScanRequest, "scan");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiScanResponse {}
conversation_message!(UiScanResponse, "scan");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiSetConfigurationRequest {
    pub name: String,
    pub value: String,
}
conversation_message!(UiSetConfigurationRequest, "setConfiguration");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiSetConfigurationResponse {}

conversation_message!(UiSetConfigurationResponse, "setConfiguration");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiShutdownRequest {}
conversation_message!(UiShutdownRequest, "shutdown");

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UiShutdownResponse {}
conversation_message!(UiShutdownResponse, "shutdown");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiWalletAddressesRequest {
    #[serde(rename = "dbPassword")]
    pub db_password: String,
}

conversation_message!(UiWalletAddressesRequest, "walletAddresses");

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UiWalletAddressesResponse {
    #[serde(rename = "consumingWalletAddress")]
    pub consuming_wallet_address: String,
    #[serde(rename = "earningWalletAddress")]
    pub earning_wallet_address: String,
}
conversation_message!(UiWalletAddressesResponse, "walletAddresses");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::UiMessageError::{DeserializationError, PayloadError, UnexpectedMessage};
    use crate::ui_gateway::MessagePath::{Conversation, FireAndForget};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(NODE_UI_PROTOCOL, "MASQNode-UIv2");
    }

    #[test]
    fn ui_message_errors_are_displayable() {
        assert_eq!(
            UnexpectedMessage(MessageBody {
                opcode: "opcode".to_string(),
                path: FireAndForget,
                payload: Ok("{\"name\": \"value\"}".to_string()),
            }).to_string(),
            "Unexpected one-way message with opcode 'opcode'\nOk(\"{\\\"name\\\": \\\"value\\\"}\")".to_string()
        );
        assert_eq!(
            UnexpectedMessage(MessageBody {
                opcode: "opcode".to_string(),
                path: Conversation (1234),
                payload: Ok("{\"name\": \"value\"}".to_string()),
            }).to_string(),
            "Unexpected two-way message from context 1234 with opcode 'opcode'\nOk(\"{\\\"name\\\": \\\"value\\\"}\")".to_string()
        );
        assert_eq!(
            PayloadError(MessageBody {
                opcode: "opcode".to_string(),
                path: Conversation (1234),
                payload: Err((1234, "Booga booga".to_string())),
            }).to_string(),
            "Daemon or Node complained about your command with opcode 'opcode'. Error code 1234: Booga booga"
                .to_string()
        );
        assert_eq!(
            PayloadError(MessageBody {
                opcode: "opcode".to_string(),
                path: Conversation (1234),
                payload: Ok("Shouldn't ever be".to_string()),
            }).to_string(),
            "Daemon or Node is acting erratically: PayloadError received for 'opcode' message with path 'Conversation(1234)', but payload contained no error\nShouldn't ever be"
                .to_string()
        );
        assert_eq!(
            DeserializationError("Booga booga".to_string(), MessageBody {
                opcode: "opcode".to_string(),
                path: Conversation (1234),
                payload: Ok("{\"name\": \"value\"}".to_string()),
            }).to_string(),
            "Could not deserialize message from Daemon or Node: Booga booga\nOk(\"{\\\"name\\\": \\\"value\\\"}\")".to_string()
        );
    }

    #[test]
    fn ui_descriptor_methods_were_correctly_generated() {
        let subject = UiDescriptorResponse {
            node_descriptor_opt: Some("descriptor".to_string()),
        };

        assert_eq!(subject.opcode(), "descriptor");
        assert_eq!(subject.is_conversational(), true);
    }

    #[test]
    fn can_serialize_ui_descriptor_response() {
        let subject = UiDescriptorResponse {
            node_descriptor_opt: None,
        };
        let subject_json = serde_json::to_string(&subject).unwrap();

        let result: MessageBody = UiDescriptorResponse::tmb(subject, 1357);

        assert_eq!(
            result,
            MessageBody {
                opcode: "descriptor".to_string(),
                path: Conversation(1357),
                payload: Ok(subject_json)
            }
        );
    }

    #[test]
    fn can_deserialize_ui_descriptor_response_with_bad_opcode() {
        let json = r#"
            {
                "nodeDescriptorOpt": "descriptor"
            }
        "#
        .to_string();
        let message_body = MessageBody {
            opcode: "booga".to_string(),
            path: Conversation(1234),
            payload: Ok(json),
        };

        let result: Result<(UiDescriptorResponse, u64), UiMessageError> =
            UiDescriptorResponse::fmb(message_body.clone());

        assert_eq!(result, Err(UnexpectedMessage(message_body)))
    }

    #[test]
    fn can_deserialize_ui_descriptor_response_with_bad_path() {
        let json = r#"
            {
                "nodeDescriptorOpt": "descriptor"
            }
        "#
        .to_string();
        let message_body = MessageBody {
            opcode: "descriptor".to_string(),
            path: FireAndForget,
            payload: Ok(json),
        };

        let result: Result<(UiDescriptorResponse, u64), UiMessageError> =
            UiDescriptorResponse::fmb(message_body.clone());

        assert_eq!(result, Err(UnexpectedMessage(message_body)))
    }

    #[test]
    fn can_deserialize_ui_descriptor_response_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "descriptor".to_string(),
            path: Conversation(1234),
            payload: Err((100, "error".to_string())),
        };

        let result: Result<(UiDescriptorResponse, u64), UiMessageError> =
            UiDescriptorResponse::fmb(message_body.clone());

        assert_eq!(result, Err(PayloadError(message_body)))
    }

    #[test]
    fn can_deserialize_unparseable_ui_descriptor_response() {
        let json = "} - unparseable - {".to_string();
        let message_body = MessageBody {
            opcode: "descriptor".to_string(),
            path: Conversation(1234),
            payload: Ok(json),
        };

        let result: Result<(UiDescriptorResponse, u64), UiMessageError> =
            UiDescriptorResponse::fmb(message_body.clone());

        assert_eq!(
            result,
            Err(DeserializationError(
                "Error(\"expected value\", line: 1, column: 1)".to_string(),
                message_body
            ))
        )
    }

    #[test]
    fn can_deserialize_ui_descriptor_response() {
        let json = r#"
            {
                "nodeDescriptorOpt": "descriptor"
            }
        "#
        .to_string();
        let message_body = MessageBody {
            opcode: "descriptor".to_string(),
            path: Conversation(4321),
            payload: Ok(json),
        };

        let result: Result<(UiDescriptorResponse, u64), UiMessageError> =
            UiDescriptorResponse::fmb(message_body);

        assert_eq!(
            result,
            Ok((
                UiDescriptorResponse {
                    node_descriptor_opt: Some("descriptor".to_string())
                },
                4321
            ))
        );
    }

    #[test]
    fn ui_unmarshal_error_methods_were_correctly_generated() {
        let subject = UiUnmarshalError {
            message: "".to_string(),
            bad_data: "".to_string(),
        };

        assert_eq!(subject.opcode(), "unmarshalError");
        assert_eq!(subject.is_conversational(), false);
    }

    #[test]
    fn can_serialize_ui_unmarshal_error() {
        let subject = UiUnmarshalError {
            message: "message".to_string(),
            bad_data: "bad_data".to_string(),
        };
        let subject_json = serde_json::to_string(&subject).unwrap();

        let result: MessageBody = subject.tmb(1357);

        assert_eq!(
            result,
            MessageBody {
                opcode: "unmarshalError".to_string(),
                path: FireAndForget,
                payload: Ok(subject_json)
            }
        );
    }

    #[test]
    fn can_deserialize_ui_unmarshal_error_with_bad_opcode() {
        let json = "{}".to_string();
        let message_body = MessageBody {
            opcode: "booga".to_string(),
            path: FireAndForget,
            payload: Ok(json),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body.clone());

        assert_eq!(result, Err(UnexpectedMessage(message_body)))
    }

    #[test]
    fn can_deserialize_ui_unmarshal_error_with_bad_path() {
        let json = r#"{"message": "message", "badData": "{\"name\": 4}"}"#.to_string();
        let message_body = MessageBody {
            opcode: "unmarshalError".to_string(),
            path: Conversation(0),
            payload: Ok(json),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body.clone());

        assert_eq!(result, Err(UnexpectedMessage(message_body)))
    }

    #[test]
    fn can_deserialize_ui_unmarshal_error_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "unmarshalError".to_string(),
            path: FireAndForget,
            payload: Err((100, "error".to_string())),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body.clone());

        assert_eq!(result, Err(PayloadError(message_body)))
    }

    #[test]
    fn can_deserialize_unparseable_ui_unmarshal_error() {
        let json = "} - unparseable - {".to_string();
        let message_body = MessageBody {
            opcode: "unmarshalError".to_string(),
            path: FireAndForget,
            payload: Ok(json),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body.clone());

        assert_eq!(
            result,
            Err(DeserializationError(
                "Error(\"expected value\", line: 1, column: 1)".to_string(),
                message_body
            ))
        )
    }

    #[test]
    fn can_deserialize_ui_unmarshal_error() {
        let json = r#"{"message": "message", "badData": "{}"}"#.to_string();
        let message_body = MessageBody {
            opcode: "unmarshalError".to_string(),
            path: FireAndForget,
            payload: Ok(json),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body);

        assert_eq!(
            result,
            Ok((
                UiUnmarshalError {
                    message: "message".to_string(),
                    bad_data: "{}".to_string()
                },
                0
            ))
        );
    }

    #[test]
    fn scan_type_from_string_happy_path() {
        let result: Vec<ScanType> = vec![
            "Payables",
            "pAYABLES",
            "Receivables",
            "rECEIVABLES",
            "PendingPayables",
            "pENDINGpAYABLES",
        ]
        .into_iter()
        .map(|s| ScanType::from_str(s).unwrap())
        .collect();

        assert_eq!(
            result,
            vec![
                ScanType::Payables,
                ScanType::Payables,
                ScanType::Receivables,
                ScanType::Receivables,
                ScanType::PendingPayables,
                ScanType::PendingPayables,
            ]
        )
    }

    #[test]
    fn scan_type_from_string_error() {
        let result = ScanType::from_str("unrecognized");

        assert_eq!(
            result,
            Err("Unrecognized ScanType: 'unrecognized'".to_string())
        );
    }

    #[test]
    fn top_records_ordering_from_str() {
        assert_eq!(
            TopRecordsOrdering::try_from("balance").unwrap(),
            TopRecordsOrdering::Balance
        );
        assert_eq!(
            TopRecordsOrdering::try_from("age").unwrap(),
            TopRecordsOrdering::Age
        )
    }

    #[test]
    fn top_records_ordering_from_str_error() {
        assert_eq!(
            TopRecordsOrdering::try_from("upside-down"),
            Err("Unrecognized ordering: 'upside-down'".to_string())
        );
    }
}
