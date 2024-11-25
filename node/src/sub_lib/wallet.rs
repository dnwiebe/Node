// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
use crate::blockchain::payer::Payer;
use crate::sub_lib::cryptde;
use crate::sub_lib::cryptde::PublicKey as CryptdePublicKey;
use ethereum_types::H160;
use ethsign::{PublicKey, Signature};
use rusqlite::types::{FromSql, FromSqlError, ToSqlOutput, Value, ValueRef};
use rusqlite::ToSql;
use rustc_hex::ToHex;
use serde::{de, ser::SerializeStruct, Serialize, Serializer};
use serde_json::{self, json};
use std::convert::TryInto;
use std::fmt::{Display, Error, Formatter};
use std::hash::{Hash, Hasher};
use std::result::Result;
use std::str::FromStr;
use std::{fmt, marker};
use web3::types::{Address, H256};

#[derive(Debug, PartialEq, Eq)]
pub enum WalletError {
    InvalidAddress,
    Signature(String),
}

impl std::error::Error for WalletError {}

impl Display for WalletError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::InvalidAddress => write!(f, "Invalid address"),
            WalletError::Signature(msg) => write!(f, "{}", msg),
        }
    }
}

#[derive(Debug)]
pub enum WalletKind {
    Address(Address),
    SecretKey(Bip32EncryptionKeyProvider),
    PublicKey(PublicKey),
    Uninitialized,
}

impl Clone for WalletKind {
    fn clone(&self) -> Self {
        match self {
            WalletKind::Address(address) => WalletKind::Address(H160(address.0)),
            WalletKind::SecretKey(keypair) => WalletKind::SecretKey(
                Bip32EncryptionKeyProvider::from_raw_secret(keypair.clone_secret().as_ref())
                    .expect("failed to clone once checked secret"),
            ),
            WalletKind::PublicKey(public) => WalletKind::PublicKey(
                PublicKey::from_slice(public.bytes()).expect("Failed to clone from PublicKey"),
            ),
            WalletKind::Uninitialized => WalletKind::Uninitialized,
        }
    }
}

impl PartialEq<WalletKind> for WalletKind {
    fn eq(&self, other: &Self) -> bool {
        match other {
            WalletKind::Address(other_address) => match self {
                WalletKind::Address(self_address) => self_address == other_address,
                _ => false,
            },
            WalletKind::SecretKey(other_keypair) => match self {
                WalletKind::SecretKey(self_keypair) => self_keypair == other_keypair,
                _ => false,
            },
            WalletKind::PublicKey(other_public) => match self {
                WalletKind::PublicKey(self_public) => {
                    self_public.bytes().to_hex::<String>()
                        == other_public.bytes().to_hex::<String>()
                }
                _ => false,
            },
            WalletKind::Uninitialized => matches!(self, WalletKind::Uninitialized),
        }
    }
}

impl Eq for WalletKind {}

impl Hash for WalletKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            WalletKind::Address(address) => {
                1.hash(state);
                address.hash(state)
            }
            WalletKind::SecretKey(keypair) => {
                2.hash(state);
                keypair.hash(state)
            }
            WalletKind::PublicKey(public) => {
                3.hash(state);
                public.bytes().hash(state)
            }
            WalletKind::Uninitialized => 4.hash(state),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Wallet {
    kind: WalletKind,
}

impl Wallet {
    pub fn new(address: &str) -> Self {
        match Self::from_str(address) {
            Ok(wallet) => wallet,
            Err(_) => Self {
                kind: WalletKind::Uninitialized,
            },
        }
    }

    pub fn as_address_wallet(&self) -> Wallet {
        Wallet::from(self.address())
    }

    pub fn address(&self) -> Address {
        match &self.kind {
            WalletKind::Address(address) => H160(address.0),
            WalletKind::PublicKey(public) => H160(*public.address()),
            WalletKind::SecretKey(key_provider) => key_provider.address(),
            WalletKind::Uninitialized => panic!("No address for an uninitialized wallet!"), // TODO: If we can get rid of it, it'll be awesome!
        }
    }

    pub fn null() -> Self {
        Wallet {
            kind: WalletKind::Uninitialized,
        }
    }

    pub fn string_address_from_keypair(&self) -> String {
        format!("{:#x}", self.address())
    }

    pub fn sign(&self, msg: &dyn AsRef<[u8]>) -> Result<Signature, WalletError> {
        match self.kind {
            WalletKind::SecretKey(ref key_provider) => key_provider
                .sign(msg.as_ref())
                .map_err(|e| WalletError::Signature(format!("{:?}", e))),
            _ => Err(WalletError::Signature(format!(
                "Cannot sign with non-keypair wallet: {:?}.",
                self.kind
            ))),
        }
    }

    pub fn prepare_secp256k1_secret(
        &self,
    ) -> Result<secp256k1secrets::key::SecretKey, WalletError> {
        match self.kind {
            WalletKind::SecretKey(ref key_provider) => Ok(key_provider.into()),
            _ => Err(WalletError::Signature(format!(
                "Cannot sign with non-keypair wallet: {:?}.",
                self.kind
            ))),
        }
    }

    pub fn verify(&self, signature: &Signature, msg: &dyn AsRef<[u8]>) -> bool {
        match self.kind {
            WalletKind::SecretKey(ref key_provider) => {
                match &key_provider.verify(signature, msg.as_ref()) {
                    Ok(result) => *result,
                    Err(_log_this) => false,
                }
            }
            _ => panic!("Keypair wallet required"),
        }
    }

    pub fn as_payer(
        &self,
        public_key: &dyn AsRef<[u8]>,
        contract_address: &dyn AsRef<[u8]>,
    ) -> Payer {
        match self.sign(&cryptde::create_digest(public_key, contract_address)) {
            Ok(proof) => Payer::new(self, &proof),
            Err(e) => panic!(
                "Trying to sign for {:?} encountered {:?}",
                CryptdePublicKey::from(public_key.as_ref()),
                e
            ),
        }
    }

    pub fn congruent(&self, other: &Wallet) -> bool {
        self.kind == other.kind
            || (self.kind != WalletKind::Uninitialized
                && other.kind != WalletKind::Uninitialized
                && self.address() == other.address())
    }
}

impl FromStr for Wallet {
    type Err = WalletError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match serde_json::from_value::<Address>(json!(s)) {
            Ok(address) => Ok(Self {
                kind: WalletKind::Address(address),
            }),
            Err(_) => Err(WalletError::InvalidAddress),
        }
    }
}

impl From<H256> for Wallet {
    fn from(address: H256) -> Self {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&address.0[12..32]);
        Self {
            kind: WalletKind::Address(H160(addr)),
        }
    }
}

impl From<Address> for Wallet {
    fn from(address: Address) -> Self {
        Self {
            kind: WalletKind::Address(address),
        }
    }
}
impl From<PublicKey> for Wallet {
    fn from(public: PublicKey) -> Self {
        Self {
            kind: WalletKind::PublicKey(public),
        }
    }
}

impl From<Bip32EncryptionKeyProvider> for Wallet {
    fn from(keypair: Bip32EncryptionKeyProvider) -> Self {
        Self {
            kind: WalletKind::SecretKey(keypair),
        }
    }
}

impl Display for Wallet {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:#x}", self.address())
    }
}

impl ToSql for Wallet {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Text(format!(
            "{:#x}",
            self.address()
        ))))
    }
}

impl FromSql for Wallet {
    fn column_result(value: ValueRef) -> Result<Self, FromSqlError> {
        match value.as_str() {
            Ok(address) => Wallet::from_str(address).map_err(|e| FromSqlError::Other(Box::new(e))),
            Err(e) => Err(e),
        }
    }
}

impl TryInto<Bip32EncryptionKeyProvider> for Wallet {
    type Error = String;

    fn try_into(self) -> Result<Bip32EncryptionKeyProvider, Self::Error> {
        match self.kind {
            WalletKind::SecretKey(keypair) => Ok(keypair),
            _ => Err("Wallet contains no secret key: can't convert to Bip32KeyPair".to_string()),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Wallet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        enum WalletField {
            Address,
            __Ignore,
        }
        struct WalletFieldVisitor;
        impl<'de> serde::de::Visitor<'de> for WalletFieldVisitor {
            type Value = WalletField;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                fmt::Formatter::write_str(formatter, "field identifier")
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    0u64 => Ok(WalletField::Address),
                    _ => Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(value),
                        &"field index 0 <= i < 1",
                    )),
                }
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "address" => Ok(WalletField::Address),
                    _ => Ok(WalletField::__Ignore),
                }
            }
            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    b"address" => Ok(WalletField::Address),
                    _ => Ok(WalletField::__Ignore),
                }
            }
        }
        impl<'de> serde::Deserialize<'de> for WalletField {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                serde::Deserializer::deserialize_identifier(deserializer, WalletFieldVisitor)
            }
        }
        struct WalletVisitor<'de> {
            marker: marker::PhantomData<Wallet>,
            lifetime: marker::PhantomData<&'de ()>,
            human_readable: bool,
        }
        impl<'de> serde::de::Visitor<'de> for WalletVisitor<'de> {
            type Value = Wallet;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                fmt::Formatter::write_str(formatter, "struct Wallet")
            }
            #[inline]
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let address = match serde::de::SeqAccess::next_element::<Address>(&mut seq)? {
                    Some(address) => address,
                    None => {
                        return Err(serde::de::Error::invalid_length(
                            0usize,
                            &"struct Wallet with 1 element",
                        ));
                    }
                };
                Ok(Wallet {
                    kind: WalletKind::Address(address),
                })
            }
            #[inline]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut possible_address: Option<Address> = None;
                while let Some(key) = serde::de::MapAccess::next_key::<WalletField>(&mut map)? {
                    match key {
                        WalletField::Address => {
                            if Option::is_some(&possible_address) {
                                return Err(<A::Error as de::Error>::duplicate_field("address"));
                            }
                            possible_address = match &self.human_readable {
                                true => {
                                    Some(serde::de::MapAccess::next_value::<Address>(&mut map)?)
                                }
                                false => {
                                    let bytes =
                                        serde::de::MapAccess::next_value::<Vec<u8>>(&mut map)?;
                                    let mut address = [0u8; 20];
                                    address.copy_from_slice(bytes.as_slice());
                                    Some(Address::from(address))
                                }
                            }
                        }
                        _ => {
                            let _ = serde::de::MapAccess::next_value::<serde::de::IgnoredAny>(
                                &mut map,
                            )?;
                        }
                    }
                }
                let address = match possible_address {
                    Some(address) => address,
                    None => return Err(<A::Error as de::Error>::missing_field("address")),
                };
                Ok(Wallet {
                    kind: WalletKind::Address(address),
                })
            }
        }

        let human_readable = deserializer.is_human_readable();
        serde::Deserializer::deserialize_struct(
            deserializer,
            "Wallet",
            &["address"],
            WalletVisitor {
                marker: marker::PhantomData::<Wallet>,
                lifetime: marker::PhantomData,
                human_readable,
            },
        )
    }
}

impl Serialize for Wallet {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let human_readable = serializer.is_human_readable();
        let mut wallet_serializer: <S as Serializer>::SerializeStruct =
            serializer.serialize_struct("Wallet", 1)?;
        if human_readable {
            wallet_serializer.serialize_field("address", &self.address())?;
        } else {
            wallet_serializer.serialize_field("address", &self.address().0.to_vec())?;
        }
        wallet_serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::test_utils::make_meaningless_seed;
    use crate::masq_lib::utils::DEFAULT_CONSUMING_DERIVATION_PATH;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::make_wallet;
    use bip39::{Language, Mnemonic, Seed};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::derivation_path;
    use rusqlite::Connection;
    use rustc_hex::FromHex;
    use serde_cbor;
    use std::collections::hash_map::DefaultHasher;
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn can_create_with_str_address() {
        let subject =
            Wallet::from_str(format!("0x{}", &b"A valid eth address!".to_hex::<String>()).as_str())
                .unwrap();

        assert_eq!(
            "0x412076616c696420657468206164647265737321".to_string(),
            format!("{:#x}", subject.address())
        );
    }

    #[test]
    fn can_create_from_an_h256() {
        let result = Wallet::from(
            serde_json::from_value::<H256>(json!(
                "0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc"
            ))
            .unwrap(),
        );

        assert_eq!(
            String::from("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc"),
            format!("{:#x}", result.address())
        );
    }

    #[test]
    fn display_works() {
        let subject = Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap();

        let result = format!("|{}|", subject);

        assert_eq!(
            "|0xcafedeadbeefbabefacecafedeadbeefbabeface|".to_string(),
            result
        );
    }

    #[test]
    fn string_address_from_keypair_works() {
        let derivation_path = derivation_path(0, 5);
        let expected_seed = make_meaningless_seed();
        let wallet = Wallet::from(
            Bip32EncryptionKeyProvider::try_from((
                expected_seed.as_bytes(),
                derivation_path.as_str(),
            ))
            .unwrap(),
        );

        let result = wallet.string_address_from_keypair();

        assert_eq!(result, "0x28330c4b886fc83bd6e3409a9eae776c19403c2e")
    }

    #[test]
    fn null_wallet() {
        let result = Wallet::null();

        assert_eq!(
            result,
            Wallet {
                kind: WalletKind::Uninitialized
            }
        )
    }

    #[test]
    fn serialization_roundtrips_wallet_by_address_with_cbor_successfully() {
        let expected_wallet = make_wallet("A valid eth address!");
        let serialized_data = serde_cbor::to_vec(&expected_wallet).unwrap();
        let actual_wallet = serde_cbor::from_slice::<Wallet>(serialized_data.as_slice()).unwrap();

        assert_eq!(actual_wallet, expected_wallet);
    }

    #[test]
    fn serialization_roundtrips_wallet_by_address_with_json_successfully() {
        let expected_wallet = make_wallet("A valid eth address!");
        let serialized_data = serde_json::to_string(&expected_wallet).unwrap();
        let actual_wallet = serde_json::from_str::<Wallet>(&serialized_data).unwrap();

        assert_eq!(actual_wallet, expected_wallet);
    }

    #[test]
    fn serialization_with_cbor_asymmetrically_roundtrips_keypair_to_address_only() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let keypair = Bip32EncryptionKeyProvider::try_from((
            seed.as_ref(),
            DEFAULT_CONSUMING_DERIVATION_PATH.as_str(),
        ))
        .unwrap();

        let expected = Wallet::from(keypair);
        let serialized = serde_cbor::to_vec(&expected).unwrap();
        let actual = serde_cbor::from_slice::<Wallet>(&serialized[..]).unwrap();

        assert_ne!(actual.kind, expected.kind);
        assert!(actual.congruent(&expected));
    }

    #[test]
    fn serialization_with_json_asymmetrically_roundtrips_keypair_to_address_only() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let keypair = Bip32EncryptionKeyProvider::try_from((
            seed.as_ref(),
            DEFAULT_CONSUMING_DERIVATION_PATH.as_str(),
        ))
        .unwrap();

        let expected = Wallet::from(keypair);
        let result = serde_json::to_string(&expected).unwrap();
        let actual = serde_json::from_str::<Wallet>(&result).unwrap();

        assert_ne!(actual.kind, expected.kind);
        assert!(actual.congruent(&expected));
    }

    #[test]
    fn serialization_with_json_asymmetrically_roundtrips_public_key_to_address_only() {
        let slice = [0u8; 64];
        let key = PublicKey::from_slice(&slice[..]).unwrap();
        let expected = Wallet::from(key);

        let result = serde_json::to_string(&expected).unwrap();
        let actual = serde_json::from_str::<Wallet>(&result).unwrap();

        assert_ne!(actual.kind, expected.kind);
        assert!(actual.congruent(&expected));
    }

    #[test]
    fn serialization_with_cbor_asymmetrically_roundtrips_public_key_to_address_only() {
        let slice = [0u8; 64];
        let key = PublicKey::from_slice(&slice[..]).unwrap();
        let expected = Wallet::from(key);

        let result = serde_cbor::to_vec(&expected).unwrap();
        let actual = serde_cbor::from_slice::<Wallet>(&result).unwrap();

        assert_ne!(actual.kind, expected.kind);
        assert!(actual.congruent(&expected));
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn serialization_with_json_to_roundtrip_wallet_uninitialized() {
        let expected_wallet = Wallet::new(&"");
        let result = serde_json::to_string(&expected_wallet).unwrap();

        let actual_wallet = serde_json::from_str(&result).unwrap();

        assert_eq!(expected_wallet, actual_wallet);
        expected_wallet.address();
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn serialization_with_cbor_to_roundtrip_wallet_uninitialized() {
        let expected_wallet = Wallet::new(&"");
        let serialized_data = serde_cbor::to_vec(&expected_wallet).unwrap();

        let actual_wallet = serde_cbor::from_slice(&serialized_data[..]).unwrap();

        assert_eq!(expected_wallet, actual_wallet);
        expected_wallet.address();
    }

    #[test]
    fn roundtrip_rusqlite_works() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE foo(wallet TEXT)").unwrap();
        let wallet = Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap();
        db.execute(
            "
            INSERT INTO foo(wallet) VALUES (?)",
            &[&wallet],
        )
        .unwrap();

        let mut stmt = db
            .prepare("SELECT wallet FROM foo WHERE wallet = ?")
            .unwrap();

        let result = stmt
            .query_map(&[&wallet], |row| match row.get::<usize, Wallet>(0) {
                Ok(wallet) => Ok(wallet),
                Err(e) => Err(e),
            })
            .unwrap()
            .collect::<Result<Vec<Wallet>, _>>()
            .unwrap();

        assert_eq!(result, vec![wallet]);
    }

    #[test]
    fn can_convert_to_keypair_if_came_from_keypair() {
        let secret_key_text = "0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let keypair = Bip32EncryptionKeyProvider::from_raw_secret(
            &secret_key_text.from_hex::<Vec<u8>>().unwrap(),
        )
        .unwrap();
        let expected_keypair = Bip32EncryptionKeyProvider::from_raw_secret(
            &secret_key_text.from_hex::<Vec<u8>>().unwrap(),
        )
        .unwrap();
        let subject = Wallet::from(keypair);

        let result: Bip32EncryptionKeyProvider = subject.try_into().unwrap();

        assert_eq!(result, expected_keypair);
    }

    #[test]
    fn cant_convert_to_keypair_if_didnt_come_from_keypair() {
        let subject = Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();

        let result: Result<Bip32EncryptionKeyProvider, String> = subject.try_into();

        assert_eq!(
            result,
            Err("Wallet contains no secret key: can't convert to Bip32KeyPair".to_string())
        );
    }

    #[test]
    #[should_panic(
        expected = r#"Trying to sign for 0x010203 encountered Signature("Cannot sign with non-keypair wallet: Uninitialized.")"#
    )]
    fn sign_with_uninitialized_wallets_panic() {
        Wallet::new("").as_payer(
            &CryptdePublicKey::new(&[1, 2, 3]),
            &TEST_DEFAULT_CHAIN.rec().contract,
        );
    }

    #[test]
    fn roundtrip_wallets_do_not_leak_secret_key() {
        let expected = make_paying_wallet(b"this is quite some secret");

        let serialized = serde_cbor::to_vec(&expected).unwrap();
        let actual = serde_cbor::from_slice::<Wallet>(&serialized[..]).unwrap();

        assert!(actual.congruent(&expected));
        assert_ne!(actual.kind, expected.kind);
        match actual.kind {
            WalletKind::Address(address) => assert_eq!(address, expected.address()),
            _ => assert!(false, "Failed to match expected WalletKind::Address"),
        }
    }

    fn keypair_a() -> Bip32EncryptionKeyProvider {
        let numbers = (0u8..32u8).collect::<Vec<u8>>();
        Bip32EncryptionKeyProvider::from_raw_secret(&numbers).unwrap()
    }

    fn keypair_b() -> Bip32EncryptionKeyProvider {
        let numbers = (1u8..33u8).collect::<Vec<u8>>();
        Bip32EncryptionKeyProvider::from_raw_secret(&numbers).unwrap()
    }

    fn hash(wallet: &Wallet) -> u64 {
        let mut hasher = DefaultHasher::new();
        wallet.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn wallet_hash() {
        let address_a1 = Wallet {
            kind: WalletKind::Address(keypair_a().address()),
        };
        let address_a2 = Wallet {
            kind: WalletKind::Address(keypair_a().address()),
        };
        let address_b1 = make_wallet("address");
        let keypair_a1 = Wallet {
            kind: WalletKind::SecretKey(keypair_a()),
        };
        let keypair_a2 = Wallet {
            kind: WalletKind::SecretKey(keypair_a()),
        };
        let keypair_b1 = Wallet {
            kind: WalletKind::SecretKey(keypair_b()),
        };
        let public_key_a1 = Wallet {
            kind: WalletKind::PublicKey(keypair_a().public_key()),
        };
        let public_key_a2 = Wallet {
            kind: WalletKind::PublicKey(keypair_a().public_key()),
        };
        let public_key_b1 = Wallet {
            kind: WalletKind::PublicKey(keypair_b().public_key()),
        };
        let uninitialized_a1 = Wallet {
            kind: WalletKind::Uninitialized,
        };
        let uninitialized_a2 = Wallet {
            kind: WalletKind::Uninitialized,
        };

        assert_eq!(hash(&address_a1), hash(&address_a1));
        assert_eq!(hash(&address_a1), hash(&address_a2));
        assert_ne!(hash(&address_a1), hash(&address_b1));
        assert_eq!(hash(&keypair_a1), hash(&keypair_a1));
        assert_eq!(hash(&keypair_a1), hash(&keypair_a2));
        assert_ne!(hash(&keypair_a1), hash(&keypair_b1));
        assert_ne!(hash(&keypair_a1), hash(&address_a1));
        assert_eq!(hash(&public_key_a1), hash(&public_key_a1));
        assert_eq!(hash(&public_key_a1), hash(&public_key_a2));
        assert_ne!(hash(&public_key_a1), hash(&public_key_b1));
        assert_ne!(hash(&public_key_a1), hash(&address_a1));
        assert_ne!(hash(&public_key_a1), hash(&keypair_a1));
        assert_eq!(hash(&uninitialized_a1), hash(&uninitialized_a1));
        assert_eq!(hash(&uninitialized_a1), hash(&uninitialized_a2));
        assert_ne!(hash(&uninitialized_a1), hash(&address_a1));
        assert_ne!(hash(&uninitialized_a1), hash(&keypair_a1));
        assert_ne!(hash(&uninitialized_a1), hash(&public_key_b1));
    }

    #[test]
    fn wallet_eq() {
        let address_a1 = Wallet {
            kind: WalletKind::Address(keypair_a().address()),
        };
        let address_a2 = Wallet {
            kind: WalletKind::Address(keypair_a().address()),
        };
        let address_b1 = make_wallet("address");
        let keypair_a1 = Wallet {
            kind: WalletKind::SecretKey(keypair_a()),
        };
        let keypair_a2 = Wallet {
            kind: WalletKind::SecretKey(keypair_a()),
        };
        let keypair_b1 = Wallet {
            kind: WalletKind::SecretKey(keypair_b()),
        };
        let public_key_a1 = Wallet {
            kind: WalletKind::PublicKey(keypair_a().public_key()),
        };
        let public_key_a2 = Wallet {
            kind: WalletKind::PublicKey(keypair_a().public_key()),
        };
        let public_key_b1 = Wallet {
            kind: WalletKind::PublicKey(keypair_b().public_key()),
        };
        let uninitialized_a1 = Wallet {
            kind: WalletKind::Uninitialized,
        };
        let uninitialized_a2 = Wallet {
            kind: WalletKind::Uninitialized,
        };

        assert_eq!(&address_a1, &address_a1);
        assert_eq!(&address_a1, &address_a2);
        assert_eq!(&address_a2, &address_a1);
        assert_ne!(&address_a1, &address_b1);
        assert_ne!(&address_b1, &address_a1);
        assert_eq!(&keypair_a1, &keypair_a1);
        assert_eq!(&keypair_a1, &keypair_a2);
        assert_eq!(&keypair_a2, &keypair_a1);
        assert_ne!(&keypair_a1, &keypair_b1);
        assert_ne!(&keypair_b1, &keypair_a1);
        assert_ne!(&keypair_a1, &address_a1);
        assert_ne!(&address_a1, &keypair_a1);
        assert_eq!(&public_key_a1, &public_key_a1);
        assert_eq!(&public_key_a1, &public_key_a2);
        assert_eq!(&public_key_a2, &public_key_a1);
        assert_ne!(&public_key_a1, &public_key_b1);
        assert_ne!(&public_key_b1, &public_key_a1);
        assert_ne!(&public_key_a1, &address_a1);
        assert_ne!(&address_a1, &public_key_a1);
        assert_ne!(&public_key_a1, &keypair_a1);
        assert_ne!(&keypair_a1, &public_key_a1);
        assert_eq!(&uninitialized_a1, &uninitialized_a1);
        assert_eq!(&uninitialized_a1, &uninitialized_a2);
        assert_eq!(&uninitialized_a2, &uninitialized_a1);
        assert_ne!(&uninitialized_a1, &address_a1);
        assert_ne!(&address_a1, &uninitialized_a1);
        assert_ne!(&uninitialized_a1, &keypair_a1);
        assert_ne!(&keypair_a1, &uninitialized_a1);
        assert_ne!(&uninitialized_a1, &public_key_a1);
        assert_ne!(&public_key_a1, &uninitialized_a1);
    }

    #[test]
    fn wallet_congruent() {
        let address_a1 = Wallet {
            kind: WalletKind::Address(keypair_a().address()),
        };
        let address_a2 = Wallet {
            kind: WalletKind::Address(keypair_a().address()),
        };
        let address_b1 = make_wallet("address");
        let keypair_a1 = Wallet {
            kind: WalletKind::SecretKey(keypair_a()),
        };
        let keypair_a2 = Wallet {
            kind: WalletKind::SecretKey(keypair_a()),
        };
        let keypair_b1 = Wallet {
            kind: WalletKind::SecretKey(keypair_b()),
        };
        let public_key_a1 = Wallet {
            kind: WalletKind::PublicKey(keypair_a().public_key()),
        };
        let public_key_a2 = Wallet {
            kind: WalletKind::PublicKey(keypair_a().public_key()),
        };
        let public_key_b1 = Wallet {
            kind: WalletKind::PublicKey(keypair_b().public_key()),
        };
        let uninitialized_a1 = Wallet {
            kind: WalletKind::Uninitialized,
        };
        let uninitialized_a2 = Wallet {
            kind: WalletKind::Uninitialized,
        };

        assert!(address_a1.congruent(&address_a1));
        assert!(address_a1.congruent(&address_a2));
        assert!(address_a2.congruent(&address_a1));
        assert!(!address_a1.congruent(&address_b1));
        assert!(!address_b1.congruent(&address_a1));
        assert!(keypair_a1.congruent(&keypair_a1));
        assert!(keypair_a1.congruent(&keypair_a2));
        assert!(keypair_a2.congruent(&keypair_a1));
        assert!(!keypair_a1.congruent(&keypair_b1));
        assert!(!keypair_b1.congruent(&keypair_a1));
        assert!(keypair_a1.congruent(&address_a1));
        assert!(address_a1.congruent(&keypair_a1));
        assert!(public_key_a1.congruent(&public_key_a1));
        assert!(public_key_a1.congruent(&public_key_a2));
        assert!(public_key_a2.congruent(&public_key_a1));
        assert!(!public_key_a1.congruent(&public_key_b1));
        assert!(!public_key_b1.congruent(&public_key_a1));
        assert!(public_key_a1.congruent(&address_a1));
        assert!(address_a1.congruent(&public_key_a1));
        assert!(public_key_a1.congruent(&keypair_a1));
        assert!(keypair_a1.congruent(&public_key_a1));
        assert!(uninitialized_a1.congruent(&uninitialized_a1));
        assert!(uninitialized_a1.congruent(&uninitialized_a2));
        assert!(uninitialized_a2.congruent(&uninitialized_a1));
        assert!(!uninitialized_a1.congruent(&address_a1));
        assert!(!address_a1.congruent(&uninitialized_a1));
        assert!(!uninitialized_a1.congruent(&keypair_a1));
        assert!(!keypair_a1.congruent(&uninitialized_a1));
        assert!(!uninitialized_a1.congruent(&public_key_a1));
        assert!(!public_key_a1.congruent(&uninitialized_a1));
    }

    #[test]
    fn dangerous_characters_cant_create_initialized_wallet() {
        let address_closure =
            |char: char| format!("0xabcdef0123456789a{}cdef0123456789abcdef01", char);
        let proper_input = address_closure('b');

        let initialized_wallet = Wallet::new(&proper_input);

        assert_eq!(
            initialized_wallet.kind,
            WalletKind::Address(H160::from_slice(
                &"abcdef0123456789abcdef0123456789abcdef01"
                    .from_hex::<Vec<u8>>()
                    .unwrap()
            ))
        );

        let potentially_dangerous_characters = [';', '-', '(', ')', '*', '?', '='];
        potentially_dangerous_characters
            .into_iter()
            .for_each(|char| {
                let malformed_address = address_closure(char);
                let wallet = Wallet::new(&malformed_address);
                assert_eq!(wallet.kind, WalletKind::Uninitialized)
            })
    }

    #[test]
    fn wallet_cant_be_used_for_sql_injections_with_debug() {
        let subject = Wallet::new("; EVIL SQL --");

        let debug_rendering = format!("{:?}", subject);

        assert_eq!(debug_rendering, "Wallet { kind: Uninitialized }")
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn wallet_cant_be_used_for_sql_injections_with_display() {
        let subject = Wallet::new("; EVIL SQL --");

        let _ = subject.to_string();
    }
}
