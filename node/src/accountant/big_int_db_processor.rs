// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::big_int_db_processor::ByteMagnitude::{High, Low};
use crate::accountant::big_int_db_processor::UserDefinedFunctionError::InvalidInputValue;
use crate::accountant::big_int_db_processor::WeiChange::{Addition, Subtraction};
use crate::accountant::payable_dao::PayableDaoError;
use crate::accountant::receivable_dao::ReceivableDaoError;
use crate::accountant::{checked_conversion, gwei_to_wei};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use rusqlite::functions::{Context, FunctionFlags};
use rusqlite::Error::UserFunctionError;
use rusqlite::{Connection, Error, Row, Statement, ToSql, Transaction};
use std::fmt::{Debug, Display, Formatter};
use std::iter::once;
use std::marker::PhantomData;
use std::ops::Neg;

#[derive(Debug)]
pub struct BigIntDbProcessor<T: TableNameDAO> {
    overflow_handler: Box<dyn UpdateOverflowHandler<T>>,
}

impl<'a, T: TableNameDAO> BigIntDbProcessor<T> {
    pub fn execute(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError> {
        let main_sql = config.main_sql;
        let mut stm = Self::prepare_statement(conn, main_sql);
        let params = config
            .params
            .merge_pure_rusqlite_and_wei_params((&config.params.wei_change_params).into());
        match stm.execute(params.as_slice()) {
            Ok(_) => Ok(()),
            //SQLITE_CONSTRAINT_DATATYPE (3091),
            //the moment of Sqlite trying to store the number as REAL in a strict INT column
            Err(Error::SqliteFailure(e, _)) if e.extended_code == 3091 => {
                self.overflow_handler.update_with_overflow(conn, config)
            }
            Err(e) => Err(BigIntDbError(format!(
                "Error from invalid {} command for {} table and change of {} wei to '{} = {}' with error '{}'",
                config.determine_command(),
                T::table_name(),
                config.balance_change(),
                config.params.table_unique_key_name,
                config.key_param_value(),
                e
            ))),
        }
    }
}

impl<T: TableNameDAO + 'static> Default for BigIntDbProcessor<T> {
    fn default() -> BigIntDbProcessor<T> {
        Self {
            overflow_handler: Box::new(UpdateOverflowHandlerReal::default()),
        }
    }
}

impl<T: TableNameDAO> BigIntDbProcessor<T> {
    fn prepare_statement<'a>(
        form_of_conn: Either<&'a dyn ConnectionWrapper, &'a Transaction>,
        sql: &'a str,
    ) -> Statement<'a> {
        match form_of_conn {
            Either::Left(conn) => conn.prepare(sql),
            Either::Right(tx) => tx.prepare(sql),
        }
        .expect("internal rusqlite error")
    }
}

pub trait UpdateOverflowHandler<T>: Debug + Send {
    fn update_with_overflow<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError>;
}

#[derive(Debug)]
struct UpdateOverflowHandlerReal<T: TableNameDAO> {
    phantom: PhantomData<T>,
}

impl<T: TableNameDAO> Default for UpdateOverflowHandlerReal<T> {
    fn default() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: TableNameDAO> UpdateOverflowHandler<T> for UpdateOverflowHandlerReal<T> {
    fn update_with_overflow<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError> {
        let update_divided_integer = |row: &Row| -> Result<(), rusqlite::Error> {
            let high_bytes_result = row.get::<usize, i64>(0);
            let low_bytes_result = row.get::<usize, i64>(1);

            match [high_bytes_result, low_bytes_result] {
                [Ok(former_high_bytes), Ok(former_low_bytes)] => {
                    let requested_wei_change = &config.params.wei_change_params;
                    let (high_bytes_corrected, low_bytes_corrected) = Self::correct_bytes(
                        former_high_bytes,
                        former_low_bytes,
                        requested_wei_change,
                    );
                    let wei_update_array: [(&str, &dyn ToSql); 2] = [
                        (
                            requested_wei_change.high.name.as_str(),
                            &high_bytes_corrected,
                        ),
                        (requested_wei_change.low.name.as_str(), &low_bytes_corrected),
                    ];

                    let execute_params = config
                        .params
                        .merge_pure_rusqlite_and_wei_params(wei_update_array);

                    Self::execute_update(conn, &config, &execute_params);
                    Ok(())
                }
                array_of_results => Self::return_first_error(array_of_results),
            }
        };

        let select_sql = config.select_sql();
        let mut select_stm = BigIntDbProcessor::<T>::prepare_statement(conn, &select_sql);
        match select_stm.query_row([], update_divided_integer) {
            Ok(()) => Ok(()),
            Err(e) => Err(BigIntDbError(format!(
                "Updating balance for {} table and change of {} wei to '{} = {}' with error '{}'",
                T::table_name(),
                config.balance_change(),
                config.params.table_unique_key_name,
                config.key_param_value(),
                e
            ))),
        }
    }
}

impl<T: TableNameDAO + Debug> UpdateOverflowHandlerReal<T> {
    fn execute_update<'a>(
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: &BigIntSqlConfig<'a, T>,
        execute_params: &[(&str, &dyn ToSql)],
    ) {
        match BigIntDbProcessor::<T>::prepare_statement(conn, config.overflow_update_clause)
            .execute(execute_params)
            .expect("logic broken given the previous non-overflow call accepted right")
        {
            1 => (),
            x => panic!(
                "Broken code: this code was written to handle one changed row a time, not {}",
                x
            ),
        }
    }

    fn correct_bytes(
        former_high_bytes: i64,
        former_low_bytes: i64,
        requested_wei_change: &WeiChangeAsHighAndLowBytes,
    ) -> (i64, i64) {
        let high_bytes_correction = former_high_bytes + requested_wei_change.high.value + 1;
        let low_bytes_correction = ((former_low_bytes as i128
            + requested_wei_change.low.value as i128)
            & 0x7FFFFFFFFFFFFFFF) as i64;
        (high_bytes_correction, low_bytes_correction)
    }

    fn return_first_error(two_results: [rusqlite::Result<i64>; 2]) -> rusqlite::Result<()> {
        let cached = format!("{:?}", two_results);
        match two_results.into_iter().find(|result| result.is_err()) {
            Some(err) => Err(err.expect_err("we just said it is an error")),
            None => panic!(
                "Broken code: being called to process an error but none was found in {}",
                cached
            ),
        }
    }
}

pub struct BigIntSqlConfig<'a, T> {
    main_sql: &'a str,
    overflow_update_clause: &'a str,
    pub params: SQLParams<'a>,
    phantom: PhantomData<T>,
}

impl<'a, T: TableNameDAO> BigIntSqlConfig<'a, T> {
    pub fn new(
        main_sql: &'a str,
        overflow_update_clause: &'a str,
        params: SQLParams<'a>,
    ) -> BigIntSqlConfig<'a, T> {
        Self {
            main_sql,
            overflow_update_clause,
            params,
            phantom: Default::default(),
        }
    }

    fn select_sql(&self) -> String {
        format!(
            "select {}, {} from {} where {} = '{}'",
            &self.params.wei_change_params.high.name[1..],
            &self.params.wei_change_params.low.name[1..],
            T::table_name(),
            self.params.table_unique_key_name,
            self.key_param_value()
        )
    }

    fn key_param_value(&self) -> &'a dyn ExtendedParamsMarker {
        self.params.params_except_wei_change[0].1
    }

    fn balance_change(&self) -> i128 {
        let wei_params = &self.params.wei_change_params;
        BigIntDivider::reconstitute(wei_params.high.value, wei_params.low.value)
    }

    fn determine_command(&self) -> String {
        let keyword = self
            .main_sql
            .chars()
            .skip_while(|char| char.is_whitespace())
            .take_while(|char| !char.is_whitespace())
            .collect::<String>();
        match keyword.as_str() {
            "insert" => {
                if self.main_sql.contains("update") {
                    "upsert".to_string()
                } else {
                    panic!("Sql with simple insert. The processor of big integers is correctly used only if combined with update")
                }
            }
            "update" => keyword,
            _ => panic!(
                "broken code: unexpected or misplaced command \"{}\" \
                 in upsert or update, respectively",
                keyword
            ),
        }
    }
}

//to be able to display things that implement ToSql
pub trait ExtendedParamsMarker: ToSql + Display {}

macro_rules! impl_of_extended_params_marker{
    ($($implementer: ty),+) => {
        $(impl ExtendedParamsMarker for $implementer {})+
    }
}

impl_of_extended_params_marker!(i64, &str, Wallet);

#[derive(Default)]
pub struct SQLParamsBuilder<'a> {
    key_spec_opt: Option<UniqueKeySpec<'a>>,
    wei_change_spec_opt: Option<WeiChange>,
    other_params: Vec<(&'a str, &'a dyn ExtendedParamsMarker)>,
}

impl<'a> SQLParamsBuilder<'a> {
    pub fn key(mut self, key_variant: KnownKeyVariants<'a>) -> Self {
        let (definition_name, substitution_name_in_sql, value_itself) = key_variant.into();
        self.key_spec_opt = Some(UniqueKeySpec {
            definition_name,
            substitution_name_in_sql,
            value_itself,
        });
        self
    }

    pub fn wei_change(mut self, wei_change: WeiChange) -> Self {
        self.wei_change_spec_opt = Some(wei_change);
        self
    }

    pub fn other(mut self, params: Vec<(&'a str, &'a (dyn ExtendedParamsMarker + 'a))>) -> Self {
        self.other_params = params;
        self
    }

    pub fn build(self) -> SQLParams<'a> {
        let key_spec = self
            .key_spec_opt
            .unwrap_or_else(|| panic!("SQLparams cannot miss the component of a key"));
        let wei_change_spec = self
            .wei_change_spec_opt
            .unwrap_or_else(|| panic!("SQLparams cannot miss the component of wei change"));
        let ((high_bytes_param_name, low_bytes_param_name), (high_bytes_value, low_bytes_value)) =
            Self::expand_wei_params(wei_change_spec);
        let key_as_the_first_param = (key_spec.substitution_name_in_sql, key_spec.value_itself);
        let params = once(key_as_the_first_param)
            .chain(self.other_params.into_iter())
            .collect();
        SQLParams {
            table_unique_key_name: key_spec.definition_name,
            wei_change_params: WeiChangeAsHighAndLowBytes {
                high: StdNumParamFormNamed::new(high_bytes_param_name, high_bytes_value),
                low: StdNumParamFormNamed::new(low_bytes_param_name, low_bytes_value),
            },
            params_except_wei_change: params,
        }
    }

    fn expand_wei_params(wei_change_spec: WeiChange) -> ((String, String), (i64, i64)) {
        let (name, num): (&'static str, i128) = match wei_change_spec {
            Addition(name, num) => (name, checked_conversion::<u128, i128>(num)),
            Subtraction(name, num) => (name, checked_conversion::<u128, i128>(num).neg()),
        };
        let (high_bytes, low_bytes) = BigIntDivider::deconstruct(num);
        let param_sub_name_for_high_bytes = Self::proper_wei_change_param_name(name, High);
        let param_sub_name_for_low_bytes = Self::proper_wei_change_param_name(name, Low);
        (
            (param_sub_name_for_high_bytes, param_sub_name_for_low_bytes),
            (high_bytes, low_bytes),
        )
    }

    fn proper_wei_change_param_name(base_word: &str, byte_magnitude: ByteMagnitude) -> String {
        format!(":{}_{}_b", base_word, byte_magnitude)
    }
}

struct UniqueKeySpec<'a> {
    definition_name: &'a str,
    substitution_name_in_sql: &'a str,
    value_itself: &'a dyn ExtendedParamsMarker,
}

pub enum KnownKeyVariants<'a> {
    WalletAddress(&'a dyn ExtendedParamsMarker),
    PendingPayableRowid(&'a dyn ExtendedParamsMarker),
    #[cfg(test)]
    TestKey {
        var_name: &'static str,
        sub_name: &'static str,
        val: &'a dyn ExtendedParamsMarker,
    },
}

impl<'a> From<KnownKeyVariants<'a>> for (&'static str, &'static str, &'a dyn ExtendedParamsMarker) {
    fn from(variant: KnownKeyVariants<'a>) -> Self {
        match variant {
            KnownKeyVariants::WalletAddress(val) => ("wallet_address", ":wallet", val),
            KnownKeyVariants::PendingPayableRowid(val) => ("pending_payable_rowid", ":rowid", val),
            #[cfg(test)]
            KnownKeyVariants::TestKey {
                var_name,
                sub_name,
                val,
            } => (var_name, sub_name, val),
        }
    }
}

enum ByteMagnitude {
    High,
    Low,
}

impl Display for ByteMagnitude {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            High => write!(f, "high"),
            Low => write!(f, "low"),
        }
    }
}

pub struct SQLParams<'a> {
    table_unique_key_name: &'a str,
    wei_change_params: WeiChangeAsHighAndLowBytes,
    params_except_wei_change: Vec<(&'a str, &'a dyn ExtendedParamsMarker)>,
}

#[derive(Debug, PartialEq)]
struct WeiChangeAsHighAndLowBytes {
    high: StdNumParamFormNamed,
    low: StdNumParamFormNamed,
}

#[derive(Debug, PartialEq)]
struct StdNumParamFormNamed {
    name: String,
    value: i64,
}

impl StdNumParamFormNamed {
    fn new(name: String, value: i64) -> Self {
        Self { name, value }
    }
}

impl<'a> From<&'a WeiChangeAsHighAndLowBytes> for [(&'a str, &'a dyn ToSql); 2] {
    fn from(wei_change: &'a WeiChangeAsHighAndLowBytes) -> Self {
        [
            (wei_change.high.name.as_str(), &wei_change.high.value),
            (wei_change.low.name.as_str(), &wei_change.low.value),
        ]
    }
}

impl<'a> SQLParams<'a> {
    fn merge_pure_rusqlite_and_wei_params(
        &'a self,
        wei_change_params: [(&'a str, &'a dyn ToSql); 2],
    ) -> Vec<(&'a str, &'a dyn ToSql)> {
        self.pure_rusqlite_params(wei_change_params.into_iter())
            .collect()
    }

    fn pure_rusqlite_params(
        &'a self,
        wei_change_params: impl Iterator<Item = (&'a str, &'a dyn ToSql)>,
    ) -> impl Iterator<Item = (&'a str, &'a dyn ToSql)> {
        self.params_except_wei_change
            .iter()
            .map(|(name, value)| (*name, value as &dyn ToSql))
            .chain(wei_change_params)
    }
}

pub trait TableNameDAO: Debug + Send {
    fn table_name() -> String;
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WeiChange {
    Addition(&'static str, u128),
    Subtraction(&'static str, u128),
}

#[derive(Debug, PartialEq, Eq)]
pub struct BigIntDbError(pub String);

macro_rules! insert_update_error_from {
    ($($implementer: ident),+) => {
        $(impl From<BigIntDbError> for $implementer {
            fn from(iu_err: BigIntDbError) -> Self {
                $implementer::RusqliteError(iu_err.0)
            }
        })+
    }
}

insert_update_error_from!(PayableDaoError, ReceivableDaoError);

macro_rules! create_big_int_sqlite_fns {
    ($conn: expr, $($sqlite_fn_name: expr),+; $($intern_fn_name: ident),+) => {
        $(
            $conn.create_scalar_function::<_, i64>($sqlite_fn_name, 3, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
                move |ctx| {
                    Ok(BigIntDivider::$intern_fn_name(common_arg_distillation(
                        ctx,
                        $sqlite_fn_name,
                    )?))
                }
            )?;
        )+
    }
}

pub struct BigIntDivider {}

impl BigIntDivider {
    pub fn deconstruct(num: i128) -> (i64, i64) {
        (
            Self::deconstruct_high_bytes(num),
            Self::deconstruct_low_bytes(num),
        )
    }

    fn deconstruct_high_bytes(num: i128) -> i64 {
        Self::deconstruct_range_check(num);
        (num >> 63) as i64
    }

    fn deconstruct_low_bytes(num: i128) -> i64 {
        (num & 0x7FFFFFFFFFFFFFFFi128) as i64
    }

    fn deconstruct_range_check(num: i128) {
        let top_two_bits = num >> 126 & 0b11;
        if top_two_bits == 0b01 {
            panic!("Dividing big integer for special database storage: {:#X} is too big, maximally 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF allowed",num)
        } else if top_two_bits == 0b10 {
            panic!("Dividing big integer for special database storage: {:#X} is too small, minimally 0xC0000000000000000000000000000000 allowed",num)
        }
    }

    pub fn reconstitute(high_bytes: i64, low_bytes: i64) -> i128 {
        Self::forbidden_low_bytes_negativity_check(low_bytes);
        let low_bytes = low_bytes as i128;
        let high_bytes = high_bytes as i128;
        (high_bytes << 63) | low_bytes
    }

    fn forbidden_low_bytes_negativity_check(low_bytes: i64) {
        if low_bytes < 0 {
            panic!("Reconstituting big integer from special database storage: the second, lower integer {:#X} is signed despite the requirement to be all-time positive",low_bytes)
        }
    }

    pub fn register_big_int_deconstruction_for_sqlite_connection(
        conn: &Connection,
    ) -> rusqlite::Result<()> {
        Self::register_deconstruct_guts(conn, "slope_drop_high_bytes", "slope_drop_low_bytes")
    }

    fn register_deconstruct_guts(
        conn: &Connection,
        fn_name_1: &'static str,
        fn_name_2: &'static str,
    ) -> rusqlite::Result<()> {
        fn common_arg_distillation(
            rusqlite_fn_ctx: &Context,
            fn_name: &str,
        ) -> rusqlite::Result<i128> {
            const ERR_MSG_BEGINNINGS: [&str; 3] = ["First", "Second", "Third"];
            let error_msg = |msg: String| -> rusqlite::Error {
                UserFunctionError(Box::new(InvalidInputValue(fn_name.to_string(), msg)))
            };
            let get_i64_from_args = |arg_idx: usize| -> rusqlite::Result<i64> {
                let raw_value = rusqlite_fn_ctx.get_raw(arg_idx);
                raw_value.as_i64().map_err(|_| {
                    error_msg(format!(
                        "{} argument takes only i64, not: {:?}",
                        ERR_MSG_BEGINNINGS[arg_idx], raw_value
                    ))
                })
            };
            let start_point_to_decrease_from_gwei = get_i64_from_args(0)?;
            let slope = get_i64_from_args(1)?;
            let time_parameter = get_i64_from_args(2)?;
            match (slope.is_negative(), time_parameter.is_positive()) {
                (true, true) => Ok(gwei_to_wei::<i128, _>(start_point_to_decrease_from_gwei) + slope as i128 * time_parameter as i128),
                (false, _) => Err(error_msg(format!(
                    "Nonnegative slope {}; delinquency slope must be negative, since debts must become more delinquent over time.",
                    slope
                ))),
                _ => Err(error_msg(format!(
                    "Negative time parameter {}; debt age cannot go negative.",
                    time_parameter
                ))),
            }
        }

        create_big_int_sqlite_fns!(
            conn, fn_name_1, fn_name_2;
            deconstruct_high_bytes, deconstruct_low_bytes
        );
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum UserDefinedFunctionError {
    InvalidInputValue(String, String),
}

impl std::error::Error for UserDefinedFunctionError {}

impl Display for UserDefinedFunctionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidInputValue(fn_name, err_msg) => {
                write!(f, "Error from {}: {}", fn_name, err_msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::big_int_db_processor::KnownKeyVariants::TestKey;
    use crate::accountant::big_int_db_processor::WeiChange::Addition;
    use crate::accountant::test_utils::test_database_key;
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::test_utils::make_wallet;
    use itertools::Either;
    use itertools::Either::Left;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Error::SqliteFailure;
    use rusqlite::{Connection, ErrorCode, ToSql};
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct DummyDao {}

    impl TableNameDAO for DummyDao {
        fn table_name() -> String {
            String::from("test_table")
        }
    }

    #[test]
    fn conversion_from_local_error_to_particular_payable_dao_error_works() {
        let subject = BigIntDbError(String::from("whatever"));

        let result: PayableDaoError = subject.into();

        assert_eq!(
            result,
            PayableDaoError::RusqliteError("whatever".to_string())
        )
    }

    #[test]
    fn conversion_from_local_error_to_particular_receivable_dao_error_works() {
        let subject = BigIntDbError(String::from("whatever"));

        let result: ReceivableDaoError = subject.into();

        assert_eq!(
            result,
            ReceivableDaoError::RusqliteError("whatever".to_string())
        )
    }

    #[test]
    fn display_for_byte_magnitude_works() {
        assert_eq!(High.to_string(), "high".to_string());
        assert_eq!(Low.to_string(), "low".to_string())
    }

    #[test]
    fn known_key_variants_to_tuple_of_names_and_val_works() {
        let (wallet_name, wallet_sub_name, wallet_val): (&str, &str, &dyn ExtendedParamsMarker) =
            KnownKeyVariants::WalletAddress(&"blah").into();
        let (rowid_name, rowid_sub_name, rowid_val): (&str, &str, &dyn ExtendedParamsMarker) =
            KnownKeyVariants::PendingPayableRowid(&123).into();

        assert_eq!(wallet_name, "wallet_address");
        assert_eq!(wallet_sub_name, ":wallet");
        assert_eq!(wallet_val.to_string(), "blah".to_string());
        assert_eq!(rowid_name, "pending_payable_rowid");
        assert_eq!(rowid_sub_name, ":rowid");
        assert_eq!(rowid_val.to_string(), 123.to_string())
        //cannot be compared by values directly
    }

    #[test]
    fn sql_params_builder_is_nicely_populated_inside_before_calling_build() {
        let subject = SQLParamsBuilder::default();

        let result = subject
            .wei_change(Addition("balance", 4546))
            .key(TestKey {
                var_name: "some_key",
                sub_name: ":some_key",
                val: &"blah",
            })
            .other(vec![("other_thing", &46565)]);

        assert_eq!(result.wei_change_spec_opt, Some(Addition("balance", 4546)));
        let key_spec = result.key_spec_opt.unwrap();
        assert_eq!(key_spec.definition_name, "some_key");
        assert_eq!(key_spec.substitution_name_in_sql, ":some_key");
        assert_eq!(key_spec.value_itself.to_string(), "blah".to_string());
        assert!(matches!(result.other_params[0], ("other_thing", _)));
        assert_eq!(result.other_params.len(), 1)
    }

    #[test]
    fn sql_params_builder_builds_correct_params() {
        let subject = SQLParamsBuilder::default();

        let result = subject
            .wei_change(Addition("balance", 115898))
            .key(TestKey {
                var_name: "some_key",
                sub_name: ":some_key",
                val: &"blah",
            })
            .other(vec![(":other_thing", &11111)])
            .build();

        assert_eq!(result.table_unique_key_name, "some_key");
        assert_eq!(
            result.wei_change_params,
            WeiChangeAsHighAndLowBytes {
                high: StdNumParamFormNamed::new(":balance_high_b".to_string(), 0),
                low: StdNumParamFormNamed::new(":balance_low_b".to_string(), 115898)
            }
        );
        assert_eq!(result.params_except_wei_change[0].0, ":some_key");
        assert_eq!(
            result.params_except_wei_change[0].1.to_string(),
            "blah".to_string()
        );
        assert_eq!(result.params_except_wei_change[1].0, ":other_thing");
        assert_eq!(
            result.params_except_wei_change[1].1.to_string(),
            "11111".to_string()
        );
        assert_eq!(result.params_except_wei_change.len(), 2)
    }

    #[test]
    fn sql_params_builder_builds_correct_params_with_negative_wei_change() {
        let subject = SQLParamsBuilder::default();

        let result = subject
            .wei_change(Subtraction("balance", 454684))
            .key(TestKey {
                var_name: "some_key",
                sub_name: ":some_key",
                val: &"wooow",
            })
            .other(vec![(":other_thing", &46565)])
            .build();

        assert_eq!(result.table_unique_key_name, "some_key");
        assert_eq!(
            result.wei_change_params,
            WeiChangeAsHighAndLowBytes {
                high: StdNumParamFormNamed::new(":balance_high_b".to_string(), -1),
                low: StdNumParamFormNamed::new(":balance_low_b".to_string(), 9223372036854321124)
            }
        );
        assert_eq!(result.params_except_wei_change[0].0, ":some_key");
        assert_eq!(
            result.params_except_wei_change[0].1.to_string(),
            "wooow".to_string()
        );
        assert_eq!(result.params_except_wei_change[1].0, ":other_thing");
        assert_eq!(
            result.params_except_wei_change[1].1.to_string(),
            "46565".to_string()
        );
        assert_eq!(result.params_except_wei_change.len(), 2)
    }

    #[test]
    #[should_panic(expected = "SQLparams cannot miss the component of a key")]
    fn sql_params_builder_cannot_be_built_without_key_spec() {
        let subject = SQLParamsBuilder::default();

        let _ = subject
            .wei_change(Addition("balance", 4546))
            .other(vec![("laughter", &"hahaha")])
            .build();
    }

    #[test]
    #[should_panic(expected = "SQLparams cannot miss the component of wei change")]
    fn sql_params_builder_cannot_be_built_without_wei_change_spec() {
        let subject = SQLParamsBuilder::default();

        let _ = subject
            .key(TestKey {
                var_name: "wallet",
                sub_name: ":wallet",
                val: &make_wallet("wallet"),
            })
            .other(vec![("other_thing", &46565)])
            .build();
    }

    #[test]
    fn sql_params_builder_can_be_built_without_other_params_present() {
        let subject = SQLParamsBuilder::default();

        let _ = subject
            .wei_change(Addition("balance", 4546))
            .key(TestKey {
                var_name: "id",
                sub_name: ":id",
                val: &45,
            })
            .build();
    }

    #[test]
    fn return_first_error_works_for_first_error() {
        let results = [Err(Error::GetAuxWrongType), Ok(45465)];

        let err = UpdateOverflowHandlerReal::<DummyDao>::return_first_error(results);

        assert_eq!(err, Err(Error::GetAuxWrongType))
    }

    #[test]
    fn return_first_error_works_for_second_error() {
        let results = [Ok(45465), Err(Error::QueryReturnedNoRows)];

        let err = UpdateOverflowHandlerReal::<DummyDao>::return_first_error(results);

        assert_eq!(err, Err(Error::QueryReturnedNoRows))
    }

    #[test]
    #[should_panic(
        expected = "Broken code: being called to process an error but none was found in [Ok(-45465), Ok(898)]"
    )]
    fn return_first_error_needs_some_error() {
        let results = [Ok(-45465), Ok(898)];

        let err = UpdateOverflowHandlerReal::<DummyDao>::return_first_error(results);

        assert_eq!(err, Err(Error::QueryReturnedNoRows))
    }

    fn make_empty_sql_params<'a>() -> SQLParams<'a> {
        SQLParams {
            table_unique_key_name: "",
            wei_change_params: WeiChangeAsHighAndLowBytes {
                high: StdNumParamFormNamed::new("".to_string(), 0),
                low: StdNumParamFormNamed::new("".to_string(), 0),
            },
            params_except_wei_change: vec![],
        }
    }

    #[test]
    fn determine_command_works_for_upsert() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql:
                "insert into table (a,b) values ('a','b') on conflict (rowid) do update set etc.",
            overflow_update_clause: "side clause",
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "upsert".to_string())
    }

    #[test]
    fn determine_command_works_for_update() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "update table set a='a',b='b' where a = 'e'",
            overflow_update_clause: "update with overflow sql",
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "update".to_string())
    }

    #[test]
    #[should_panic(
        expected = "Sql with simple insert. The processor of big integers is correctly used only if combined with update"
    )]
    fn determine_command_does_not_now_simple_insert() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "insert into table (blah) values ('double blah')",
            overflow_update_clause: "update with overflow sql",
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let _ = subject.determine_command();
    }

    #[test]
    #[should_panic(
        expected = "broken code: unexpected or misplaced command \"some\" in upsert or update, respectively"
    )]
    fn determine_command_panics_if_unknown_command() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "some other sql command",
            overflow_update_clause: "",
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let _ = subject.determine_command();
    }

    #[test]
    fn determine_command_allows_preceding_spaces() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "  update into table (a,b) values ('a','b')",
            overflow_update_clause: "",
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "update".to_string())
    }

    fn insert_single_record(conn: &dyn ConnectionWrapper, params: [&dyn ToSql; 3]) {
        conn.prepare(
            "insert into test_table (name,balance_high_b, balance_low_b) values (?, ?, ?)",
        )
        .unwrap()
        .execute(params.as_slice())
        .unwrap();
    }

    #[derive(Debug, Default)]
    struct UpdateOverflowHandlerMock {
        update_with_overflow_params: Arc<Mutex<Vec<()>>>,
        update_with_overflow_results: RefCell<Vec<Result<(), BigIntDbError>>>,
    }

    impl<T> UpdateOverflowHandler<T> for UpdateOverflowHandlerMock {
        fn update_with_overflow<'a>(
            &self,
            _conn: Either<&dyn ConnectionWrapper, &Transaction>,
            _config: BigIntSqlConfig<'a, T>,
        ) -> Result<(), BigIntDbError> {
            self.update_with_overflow_params.lock().unwrap().push(());
            self.update_with_overflow_results.borrow_mut().remove(0)
        }
    }

    impl UpdateOverflowHandlerMock {
        fn update_with_overflow_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
            self.update_with_overflow_params = params.clone();
            self
        }

        fn update_with_overflow_result(self, result: Result<(), BigIntDbError>) -> Self {
            self.update_with_overflow_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Debug, PartialEq)]
    struct ConventionalUpsertUpdateAnalysisData {
        was_update_with_overflow: bool,
        final_database_values: ReadFinalRow,
    }

    #[derive(Debug, PartialEq)]
    struct ReadFinalRow {
        high_bytes: i64,
        low_bytes: i64,
        as_i128: i128,
    }

    fn analyse_sql_commands_execution_without_details_of_overflow(
        test_name: &str,
        main_sql: &str,
        requested_wei_change: WeiChange,
        init_record: i128,
    ) -> ConventionalUpsertUpdateAnalysisData {
        let update_with_overflow_params_arc = Arc::new(Mutex::new(vec![]));
        let overflow_handler = UpdateOverflowHandlerMock::default()
            .update_with_overflow_params(&update_with_overflow_params_arc)
            .update_with_overflow_result(Ok(()));
        let mut subject = BigIntDbProcessor::<DummyDao>::default();
        subject.overflow_handler = Box::new(overflow_handler);

        let act = |conn: &mut dyn ConnectionWrapper| {
            subject.execute(
                Left(conn),
                BigIntSqlConfig::new(
                    main_sql,
                    "",
                    SQLParamsBuilder::default()
                        .key(test_database_key(&"Joe"))
                        .wei_change(requested_wei_change.clone())
                        .build(),
                ),
            )
        };

        precise_upsert_or_update_assertion_test_environment(
            test_name,
            init_record,
            act,
            update_with_overflow_params_arc,
        )
    }

    fn precise_upsert_or_update_assertion_test_environment<F>(
        test_name: &str,
        init_record: i128,
        act: F,
        update_with_overflow_params_arc: Arc<Mutex<Vec<()>>>,
    ) -> ConventionalUpsertUpdateAnalysisData
    where
        F: Fn(&mut dyn ConnectionWrapper) -> Result<(), BigIntDbError>,
    {
        let mut conn = initiate_simple_connection_and_test_table("big_int_db_processor", test_name);
        if init_record != 0 {
            let (init_high, init_low) = BigIntDivider::deconstruct(init_record);
            insert_single_record(conn.as_ref(), [&"Joe", &init_high, &init_low])
        };

        let result = act(conn.as_mut());

        assert_eq!(result, Ok(()));
        let update_with_overflow_params = update_with_overflow_params_arc.lock().unwrap();
        let was_update_with_overflow = !update_with_overflow_params.is_empty();
        assert_on_whole_row(was_update_with_overflow, &*conn, "Joe")
    }

    fn assert_on_whole_row(
        was_update_with_overflow: bool,
        conn: &dyn ConnectionWrapper,
        expected_name: &str,
    ) -> ConventionalUpsertUpdateAnalysisData {
        let final_database_values = conn
            .prepare("select name, balance_high_b, balance_low_b from test_table")
            .unwrap()
            .query_row([], |row| {
                let name = row.get::<usize, String>(0).unwrap();
                assert_eq!(name, expected_name.to_string());
                let high_bytes = row.get::<usize, i64>(1).unwrap();
                let low_bytes = row.get::<usize, i64>(2).unwrap();
                let single_numbered_balance = BigIntDivider::reconstitute(high_bytes, low_bytes);
                Ok(ReadFinalRow {
                    high_bytes,
                    low_bytes,
                    as_i128: single_numbered_balance,
                })
            })
            .unwrap();
        ConventionalUpsertUpdateAnalysisData {
            was_update_with_overflow,
            final_database_values,
        }
    }

    fn create_new_empty_db(module: &str, test_name: &str) -> Connection {
        let home_dir = ensure_node_home_directory_exists(module, test_name);
        let db_path = home_dir.join("test_table.db");
        Connection::open(db_path.as_path()).unwrap()
    }

    fn create_test_table(conn: &Connection) {
        conn.execute(
            "create table test_table (name text primary key, balance_high_b integer not null, balance_low_b integer not null) strict",
            [],
        )
            .unwrap();
    }

    fn initiate_simple_connection_and_test_table(
        module: &str,
        test_name: &str,
    ) -> Box<ConnectionWrapperReal> {
        let conn = create_new_empty_db(module, test_name);
        create_test_table(&conn);
        Box::new(ConnectionWrapperReal::new(conn))
    }

    const STANDARD_EXAMPLE_OF_UPDATE_CLAUSE: &str = "update test_table set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name";
    const STANDARD_EXAMPLE_OF_INSERT_CLAUSE: &str = "insert into test_table (name, balance_high_b, balance_low_b) values (:name, :balance_high_b, :balance_low_b)";
    const STANDARD_EXAMPLE_OF_INSERT_WITH_CONFLICT_CLAUSE: &str = "insert into test_table (name, balance_high_b, balance_low_b) values (:name, :balance_high_b, :balance_low_b) on conflict (name) do update set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name";
    const STANDARD_EXAMPLE_OF_OVERFLOW_UPDATE_CLAUSE: &str = "update test_table set balance_high_b = :balance_high_b, balance_low_b = :balance_low_b where name = :name";

    #[test]
    fn update_alone_works_for_addition() {
        let initial = BigIntDivider::reconstitute(55, 1234567);
        let wei_change = BigIntDivider::reconstitute(1, 22222);

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "update_alone_works_for_addition",
            STANDARD_EXAMPLE_OF_UPDATE_CLAUSE,
            Addition("balance", wei_change as u128),
            initial,
        );

        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: false,
                final_database_values: ReadFinalRow {
                    high_bytes: 56,
                    low_bytes: 1256789,
                    as_i128: initial + wei_change
                }
            }
        )
    }

    #[test]
    fn update_alone_works_for_addition_with_overflow() {
        let initial = BigIntDivider::reconstitute(55, i64::MAX - 5);
        let wei_change = BigIntDivider::reconstitute(1, 6);

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "update_alone_works_for_addition_with_overflow",
            STANDARD_EXAMPLE_OF_UPDATE_CLAUSE,
            Addition("balance", wei_change as u128),
            initial,
        );

        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: true,
                //overflow halts the update machinery within this specific test, no numeric change
                final_database_values: ReadFinalRow {
                    high_bytes: 55,
                    low_bytes: i64::MAX - 5,
                    as_i128: initial
                }
            }
        )
    }

    #[test]
    fn update_alone_works_for_subtraction() {
        let initial = BigIntDivider::reconstitute(55, i64::MAX - 5);
        let wei_change = -(i64::MAX - 3) as i128;

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "update_alone_works_for_subtraction",
            STANDARD_EXAMPLE_OF_UPDATE_CLAUSE,
            Subtraction("balance", wei_change.abs() as u128),
            initial,
        );

        assert_eq!(BigIntDivider::deconstruct(wei_change), (-1, 4));
        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: false,
                final_database_values: ReadFinalRow {
                    high_bytes: 54,
                    low_bytes: i64::MAX - 1,
                    as_i128: initial - (-wei_change)
                }
            }
        )
    }

    #[test]
    fn update_alone_works_for_subtraction_with_overflow() {
        let initial = BigIntDivider::reconstitute(55, 4588288282);
        let wei_change: i128 = -12;

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "update_alone_works_for_subtraction_with_overflow",
            STANDARD_EXAMPLE_OF_UPDATE_CLAUSE,
            Subtraction("balance", wei_change.abs() as u128),
            initial,
        );

        assert_eq!(
            BigIntDivider::deconstruct(wei_change),
            (-1, 9223372036854775796)
        );
        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: true,
                //overflow halts the update machinery within this specific test, no numeric change
                final_database_values: ReadFinalRow {
                    high_bytes: 55,
                    low_bytes: 4588288282,
                    as_i128: initial
                }
            }
        )
    }

    #[test]
    fn early_return_for_successful_insert_works_for_addition() {
        let initial = BigIntDivider::reconstitute(0, 0);
        let wei_change = BigIntDivider::reconstitute(845, 7788);

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "early_return_for_successful_insert_works",
            STANDARD_EXAMPLE_OF_INSERT_CLAUSE,
            Addition("balance", wei_change as u128),
            initial,
        );

        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: false,
                final_database_values: ReadFinalRow {
                    high_bytes: 845,
                    low_bytes: 7788,
                    as_i128: wei_change
                }
            }
        )
    }

    #[test]
    fn early_return_for_successful_insert_works_for_subtraction() {
        let initial = BigIntDivider::reconstitute(0, 0);
        let wei_change: i128 = -987654;

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "early_return_for_successful_insert_works_for_subtraction",
            STANDARD_EXAMPLE_OF_INSERT_CLAUSE,
            Subtraction("balance", wei_change.abs() as u128),
            initial,
        );

        assert_eq!(
            BigIntDivider::deconstruct(wei_change),
            (-1, 9223372036853788154)
        );
        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: false,
                final_database_values: ReadFinalRow {
                    high_bytes: -1,
                    low_bytes: 9223372036853788154,
                    as_i128: wei_change
                }
            }
        )
    }

    #[test]
    fn insert_blocked_simple_update_succeeds_for_addition() {
        let initial = BigIntDivider::reconstitute(-50, 20);
        let wei_change = BigIntDivider::reconstitute(3, 4);

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "insert_blocked_simple_update_succeeds_for_addition",
            STANDARD_EXAMPLE_OF_INSERT_WITH_CONFLICT_CLAUSE,
            Addition("balance", wei_change as u128),
            initial,
        );

        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: false,
                final_database_values: ReadFinalRow {
                    high_bytes: -47,
                    low_bytes: 24,
                    as_i128: initial + wei_change
                }
            }
        )
    }

    #[test]
    fn insert_blocked_simple_update_succeeds_for_subtraction() {
        let initial = BigIntDivider::reconstitute(-50, 20);
        let wei_change: i128 = -27670116110564327418;

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "insert_blocked_simple_update_succeeds_for_subtraction",
            STANDARD_EXAMPLE_OF_INSERT_WITH_CONFLICT_CLAUSE,
            Subtraction("balance", wei_change.abs() as u128),
            initial,
        );

        assert_eq!(BigIntDivider::deconstruct(wei_change), (-3, 6));
        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: false,
                final_database_values: ReadFinalRow {
                    high_bytes: -53,
                    low_bytes: 26,
                    as_i128: initial - (-wei_change)
                }
            }
        )
    }

    #[test]
    fn insert_blocked_update_with_overflow_for_addition() {
        let initial = BigIntDivider::reconstitute(-50, 20);
        let wei_change = BigIntDivider::reconstitute(8, i64::MAX - 19);

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "insert_blocked_update_with_overflow_for_addition",
            STANDARD_EXAMPLE_OF_INSERT_WITH_CONFLICT_CLAUSE,
            Addition("balance", wei_change as u128),
            initial,
        );

        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: true,
                //overflow halts the update machinery within this specific test, no numeric change
                final_database_values: ReadFinalRow {
                    high_bytes: -50,
                    low_bytes: 20,
                    as_i128: initial
                }
            }
        )
    }

    #[test]
    fn insert_blocked_update_with_overflow_for_subtraction() {
        let initial = BigIntDivider::reconstitute(-44, 11);
        let wei_change: i128 = -7;

        let result = analyse_sql_commands_execution_without_details_of_overflow(
            "insert_blocked_update_with_overflow_for_subtraction",
            STANDARD_EXAMPLE_OF_INSERT_WITH_CONFLICT_CLAUSE,
            Subtraction("balance", wei_change.abs() as u128),
            initial,
        );

        assert_eq!(
            BigIntDivider::deconstruct(wei_change),
            (-1, 9223372036854775801)
        );
        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: true,
                //overflow halts the update machinery within this specific test, no numeric change
                final_database_values: ReadFinalRow {
                    high_bytes: -44,
                    low_bytes: 11,
                    as_i128: initial
                }
            }
        );
    }

    #[test]
    fn update_alone_works_also_for_transaction_instead_of_connection() {
        let initial = BigIntDivider::reconstitute(10, 20);
        let wei_change = BigIntDivider::reconstitute(0, 30);
        let subject = BigIntDbProcessor::<DummyDao>::default();
        let act = |conn: &mut dyn ConnectionWrapper| {
            let tx = conn.transaction().unwrap();
            let result = subject.execute(
                Either::Right(&tx),
                BigIntSqlConfig::new(
                    STANDARD_EXAMPLE_OF_UPDATE_CLAUSE,
                    "",
                    SQLParamsBuilder::default()
                        .key(test_database_key(&"Joe"))
                        .wei_change(Addition("balance", wei_change as u128))
                        .build(),
                ),
            );
            tx.commit().unwrap();
            result
        };
        let result = precise_upsert_or_update_assertion_test_environment(
            "update_alone_works_also_for_transaction_instead_of_connection",
            initial,
            act,
            Arc::new(Mutex::new(vec![])),
        );

        assert_eq!(
            result,
            ConventionalUpsertUpdateAnalysisData {
                was_update_with_overflow: false,
                final_database_values: ReadFinalRow {
                    high_bytes: 10,
                    low_bytes: 50,
                    as_i128: initial + wei_change
                }
            }
        )
    }

    #[test]
    fn main_sql_clause_error_handled() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "main_sql_clause_error_handled",
        );
        let subject = BigIntDbProcessor::<DummyDao>::default();
        let balance_change = Addition("balance", 4879898145125);
        let config = BigIntSqlConfig::new(
            "insert into test_table (name, balance_high_b, balance_low_b) values (:name, :balance_wrong_a, :balance_wrong_b) on conflict (name) do \
             update set balance_high_b = balance_high_b + 5, balance_low_b = balance_low_b + 10 where name = :name",
            "",
            SQLParamsBuilder::default()
                .key(test_database_key(&"Joe"))
                .wei_change(balance_change)
                .build(),
        );

        let result = subject.execute(Left(conn.as_ref()), config);

        assert_eq!(
            result,
            Err(BigIntDbError(
                "Error from invalid upsert command for test_table table and change of 4879898145125 \
                wei to 'name = Joe' with error 'Invalid parameter name: :balance_high_b'"
                    .to_string()
            ))
        );
    }

    fn update_with_overflow_shared_test_body(
        test_name: &str,
        init_big_initial: i128,
        balance_change: WeiChange,
    ) -> (i64, i64) {
        let conn = initiate_simple_connection_and_test_table("big_int_db_processor", test_name);
        let (init_high_bytes, init_low_bytes) = BigIntDivider::deconstruct(init_big_initial);
        insert_single_record(&*conn, [&"Joe", &init_high_bytes, &init_low_bytes]);
        let update_config = BigIntSqlConfig::new(
            "",
            STANDARD_EXAMPLE_OF_OVERFLOW_UPDATE_CLAUSE,
            SQLParamsBuilder::default()
                .wei_change(balance_change)
                .key(test_database_key(&"Joe"))
                .build(),
        );

        let result = BigIntDbProcessor::<DummyDao>::default()
            .overflow_handler
            .update_with_overflow(Left(&*conn), update_config);

        assert_eq!(result, Ok(()));
        let (final_high_bytes, final_low_bytes) = conn
            .prepare("select balance_high_b, balance_low_b from test_table where name = 'Joe'")
            .unwrap()
            .query_row([], |row| {
                let high_bytes = row.get::<usize, i64>(0).unwrap();
                let low_bytes = row.get::<usize, i64>(1).unwrap();
                Ok((high_bytes, low_bytes))
            })
            .unwrap();
        (final_high_bytes, final_low_bytes)
    }

    #[test]
    fn update_with_overflow_for_addition() {
        let big_initial = i64::MAX as i128 * 3;
        let big_addend = i64::MAX as i128 + 454;
        let big_sum = big_initial + big_addend;

        let (final_high_bytes, final_low_bytes) = update_with_overflow_shared_test_body(
            "update_with_overflow_for_addition",
            big_initial,
            Addition("balance", big_addend as u128),
        );

        assert_eq!(
            BigIntDivider::deconstruct(big_initial),
            (2, 9223372036854775805)
        );
        assert_eq!(BigIntDivider::deconstruct(big_addend), (1, 453));
        let result = BigIntDivider::reconstitute(final_high_bytes, final_low_bytes);
        assert_eq!(result, big_sum)
    }

    #[test]
    fn update_with_overflow_for_subtraction_from_positive_num() {
        let big_initial = i64::MAX as i128 * 2;
        let big_subtrahend = i64::MAX as i128 + 120;
        let big_sum = big_initial - big_subtrahend;

        let (final_high_bytes, final_low_bytes) = update_with_overflow_shared_test_body(
            "update_with_overflow_for_subtraction_from_positive_num",
            big_initial,
            Subtraction("balance", big_subtrahend as u128),
        );

        assert_eq!(
            BigIntDivider::deconstruct(big_initial),
            (1, 9223372036854775806)
        );
        assert_eq!(
            BigIntDivider::deconstruct(-big_subtrahend),
            (-2, 9223372036854775689)
        );
        let result = BigIntDivider::reconstitute(final_high_bytes, final_low_bytes);
        assert_eq!(result, big_sum)
    }

    #[test]
    fn update_with_overflow_for_subtraction_from_negative_num() {
        let big_initial = i64::MAX as i128 * 3 + 200;
        let big_subtrahend = i64::MAX as i128 + 120;
        let big_sum = -big_initial - big_subtrahend;

        let (final_high_bytes, final_low_bytes) = update_with_overflow_shared_test_body(
            "update_with_overflow_for_subtraction_from_negative_num",
            -big_initial,
            Subtraction("balance", big_subtrahend as u128),
        );

        assert_eq!(
            BigIntDivider::deconstruct(-big_initial),
            (-4, 9223372036854775611)
        );
        assert_eq!(
            BigIntDivider::deconstruct(-big_subtrahend),
            (-2, 9223372036854775689)
        );
        let result = BigIntDivider::reconstitute(final_high_bytes, final_low_bytes);
        assert_eq!(result, big_sum)
    }

    #[test]
    fn update_with_overflow_handles_unspecific_error() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "update_with_overflow_handles_unspecific_error",
        );
        let balance_change = Addition("balance", 100);
        let update_config = BigIntSqlConfig::new(
            "this can be whatever because the test fails earlier on the select stm",
            STANDARD_EXAMPLE_OF_OVERFLOW_UPDATE_CLAUSE,
            SQLParamsBuilder::default()
                .wei_change(balance_change)
                .key(test_database_key(&"Joe"))
                .build(),
        );

        let result = BigIntDbProcessor::<DummyDao>::default()
            .overflow_handler
            .update_with_overflow(Left(conn.as_ref()), update_config);

        //this kind of error is impossible in the real use case but is easiest regarding an arrangement of the test
        assert_eq!(
            result,
            Err(BigIntDbError(
                "Updating balance for test_table table and change of 100 wei to 'name = Joe' with \
         error 'Query returned no rows'"
                    .to_string()
            ))
        );
    }

    #[test]
    #[should_panic(
        expected = "Broken code: this code was written to handle one changed row a time, not 2"
    )]
    fn update_with_overflow_is_designed_to_handle_one_record_a_time() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "update_with_overflow_is_designed_to_handle_one_record_a_time",
        );
        insert_single_record(&*conn, [&"Joe", &60, &5555]);
        insert_single_record(&*conn, [&"Jodie", &77, &0]);
        let balance_change = Addition("balance", 100);
        let update_config = BigIntSqlConfig::new(
            "",
            "update test_table set balance_high_b = balance_high_b + :balance_high_b, \
            balance_low_b = balance_low_b + :balance_low_b where name in (:name, 'Jodie')",
            SQLParamsBuilder::default()
                .wei_change(balance_change)
                .key(test_database_key(&"Joe"))
                .build(),
        );

        let _ = BigIntDbProcessor::<DummyDao>::default()
            .overflow_handler
            .update_with_overflow(Left(conn.as_ref()), update_config);
    }

    #[test]
    fn update_with_overflow_handles_error_from_executing_the_initial_select_stm() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "update_with_overflow_handles_error_from_executing_the_initial_select_stm",
        );
        conn.prepare("alter table test_table drop column balance_low_b")
            .unwrap()
            .execute([])
            .unwrap();
        conn.prepare("alter table test_table add column balance_low_b text")
            .unwrap()
            .execute([])
            .unwrap();
        insert_single_record(&*conn, [&"Joe", &60, &"bad type"]);
        let balance_change = Addition("balance", 100);
        let update_config = BigIntSqlConfig::new(
            "this can be whatever because the test fails earlier on the select stm",
            "",
            SQLParamsBuilder::default()
                .wei_change(balance_change)
                .key(test_database_key(&"Joe"))
                .build(),
        );

        let result = BigIntDbProcessor::<DummyDao>::default()
            .overflow_handler
            .update_with_overflow(Left(conn.as_ref()), update_config);

        assert_eq!(
            result,
            Err(BigIntDbError(
                "Updating balance for test_table table and change of 100 wei to 'name = Joe' with error \
        'Invalid column type Text at index: 1, name: balance_low_b'"
                    .to_string()
            ))
        );
    }

    fn assert_reconstitution(as_two_integers: (i64, i64), expected_number: i128) {
        let result = BigIntDivider::reconstitute(as_two_integers.0, as_two_integers.1);

        assert_eq!(result, expected_number)
    }

    #[test]
    fn deconstruct_and_reconstitute_works_for_huge_number() {
        let tested_number = (0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128) as i128;

        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (i64::MAX, i64::MAX));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_and_reconstitute_works_for_number_just_slightly_bigger_than_the_low_b_type_size()
    {
        let tested_number = i64::MAX as i128 + 1;

        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (1, 0));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_big_number() {
        let tested_number = i64::MAX as i128;
        let result = BigIntDivider::deconstruct(i64::MAX as i128);

        assert_eq!(result, (0, 9223372036854775807));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_small_positive_number() {
        let tested_number = 1;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (0, 1));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_zero() {
        let tested_number = 0;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (0, 0));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_small_negative_number() {
        let tested_number = -1;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (-1, i64::MAX));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_big_negative_number() {
        let tested_number = i64::MIN as i128;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (-1, 0));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_and_reconstitute_works_for_number_just_slightly_smaller_than_the_low_b_type_size(
    ) {
        let tested_number = i64::MIN as i128 - 1;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (-2, 9223372036854775807));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_huge_negative_number() {
        let tested_number = 0xC0000000000000000000000000000000u128 as i128;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (-9223372036854775808, 0));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    #[should_panic(
        expected = "Dividing big integer for special database storage: 0x40000000000000000000000000000000 is too big, maximally 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF allowed"
    )]
    fn deconstruct_has_its_limits_up() {
        let _ = BigIntDivider::deconstruct(0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + 1);
    }

    #[test]
    #[should_panic(
        expected = "Dividing big integer for special database storage: 0xBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF is too small, minimally 0xC0000000000000000000000000000000 allowed"
    )]
    fn deconstruct_has_its_limits_down() {
        let _ = BigIntDivider::deconstruct((0xC0000000000000000000000000000000u128 as i128) - 1);
    }

    #[test]
    #[should_panic(
        expected = "Reconstituting big integer from special database storage: the second, lower integer 0xFFFFFFFFFFFFFFFF is signed despite the requirement to be all-time positive"
    )]
    fn reconstitute_should_reject_lower_half_with_high_bit_set() {
        let _ = BigIntDivider::reconstitute(0, -1);
    }

    #[test]
    fn divided_integers_can_be_ordered() {
        let a = i64::MAX as i128 * 23;
        let b = i64::MAX as i128 + 1;
        let c = i64::MAX as i128;
        let d = (i64::MAX - 1) as i128;
        let e = 5432;
        let f = 0;
        let g = -4567;
        let h = (i64::MIN + 1) as i128;
        let i = i64::MIN as i128;
        let j = i64::MIN as i128 - 1;
        let k = i64::MIN as i128 * 32;
        let vec = vec![b, c, d, e, f, g, h, i, j, k];

        let _ = vec.into_iter().enumerate().fold(
            a,
            |previous, current: (usize, i128)| {
                let (previous_high_b, previous_low_b) = BigIntDivider::deconstruct(previous);
                let (current_high_b, current_low_b) = BigIntDivider::deconstruct(current.1);
                assert!(
                    (previous_high_b > current_high_b) || (previous_high_b == current_high_b && previous_low_b > current_low_b) ,
                    "previous_high_b: {}, current_high_b: {} and previous_low_b: {}, current_low_b: {} for {} and {} which is idx {}",
                    previous_high_b,
                    current_high_b,
                    previous_low_b,
                    current_low_b,
                    BigIntDivider::reconstitute(previous_high_b, previous_low_b),
                    BigIntDivider::reconstitute(current_high_b, current_low_b),
                    current.0
                );
                current.1
            },
        );
    }

    fn create_test_table_and_run_register_deconstruction_for_sqlite_connection(
        test_name: &str,
    ) -> Connection {
        let conn = create_new_empty_db("big_int_db_processor", test_name);
        BigIntDivider::register_big_int_deconstruction_for_sqlite_connection(&conn).unwrap();
        conn.execute("create table test_table (computed_high_bytes int, computed_low_bytes int, database_parameter int not null)",[]).unwrap();
        conn
    }

    #[test]
    fn register_deconstruct_for_sqlite_connection_works() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_works",
        );

        let database_value_1: i64 = 12222;
        let database_value_2: i64 = 23333444;
        let database_value_3: i64 = 5555;
        let slope: i64 = -35_000_000;
        conn.execute(
            "insert into test_table (database_parameter) values (?),(?),(?)",
            &[&database_value_1, &database_value_2, &database_value_3],
        )
        .unwrap();
        let arbitrary_constant = 111222333444_i64;
        conn.execute(
            "update test_table set computed_high_bytes = slope_drop_high_bytes(:my_constant, :slope, database_parameter),\
        computed_low_bytes = slope_drop_low_bytes(:my_constant, :slope, database_parameter)",
            &[(":my_constant", &arbitrary_constant), (":slope", &slope)],
        )
        .unwrap();
        let mut stm = conn
            .prepare("select computed_high_bytes, computed_low_bytes from test_table")
            .unwrap();
        let computed_values = stm
            .query_map([], |row| {
                let high_bytes = row.get::<usize, i64>(0).unwrap();
                let low_bytes = row.get::<usize, i64>(1).unwrap();
                Ok((high_bytes, low_bytes))
            })
            .unwrap()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(
            computed_values,
            vec![
                BigIntDivider::deconstruct(
                    gwei_to_wei::<i128, _>(arbitrary_constant) + (slope * database_value_1) as i128
                ),
                BigIntDivider::deconstruct(
                    gwei_to_wei::<i128, _>(arbitrary_constant) + (slope * database_value_2) as i128
                ),
                BigIntDivider::deconstruct(
                    gwei_to_wei::<i128, _>(arbitrary_constant) + (slope * database_value_3) as i128
                )
            ]
        );
    }

    #[test]
    fn user_defined_functions_error_implements_display() {
        assert_eq!(
            InvalidInputValue("CoolFn".to_string(), "error message".to_string()).to_string(),
            "Error from CoolFn: error message".to_string()
        )
    }

    #[test]
    fn register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_first_function() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_first_function",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (slope_drop_high_bytes('hello', -4005000000, 712))",
                [],
            )
            .unwrap_err();

        assert_eq!(
            result,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_high_bytes: First argument takes only i64, not: Text([104, 101, 108, 108, 111])"
                        .to_string()
                )
            )
        )
    }

    #[test]
    fn register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_second_function() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_second_function",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (slope_drop_low_bytes('bye', -10000000000, 44233))",
                [],
            )
            .unwrap_err();

        assert_eq!(
            result,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_low_bytes: First argument takes only i64, not: Text([98, 121, 101])".to_string()
                )
            )
        )
    }

    #[test]
    fn our_sqlite_functions_are_specialized_and_thus_should_not_take_positive_number_for_the_second_parameter(
    ) {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "our_sqlite_functions_are_specialized_and_thus_should_not_take_positive_number_for_the_second_parameter"
        );
        let error_invoker = |bytes_type: &str| {
            let sql = format!(
                "insert into test_table (computed_{0}_bytes) values (slope_drop_{0}_bytes(45656, 5656, 11111))",
                bytes_type
            );
            conn.execute(&sql, []).unwrap_err()
        };

        let high_bytes_error = error_invoker("high");
        let low_bytes_error = error_invoker("low");

        assert_eq!(
            high_bytes_error,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_high_bytes: Nonnegative slope 5656; delinquency \
                        slope must be negative, since debts must become more delinquent over time."
                        .to_string()
                )
            )
        );
        assert_eq!(
            low_bytes_error,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_low_bytes: Nonnegative slope 5656; delinquency \
                       slope must be negative, since debts must become more delinquent over time."
                        .to_string()
                )
            )
        );
    }

    #[test]
    fn our_sqlite_functions_are_specialized_thus_should_not_take_negative_number_for_the_third_parameter(
    ) {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "our_sqlite_functions_are_specialized_thus_should_not_take_negative_number_for_the_third_parameter"
        );
        let error_invoker = |bytes_type: &str| {
            let sql = format!(
                "insert into test_table (computed_{0}_bytes) values (slope_drop_{0}_bytes(45656, -500000, -11111))",
                bytes_type
            );
            conn.execute(&sql, []).unwrap_err()
        };

        let high_bytes_error = error_invoker("high");
        let low_bytes_error = error_invoker("low");

        assert_eq!(
            high_bytes_error,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_high_bytes: Negative time parameter -11111; debt age cannot go negative."
                        .to_string()
                )
            )
        );
        assert_eq!(
            low_bytes_error,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_low_bytes: Negative time parameter -11111; debt age cannot go negative."
                        .to_string()
                )
            )
        );
    }

    #[test]
    fn third_argument_error() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "third_argument_error",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (slope_drop_low_bytes(15464646, 7866, 'time'))",
                [],
            )
            .unwrap_err();

        assert_eq!(
            result,
            SqliteFailure(
                rusqlite::ffi::Error{ code: ErrorCode::Unknown, extended_code: 1 },
                Some("Error from slope_drop_low_bytes: Third argument takes only i64, not: Text([116, 105, 109, 101])".to_string()
            ))
        )
    }

    #[test]
    fn first_fn_returns_internal_error_from_create_scalar_function() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "first_fn_returns_internal_error_from_create_scalar_function",
        );

        let result = BigIntDivider::register_deconstruct_guts(
            &conn,
            "badly\u{0000}named",
            "slope_drop_low_bytes",
        )
        .unwrap_err();

        //not asserting on the exact fit because the error
        //would involve some unstable code at reproducing it
        assert_eq!(
            result.to_string(),
            "nul byte found in provided data at position: 5".to_string()
        )
    }

    #[test]
    fn second_fn_returns_internal_error_from_create_scalar_function() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "second_fn_returns_internal_error_from_create_scalar_function",
        );

        let result = BigIntDivider::register_deconstruct_guts(
            &conn,
            "slope_drop_high_bytes",
            "also\u{0000}badlynamed",
        )
        .unwrap_err();

        //not asserting on the exact fit because the error
        //would involve some unstable code at reproducing it
        assert_eq!(
            result.to_string(),
            "nul byte found in provided data at position: 4".to_string()
        )
    }
}