// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableDaoError;
use crate::accountant::receivable_dao::ReceivableDaoError;
use crate::accountant::{checked_conversion, politely_checked_conversion};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use masq_lib::utils::ExpectValue;
use rusqlite::types::ToSqlOutput;
use rusqlite::ErrorCode::ConstraintViolation;
use rusqlite::{Error, Row, Statement, ToSql, Transaction};
use std::fmt::{Debug, Display, Formatter};
use std::iter::once;
use std::marker::PhantomData;
use std::ops::Neg;

pub trait BlobInsertUpdate<T: 'static>: Send + Debug {
    fn update<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: &'a (dyn UpdateConfiguration<'a, T> + 'a),
    ) -> Result<(), BlobInsertUpdateError>;
    fn upsert<'a>(
        &self,
        conn: &dyn ConnectionWrapper,
        config: BlobInsertUpdateConfig<'a>,
    ) -> Result<(), BlobInsertUpdateError>;
}

#[derive(Debug)]
pub struct BlobInsertUpdateReal<T: Debug + DAOTableIdentifier + Send + 'static> {
    phantom: PhantomData<T>,
}

impl<T: DAOTableIdentifier + Debug + Send + 'static> BlobInsertUpdate<T>
    for BlobInsertUpdateReal<T>
{
    fn update<'a>(
        &self,
        form_of_conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: &'a (dyn UpdateConfiguration<'a, T> + 'a),
    ) -> Result<(), BlobInsertUpdateError> {
        let params = config.update_params();
        let ((correct_key_name_from_table, sql_key_name, key_idx), balance_change) =
            Self::fetch_fundamentals(params);
        let present_state_query = config.select_sql(&correct_key_name_from_table, &sql_key_name);
        let mut select_stm = Self::prepare_statement(form_of_conn, present_state_query.as_str());
        match select_stm.query_row(&[(&*sql_key_name, params.params[key_idx].1)], |row| {
            let balance_result: rusqlite::Result<i128> = row.get(0);
            match balance_result {
                Ok(balance) => {
                    let updated_balance = balance + balance_change;
                    let params_to_update = params.pure_rusqlite_params();
                    let update_params =
                        config.finalize_update_params(&updated_balance, params_to_update);
                    let update_query = config.update_sql();
                    let mut update_stm = Self::prepare_statement(form_of_conn, update_query);
                    update_stm.execute(&*update_params)
                }
                Err(e) => Err(e),
            }
        }) {
            Ok(_) => Ok(()),
            Err(e) => Err(BlobInsertUpdateError(format!(
                "Updating balance for {} of {} Wei to {} with error '{}'",
                config.table(),
                balance_change,
                params.params[key_idx].1,
                e
            ))),
        }
    }

    fn upsert<'a>(
        &self,
        conn: &dyn ConnectionWrapper,
        config: BlobInsertUpdateConfig<'a>,
    ) -> Result<(), BlobInsertUpdateError> {
        let params = config.params.pure_rusqlite_params();
        let mut stm = conn
            .prepare(config.insert_sql)
            .expect("internal rusqlite error");
        match stm.execute(&*params) {
            Ok(_) => Ok(()),
            Err(e)
                if match e {
                    Error::SqliteFailure(e, _) => matches!(e.code, ConstraintViolation),
                    _ => false,
                } =>
            {
                self.update(Either::Left(conn), &config)
            }
            Err(e) => {
                let params = config.params;
                let ((_, _, key_idx), amount) = Self::fetch_fundamentals(&params);
                Err(BlobInsertUpdateError(format!(
                    "Updating balance after invalid insertion for {} of {} Wei to {} with error '{}'",
                    T::table_name(), amount, params.params[key_idx].1, e
                    )
                ))
            }
        }
    }
}

impl<T: Debug + DAOTableIdentifier + Send> BlobInsertUpdateReal<T> {
    pub fn new() -> BlobInsertUpdateReal<T> {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: Debug + DAOTableIdentifier + Send> BlobInsertUpdateReal<T> {
    fn fetch_fundamentals(params: &SQLExtendedParams) -> ((String, String, usize), i128) {
        (
            params.fetch_key_specification(),
            params.fetch_balance_change(),
        )
    }

    fn prepare_statement<'a>(
        form_of_conn: Either<&'a dyn ConnectionWrapper, &'a Transaction>,
        query: &'a str,
    ) -> Statement<'a> {
        match form_of_conn {
            Either::Left(conn) => conn.prepare(query),
            Either::Right(tx) => tx.prepare(query),
        }
        .expect("internal rusqlite error")
    }
}

pub struct BlobInsertUpdateConfig<'a> {
    pub insert_sql: &'a str,
    pub update_sql: &'a str,
    pub params: SQLExtendedParams<'a>,
}

pub struct UpdateConfig<'a> {
    pub update_sql: &'a str,
    pub params: SQLExtendedParams<'a>,
}

pub trait ExtendedParamsMarker: ToSql + Display {
    fn balance_change_opt(&self) -> Option<i128> {
        None
    }
    fn key_name_opt(&self) -> Option<String> {
        None
    }
}

macro_rules! blank_impl_of_extended_params_marker{
    ($($implementer: ty),+) => {
        $(impl ExtendedParamsMarker for $implementer {})+
    }
}

//please don't implement for i128, instead use BalanceChange as intentionally designed

blank_impl_of_extended_params_marker!(i64, &str, Wallet);

impl ExtendedParamsMarker for BalanceChange {
    fn balance_change_opt(&self) -> Option<i128> {
        Some(self.change)
    }
}

impl ExtendedParamsMarker for KeyParamHolder<'_> {
    fn key_name_opt(&self) -> Option<String> {
        Some(self.key_param.0.to_string())
    }
}

pub struct SQLExtendedParams<'a> {
    params: Vec<(&'a str, &'a dyn ExtendedParamsMarker)>,
}

impl<'a> SQLExtendedParams<'a> {
    pub fn new(params: Vec<(&'a str, &'a (dyn ExtendedParamsMarker + 'a))>) -> Self {
        Self { params }
    }

    pub fn pure_rusqlite_params(&'a self) -> Vec<(&'a str, &'a dyn ToSql)> {
        self.params
            .iter()
            .map(|(first, second)| (*first, second as &dyn ToSql))
            .collect()
    }

    pub fn fetch_balance_change(&self) -> i128 {
        self.params
            .iter()
            .fold(
                None,
                |acc: Option<i128>, (_, balance_change_candidate)| match acc {
                    Some(x) => match balance_change_candidate.balance_change_opt() {
                        None => Some(x),
                        Some(_) => {
                            panic!("only one parameter of changed balance is allowed a time")
                        }
                    },
                    None => balance_change_candidate.balance_change_opt(),
                },
            )
            .unwrap_or_else(|| panic!("missing parameter of the change in balance; broken"))
    }

    pub fn fetch_key_specification(&self) -> (String, String, usize) {
        self.params
            .iter()
            .enumerate()
            .fold(
                None,
                |acc: Option<(String, String, usize)>, (idx, (param_name, key_candidate))| match acc
                {
                    Some(x) => match key_candidate.key_name_opt() {
                        None => Some(x),
                        Some(_) => panic!("only one key parameter is allowed"),
                    },
                    None => key_candidate.key_name_opt().map(|in_table_param_name| {
                        (in_table_param_name, param_name.to_string(), idx)
                    }),
                },
            )
            .unwrap_or_else(|| panic!("missing key parameter; broken"))
    }

    #[cfg(test)]
    pub fn extended_params_ref(&'a self) -> &'a Vec<(&'a str, &'a dyn ExtendedParamsMarker)> {
        &self.params
    }
}

pub trait UpdateConfiguration<'a, T: DAOTableIdentifier> {
    fn table(&self) -> String;
    fn select_sql(&self, in_table_param_name: &str, sql_param_name: &str) -> String {
        format!(
            "select balance from {} where {} = {}",
            &self.table(),
            in_table_param_name,
            sql_param_name
        )
    }
    fn update_sql(&self) -> &'a str;
    fn update_params(&self) -> &SQLExtendedParams;
    fn finalize_update_params<'b>(
        &'a self,
        updated_balance: &'b i128,
        params_to_update: Vec<(&'b str, &'b dyn ToSql)>,
    ) -> Vec<(&'b str, &'b dyn ToSql)> {
        params_to_update
            .into_iter()
            .filter(|(name, _)| *name != ":balance")
            .chain(once((":updated_balance", updated_balance as &dyn ToSql)))
            .collect()
    }
}

pub trait DAOTableIdentifier {
    fn table_name() -> String;
}

macro_rules! update_configuration_std_impl {
    ($implementor: ident) => {
        impl<'a, T: DAOTableIdentifier> UpdateConfiguration<'a, T> for $implementor<'a> {
            fn table(&self) -> String {
                T::table_name()
            }
            fn update_sql(&self) -> &'a str {
                self.update_sql
            }
            fn update_params(&self) -> &SQLExtendedParams {
                &self.params
            }
        }
    };
}

update_configuration_std_impl!(BlobInsertUpdateConfig);
update_configuration_std_impl!(UpdateConfig);

pub fn get_unsized_128(row: &Row, index: usize) -> Result<u128, rusqlite::Error> {
    row.get::<usize, i128>(index).map(|val| val as u128)
}

#[derive(PartialEq, Debug)]
pub struct BalanceChange {
    change: i128,
}

impl BalanceChange {
    pub fn new_addition(abs_change: u128) -> Self {
        Self {
            change: checked_conversion::<u128, i128>(abs_change),
        }
    }
    pub fn new_subtraction(abs_change: u128) -> Self {
        Self {
            change: checked_conversion::<u128, i128>(abs_change).neg(),
        }
    }

    pub fn polite_new_subtraction(abs_change: u128) -> Result<Self, String> {
        Ok(Self {
            change: politely_checked_conversion::<u128, i128>(abs_change).map(|num| num.neg())?,
        })
    }
}

impl ToSql for BalanceChange {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.change))
    }
}

impl Display for BalanceChange {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.change)
    }
}

pub struct KeyParamHolder<'a> {
    key_param: (&'a str, &'a dyn ExtendedParamsMarker),
}

impl<'a> KeyParamHolder<'a> {
    pub fn new(inner_value: &'a dyn ExtendedParamsMarker, key_parameter_name: &'a str) -> Self {
        Self {
            key_param: (key_parameter_name, inner_value),
        }
    }
}

impl ToSql for KeyParamHolder<'_> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.key_param.1.to_sql()
    }
}

impl Display for KeyParamHolder<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.key_param.1)
    }
}

#[derive(Debug, PartialEq)]
pub struct BlobInsertUpdateError(pub String);

macro_rules! insert_update_error_from {
    ($implementer: ident) => {
        impl From<BlobInsertUpdateError> for $implementer {
            fn from(iu_err: BlobInsertUpdateError) -> Self {
                $implementer::RusqliteError(iu_err.0)
            }
        }
    };
}

insert_update_error_from!(PayableDaoError);
insert_update_error_from!(ReceivableDaoError);

pub fn collect_and_sum_i128_values_from_table(
    conn: &dyn ConnectionWrapper,
    table: &str,
    parameter_name: &str,
) -> i128 {
    let select_stm = format!("select {} from {}", parameter_name, table);
    conn.prepare(&select_stm)
        .expect("select stm error")
        .query_map([], |row| {
            Ok(row.get::<usize, i128>(0).expectv("i128 value"))
        })
        .expect("select query failed")
        .flatten()
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::payable_dao::PayableDaoReal;
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::db_migrations::MigratorConfig;
    use crate::test_utils::make_wallet;
    use itertools::{Either, Itertools};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::types::ToSqlOutput;
    use rusqlite::{named_params, params, Connection, OpenFlags, ToSql};

    fn convert_params_to_debuggable_values<'a>(
        standard_params: Vec<(&'a str, &'a dyn ToSql)>,
    ) -> Vec<(&'a str, ToSqlOutput)> {
        let mut vec = standard_params
            .into_iter()
            .map(|(name, value)| (name, value.to_sql().unwrap()))
            .collect_vec();
        vec.sort_by(|(name_a, _), (name_b, _)| name_a.cmp(name_b));
        vec
    }

    #[derive(Debug)]
    struct DummyDao {}

    impl DAOTableIdentifier for DummyDao {
        fn table_name() -> String {
            String::from("test_table")
        }
    }

    #[test]
    fn finalize_update_params_for_update_config_works() {
        let balance_change = BalanceChange::new_addition(5555);
        let subject = UpdateConfig {
            update_sql: "blah",
            params: SQLExtendedParams::new(vec![
                (":something", &152_i64),
                (":balance", &balance_change),
                (":something_else", &"foooo"),
            ]),
        };

        finalize_update_params_assertion::<PayableDaoReal>(&subject)
    }

    #[test]
    fn finalize_update_params_for_insert_update_config_works() {
        let balance_change = BalanceChange::new_addition(5555);
        let subject = BlobInsertUpdateConfig {
            insert_sql: "blah1",
            update_sql: "blah2",
            params: SQLExtendedParams::new(vec![
                (":something", &152_i64),
                (":balance", &balance_change),
                (":something_else", &"foooo"),
            ]),
        };

        finalize_update_params_assertion::<PayableDaoReal>(&subject)
    }

    fn finalize_update_params_assertion<'a, T: DAOTableIdentifier>(
        subject: &'a dyn UpdateConfiguration<'a, T>,
    ) {
        let updated_balance = 456789;
        let balance_change = BalanceChange::new_addition(updated_balance as u128);

        let result = subject.finalize_update_params(
            &updated_balance,
            subject.update_params().pure_rusqlite_params(),
        );

        let expected_params: Vec<(&str, &dyn ToSql)> = vec![
            (":something", &152_i64),
            (":updated_balance", &balance_change),
            (":something_else", &"foooo"),
        ];
        let expected_assertable = convert_params_to_debuggable_values(expected_params);
        let result_assertable = convert_params_to_debuggable_values(result);
        assert_eq!(result_assertable, expected_assertable)
    }

    #[test]
    fn fetch_balance_change_works() {
        let balance_change = BalanceChange::new_addition(5021);
        let params = SQLExtendedParams {
            params: vec![
                (":something", &"yo-yo"),
                (":balance", &balance_change),
                (":something_else", &55_i64),
            ],
        };

        let result = params.fetch_balance_change();

        assert_eq!(result, 5021)
    }

    #[test]
    fn fetch_key_works() {
        let wallet = make_wallet("blah");
        let key_holder = KeyParamHolder::new(&wallet, "wallet");
        let params = SQLExtendedParams {
            params: vec![
                (":something", &"yo-yo"),
                (":wonderful_wallet", &key_holder),
                (":something_else", &55_i64),
            ],
        };

        let result = params.fetch_key_specification();

        let (in_table_name, sql_param_name, idx) = result;
        assert_eq!(in_table_name, "wallet".to_string());
        assert_eq!(sql_param_name, ":wonderful_wallet".to_string());
        assert_eq!(idx, 1)
    }

    #[test]
    #[should_panic(expected = "only one key parameter is allowed")]
    fn we_support_only_one_key_a_time_now() {
        let wallet = make_wallet("blah");
        let key_holder_1 = KeyParamHolder::new(&wallet, "param_name");
        let key_holder_2 = KeyParamHolder::new(&66_i64, "param_name_2");
        let params = SQLExtendedParams {
            params: vec![
                (":something", &"yo-yo"),
                (":wonderful_wallet", &key_holder_1),
                (":something_else", &key_holder_2),
            ],
        };

        let _ = params.fetch_key_specification();
    }

    #[test]
    #[should_panic(expected = "missing key parameter; broken")]
    fn no_key_is_an_issue() {
        let wallet = make_wallet("abc");
        let subject = SQLExtendedParams {
            params: vec![
                (":something", &"yo-yo"),
                (":wonderful_wallet", &wallet),
                (":something_else", &699_i64),
            ],
        };

        let _ = subject.fetch_key_specification();
    }

    #[test]
    #[should_panic(expected = "missing parameter of the change in balance; broken")]
    fn no_balance_change_is_an_issue() {
        let subject = SQLExtendedParams {
            params: vec![(":something", &"yo-yo"), (":something_else", &55_i64)],
        };

        let _ = subject.fetch_balance_change();
    }

    #[test]
    #[should_panic(expected = "only one parameter of changed balance is allowed a time")]
    fn we_support_only_one_change_balance_param() {
        let balance_change_1 = BalanceChange { change: 458 };
        let balance_change_2 = BalanceChange { change: -5000000 };
        let params = SQLExtendedParams {
            params: vec![
                (":something", &"yo-yo"),
                (":my_fortune", &balance_change_1),
                (":my_poverty", &balance_change_2),
            ],
        };

        let _ = params.fetch_balance_change();
    }

    #[test]
    fn conversion_from_insert_update_error_to_particular_payable_dao_error_works() {
        let subject = BlobInsertUpdateError(String::from("whatever"));

        let result: PayableDaoError = subject.into();

        assert_eq!(
            result,
            PayableDaoError::RusqliteError("whatever".to_string())
        )
    }

    #[test]
    fn conversion_from_insert_update_error_to_particular_receivable_dao_error_works() {
        let subject = BlobInsertUpdateError(String::from("whatever"));

        let result: ReceivableDaoError = subject.into();

        assert_eq!(
            result,
            ReceivableDaoError::RusqliteError("whatever".to_string())
        )
    }

    #[test]
    fn constructor_for_balance_change_works_for_addition() {
        let addition = BalanceChange::new_addition(50);

        assert_eq!(addition, BalanceChange { change: 50_i128 });
    }

    #[test]
    fn constructor_for_balance_change_works_for_subtraction() {
        let subtraction = BalanceChange::new_subtraction(i128::MIN as u128 - 1);

        assert_eq!(
            subtraction,
            BalanceChange {
                change: i128::MIN + 1
            }
        )
    }

    #[test]
    fn display_for_balance_change_works() {
        let subtraction = BalanceChange::new_subtraction(100);
        let addition = BalanceChange::new_addition(50);

        assert_eq!(subtraction.to_string(), "-100".to_string());
        assert_eq!(addition.to_string(), "50".to_string())
    }

    #[test]
    fn display_for_key_param_holder_works() {
        let wallet = make_wallet("booga");
        let key_holder_with_wallet = KeyParamHolder::new(&wallet, "wallet_address");
        let rowid = 56_i64;
        let key_holder_with_rowid = KeyParamHolder::new(&rowid, "pending_payable_rowid");

        assert_eq!(key_holder_with_wallet.to_string(), wallet.to_string());
        assert_eq!(key_holder_with_rowid.to_string(), rowid.to_string())
    }

    #[test]
    fn to_sql_for_param_key_holder_works() {
        let value_1 = make_wallet("boooga");
        let value_2 = 235_i64;
        let key_holder_1 = KeyParamHolder::new(&value_1, "random_wallet");
        let key_holder_2 = KeyParamHolder::new(&value_2, "random_parameter");

        let result_1 = key_holder_1.to_sql();
        let result_2 = key_holder_2.to_sql();

        assert_eq!(result_1, value_1.to_sql());
        assert_eq!(result_2, value_2.to_sql())
    }

    #[test]
    fn get_key_for_non_key_params_is_always_none() {
        assert_eq!("blah".key_name_opt().is_none(), true);
        assert_eq!(make_wallet("some wallet").key_name_opt().is_none(), true);
        assert_eq!(
            BalanceChange::new_addition(555).key_name_opt().is_none(),
            true
        );
        assert_eq!(56_i64.key_name_opt().is_none(), true)
    }

    #[test]
    fn getter_for_key_param_holder_returns_something_reasonable() {
        //notice that i64 alone returns None but inside this holder it is Some()...
        let key_object = KeyParamHolder::new(&8989_i64, "balance").key_name_opt();

        let in_table_param_name = key_object.unwrap();
        assert_eq!(in_table_param_name, "balance".to_string());
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 170141183460469231731687303715884105728: cannot be converted from u128 to i128"
    )]
    fn balance_change_constructor_blows_up_on_overflow_in_addition() {
        let _ = BalanceChange::new_addition(i128::MAX as u128 + 1);
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 170141183460469231731687303715884105728: cannot be converted from u128 to i128"
    )]
    fn balance_change_constructor_blows_up_on_overflow_in_subtraction() {
        let _ = BalanceChange::new_subtraction(i128::MIN as u128);
    }

    #[test]
    fn update_handles_error_for_insert_update_config() {
        let wallet_address = "a11122";
        let wallet_as_key = KeyParamHolder::new(&wallet_address, "wallet_address");
        let conn = Connection::open_in_memory().unwrap();
        conn.prepare(
            "create table payable
                  ( wallet_address text primary key,
                    balance blob not null,
                    last_paid_timestamp integer not null,
                    pending_payable_rowid integer null )",
        )
        .unwrap()
        .execute([])
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn);
        let balance_change = BalanceChange::new_addition(100);
        let update_config = BlobInsertUpdateConfig {
            insert_sql: "",
            update_sql: "",
            params: SQLExtendedParams::new(vec![
                (":wallet", &wallet_as_key),
                (":balance", &balance_change),
            ]),
        };

        let result = BlobInsertUpdateReal::<PayableDaoReal>::new()
            .update(Either::Left(&wrapped_conn), &update_config);

        assert_eq!(result, Err(BlobInsertUpdateError("Updating balance for payable of 100 Wei to a11122 with error 'Query returned no rows'".to_string())));
    }

    #[test]
    fn update_handles_error_on_a_row_due_to_unfitting_data_types() {
        let wallet_address = "a11122";
        let wallet_as_key = KeyParamHolder::new(&wallet_address, "wallet_address");
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "update_handles_error_on_a_row_due_to_unfitting_data_types",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let params = named_params! {
            ":wallet":wallet_address,
            ":balance":"bubblebooo",
            ":last_time_stamp":"genesis",
            ":pending_payable_rowid":45_i64
        };
        let mut stm = conn.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (:wallet,:balance,:last_time_stamp,:pending_payable_rowid)").unwrap();
        stm.execute(params).unwrap();
        let balance_change = BalanceChange::new_addition(100);
        let last_received_time_stamp_sec = 123_i64;
        let update_config = UpdateConfig {
            update_sql: "update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet",
            params: SQLExtendedParams::new(vec![(":wallet", &wallet_as_key), (":balance", &balance_change), (":last_received", &last_received_time_stamp_sec)]),
        };

        let result = BlobInsertUpdateReal::<PayableDaoReal>::new()
            .update(Either::Left(conn_ref), &update_config);

        assert_eq!(result, Err(BlobInsertUpdateError("Updating balance for payable of 100 Wei to a11122 with error 'Invalid column type Text at index: 0, name: balance'".to_string())));
    }

    #[test]
    fn update_handles_error_of_bad_sql_params() {
        let wallet_address = "a11122";
        let wallet_as_key = KeyParamHolder::new(&wallet_address, "wallet_address");
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "update_handles_error_of_bad_sql_params",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let mut stm = conn_ref.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (?,?,strftime('%s','now'),null)").unwrap();
        stm.execute(params![wallet_address, 45245_i128]).unwrap();
        let balance_change = BalanceChange::new_addition(100);
        let last_received_time_stamp_sec = 123_i64;
        let update_config = UpdateConfig {
            update_sql: "update receivable set balance = ?, last_received_timestamp = ? where wallet_address = ?",
            params: SQLExtendedParams::new( vec![(":woodstock", &wallet_address), (":hendrix", &last_received_time_stamp_sec), (":wallet", &wallet_as_key), (":balance", &balance_change)]),
        };

        let result = BlobInsertUpdateReal::<PayableDaoReal>::new()
            .update(Either::Left(conn_ref), &update_config);

        assert_eq!(result, Err(BlobInsertUpdateError("Updating balance for payable of 100 Wei to a11122 with error 'Invalid parameter name: :woodstock'".to_string())));
    }

    fn initiate_simple_connection_and_test_table(
        module: &str,
        test_name: &str,
        read_only_conn: bool,
    ) -> Box<ConnectionWrapperReal> {
        let home_dir = ensure_node_home_directory_exists(module, test_name);
        let db_path = home_dir.join("test_table.db");
        let conn = Connection::open(db_path.as_path()).unwrap();
        conn.execute(
            "create table test_table (name text primary key, balance integer not null)",
            [],
        )
        .unwrap();
        let conn = if !read_only_conn {
            conn
        } else {
            drop(conn);
            Connection::open_with_flags(db_path.as_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap()
        };
        Box::new(ConnectionWrapperReal::new(conn))
    }

    #[test]
    fn upsert_early_return_for_successful_insert_works() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_early_return_for_successful_insert_works",
            false,
        );
        let subject = BlobInsertUpdateReal::<DummyDao>::new();
        let config = BlobInsertUpdateConfig {
            insert_sql: "insert into test_table (name,balance) values (:name,:balance)",
            update_sql: "",
            params: SQLExtendedParams {
                params: vec![(":name", &"Joe"), (":balance", &255_i64)],
            },
        };

        let result = subject.upsert(conn.as_ref(), config);

        assert_eq!(result, Ok(()));
        conn.prepare("select * from test_table")
            .unwrap()
            .query_row([], |_row| Ok(()))
            .unwrap();
    }

    #[test]
    fn upsert_insert_failed_update_succeeded() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_insert_failed_update_succeeded",
            false,
        );
        conn.prepare("insert into test_table (name,balance) values ('Joe', ?)")
            .unwrap()
            .execute(&[&60_i128])
            .unwrap();
        let subject = BlobInsertUpdateReal::<DummyDao>::new();
        let key_holder = KeyParamHolder::new(&"Joe", "name");
        let balance_change = BalanceChange::new_addition(5555);
        let config = BlobInsertUpdateConfig {
            insert_sql: "insert into test_table (name,balance) values (:name,:balance)",
            update_sql: "update test_table set balance = :updated_balance where name = :name",
            params: SQLExtendedParams {
                params: vec![(":name", &key_holder), (":balance", &balance_change)],
            },
        };

        let result = subject.upsert(conn.as_ref(), config);

        assert_eq!(result, Ok(()));
        conn.prepare("select * from test_table")
            .unwrap()
            .query_row([], |row| {
                assert_eq!(row.get::<usize, String>(0).unwrap(), "Joe".to_string());
                assert_eq!(row.get::<usize, i128>(1).unwrap(), 60_i128 + 5555);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn upsert_insert_failed_update_failed_too() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_insert_failed_update_failed_too",
            false,
        );
        conn.prepare("insert into test_table (name,balance) values ('Joe', ?)")
            .unwrap()
            //notice the type difference here and later
            .execute(&[&60_i64])
            .unwrap();
        let subject = BlobInsertUpdateReal::<DummyDao>::new();
        let key_holder = KeyParamHolder::new(&"Joe", "name");
        let balance_change = BalanceChange::new_addition(5555);
        let config = BlobInsertUpdateConfig {
            insert_sql: "insert into test_table (name,balance) values (:name,:balance)",
            update_sql: "update test_table set balance = :updated_balance where name = :name",
            params: SQLExtendedParams {
                params: vec![(":name", &key_holder), (":balance", &balance_change)],
            },
        };

        let result = subject.upsert(conn.as_ref(), config);

        assert_eq!(
            result,
            Err(BlobInsertUpdateError(
                "Updating balance for test_table of 5555 Wei to Joe with \
        error 'Invalid column type Integer at index: 0, name: balance'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn upsert_insert_handles_unspecific_failures() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_insert_handles_unspecific_failures",
            false,
        );
        let subject = BlobInsertUpdateReal::<DummyDao>::new();
        let key_holder = KeyParamHolder::new(&"Joe", "name");
        let balance_change = BalanceChange::new_addition(5555);
        let config = BlobInsertUpdateConfig {
            insert_sql: "insert into test_table (name,balance) values (:name,:balance)",
            update_sql: "",
            params: SQLExtendedParams {
                params: vec![(":diff_name", &key_holder), (":balance", &balance_change)],
            },
        };

        let result = subject.upsert(conn.as_ref(), config);

        assert_eq!(
            result,
            Err(BlobInsertUpdateError(
                "Updating balance after invalid insertion for test_table \
         of 5555 Wei to Joe with error 'Invalid parameter name: :diff_name'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn upsert_insert_handles_sqlite_failure_other_than_constrain_violation() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_insert_handles_sqlite_failure_other_than_constrain_violation",
            true,
        );
        let subject = BlobInsertUpdateReal::<DummyDao>::new();
        let key_holder = KeyParamHolder::new(&"Joe", "name");
        let balance_change = BalanceChange::new_addition(5555);
        let config = BlobInsertUpdateConfig {
            insert_sql: "insert into test_table (name,balance) values (:name,:balance)",
            update_sql: "",
            params: SQLExtendedParams {
                params: vec![(":name", &key_holder), (":balance", &balance_change)],
            },
        };

        let result = subject.upsert(conn.as_ref(), config);

        assert_eq!(
            result,
            Err(BlobInsertUpdateError(
                "Updating balance after invalid insertion for test_table \
         of 5555 Wei to Joe with error 'attempt to write a readonly database'"
                    .to_string()
            ))
        );
    }
}
