// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::big_int_db_processor::BigIntDivider;
use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::receivable_dao::ReceivableAccount;
use crate::accountant::{checked_conversion, sign_conversion};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{connection_or_panic, DbInitializerReal};
use crate::database::db_migrations::MigratorConfig;
use crate::sub_lib::accountant::WEIS_OF_GWEI;
use masq_lib::messages::{
    TopRecordsConfig, TopRecordsOrdering, UiPayableAccount, UiReceivableAccount,
};
use masq_lib::utils::ExpectValue;
use rusqlite::{params_from_iter, Row, ToSql};
use std::cell::RefCell;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

pub fn to_time_t(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Err(e) => unimplemented!("{}", e),
        Ok(d) => sign_conversion::<u64, i64>(d.as_secs()).expect("MASQNode has expired"),
    }
}

pub fn now_time_t() -> i64 {
    to_time_t(SystemTime::now())
}

pub fn from_time_t(time_t: i64) -> SystemTime {
    let interval = Duration::from_secs(time_t as u64);
    SystemTime::UNIX_EPOCH + interval
}

pub struct DaoFactoryReal {
    pub data_directory: PathBuf,
    pub create_if_necessary: bool,
    pub migrator_config: RefCell<Option<MigratorConfig>>,
}

impl DaoFactoryReal {
    pub fn new(
        data_directory: &Path,
        create_if_necessary: bool,
        migrator_config: MigratorConfig,
    ) -> Self {
        Self {
            data_directory: data_directory.to_path_buf(),
            create_if_necessary,
            migrator_config: RefCell::new(Some(migrator_config)),
        }
    }

    pub fn make_connection(&self) -> Box<dyn ConnectionWrapper> {
        connection_or_panic(
            &DbInitializerReal::default(),
            &self.data_directory,
            self.create_if_necessary,
            self.migrator_config.take().expectv("MigratorConfig"),
        )
    }
}

impl<T> From<TopRecordsConfig> for CustomQuery<T> {
    fn from(config: TopRecordsConfig) -> Self {
        CustomQuery::TopRecords {
            count: config.count,
            ordered_by: config.ordered_by,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CustomQuery<N> {
    TopRecords {
        count: u16,
        ordered_by: TopRecordsOrdering,
    },
    RangeQuery {
        min_age_s: u64,
        max_age_s: u64,
        min_amount_gwei: N,
        max_amount_gwei: N,
    },
}

pub struct TopStmConfig {
    limit_clause: &'static str,
    //this constrain, unlike to the other case, has a clear look and a constant value
    gwei_min_resolution_clause: &'static str,
    age_param: &'static str,
}

impl TopStmConfig {
    pub fn new(age_param: &'static str) -> Self {
        Self {
            limit_clause: "limit ?",
            gwei_min_resolution_clause: "where balance >= ?",
            age_param,
        }
    }
}

pub struct RangeStmConfig {
    pub where_clause: &'static str,
    pub gwei_min_resolution_clause: &'static str,
    //note that this constrain, even though unchangeable, must be also supplied among other arguments
    //because otherwise the value won't adopt the rusqlite's specific 128_blob binary format
    pub gwei_min_resolution_params: Vec<i128>,
    pub secondary_order_param: &'static str,
}

pub struct AssemblerFeeder {
    pub main_where_clause: &'static str,
    pub where_clause_extension: &'static str,
    pub order_by_first_param: &'static str,
    pub order_by_second_param: &'static str,
    pub limit_clause: &'static str,
}

impl<N: Copy + Display> CustomQuery<N> {
    pub fn query<R, S, F1, F2>(
        self,
        conn: &dyn ConnectionWrapper,
        stm_assembler: F1,
        variant_top: TopStmConfig,
        variant_range: RangeStmConfig,
        value_fetcher: F2,
    ) -> Option<Vec<R>>
    where
        F1: Fn(AssemblerFeeder) -> String,
        F2: Fn(&Row) -> rusqlite::Result<R>,
        S: TryFrom<N>,
        i128: TryFrom<N>,
    {
        let (finalized_stm, params): (String, _) = match self {
            Self::TopRecords { count, ordered_by } => {
                let (order_by_first_param, order_by_second_param) =
                    Self::ordering(ordered_by, variant_top.age_param);
                let (limit_high_b, limit_low_b) = BigIntDivider::deconstruct(WEIS_OF_GWEI);
                (
                    stm_assembler(AssemblerFeeder {
                        main_where_clause: variant_top.gwei_min_resolution_clause,
                        where_clause_extension: "",
                        order_by_first_param,
                        order_by_second_param,
                        limit_clause: variant_top.limit_clause,
                    }),
                    vec![
                        Box::new(limit_high_b) as Box<dyn ToSql>,
                        Box::new(limit_low_b),
                        Box::new(count as i64),
                    ],
                )
            }
            Self::RangeQuery {
                min_age_s: min_age,
                max_age_s: max_age,
                min_amount_gwei: min_amount,
                max_amount_gwei: max_amount,
            } => {
                let now = to_time_t(SystemTime::now());
                let params: Vec<Box<dyn ToSql>> = vec![
                    Box::new(now - min_age as i64) as Box<dyn ToSql>,
                    Box::new(now - max_age as i64),
                ]
                .into_iter()
                .chain(Self::break_big_int_and_flat_nesting(
                    vec![min_amount, max_amount],
                    variant_range.gwei_min_resolution_params,
                ))
                .collect();
                (
                    stm_assembler(AssemblerFeeder {
                        main_where_clause: variant_range.where_clause,
                        where_clause_extension: variant_range.gwei_min_resolution_clause,
                        order_by_first_param: "balance desc",
                        order_by_second_param: variant_range.secondary_order_param,
                        limit_clause: "",
                    }),
                    params,
                )
            }
        };
        match conn
            .prepare(&finalized_stm)
            .expect("select statement is wrong")
            .query_map(
                params_from_iter(params.iter().map(|param| &*param)),
                value_fetcher,
            ) {
            Ok(accounts) => {
                let vectored = accounts.flatten().collect::<Vec<R>>();
                (!vectored.is_empty()).then_some(vectored)
            }
            Err(e) => panic!("database corrupt: {}", e),
        }
    }

    fn break_big_int_and_flat_nesting(
        two_limits: Vec<N>,
        one_or_two_limits: Vec<i128>,
    ) -> Vec<Box<dyn ToSql>>
    where
        i128: TryFrom<N>,
    {
        // .chain(
        //     variant_range
        //         .gwei_min_resolution_params
        //         .into_iter()
        //         .flat_map(|i128_limit| {
        //             let (high_bytes, low_bytes) = BigIntDivider::deconstruct(i128_limit);
        //             vec![Box::new(high_bytes), Box::new(low_bytes)]
        //         }),
        // )
        todo!()
        // Box::new(checked_conversion::<N, S>(min_amount)),
        // Box::new(checked_conversion::<N, S>(max_amount)),
    }

    fn ordering(
        ordering: TopRecordsOrdering,
        age_param: &'static str,
    ) -> (&'static str, &'static str) {
        match ordering {
            TopRecordsOrdering::Age => (age_param, "balance desc"),
            TopRecordsOrdering::Balance => ("balance desc", age_param),
        }
    }
}

pub fn remap_payable_accounts(accounts: Vec<PayableAccount>) -> Vec<UiPayableAccount> {
    accounts
        .into_iter()
        .map(|account| UiPayableAccount {
            wallet: account.wallet.to_string(),
            age_s: (to_time_t(SystemTime::now()) - to_time_t(account.last_paid_timestamp)) as u64,
            balance_gwei: match (account.balance_wei / (WEIS_OF_GWEI as u128)) as u64{
                x if x > 0 => x,
                _ => panic!("Broken code: PayableAccount with less than 1 Gwei passed through db query constrains; wallet: {}, balance: {}",account.wallet,account.balance_wei)
            },
            pending_payable_hash_opt: account
                .pending_payable_opt
                .map(|full_id| full_id.hash.to_string()),
        })
        .collect()
}

pub fn remap_receivable_accounts(accounts: Vec<ReceivableAccount>) -> Vec<UiReceivableAccount> {
    accounts
        .into_iter()
        .map(|account| UiReceivableAccount {
            wallet: account.wallet.to_string(),
            age_s: (to_time_t(SystemTime::now()) - to_time_t(account.last_received_timestamp)) as u64,
            balance_gwei: match (account.balance_wei / (WEIS_OF_GWEI as i128)) as i64{
            x if x != 0 => x,
            _ => panic!("Broken code: ReceivableAccount with balance between {} Gwei passed through db query constrains; wallet: {}, balance: {}",
                        if account.balance_wei.is_positive() {"1 and 0"}else{"-1 and 0"},
                        account.wallet,
                        account.balance_wei
            )
        },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::test_utils::make_wallet;
    use masq_lib::messages::TopRecordsOrdering::Balance;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags};
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "Failed to connect to database at \"nonexistent")]
    fn connection_panics_if_connection_cannot_be_made() {
        let subject = DaoFactoryReal::new(
            &PathBuf::from_str("nonexistent").unwrap(),
            false,
            MigratorConfig::test_default(),
        );

        let _ = subject.make_connection();
    }

    #[test]
    #[should_panic(
        expected = "database corrupt: Wrong number of parameters passed to query. Got 1, needed 0"
    )]
    fn erroneous_query_leads_to_panic() {
        let home_dir =
            ensure_node_home_directory_exists("dao_utils", "erroneous_query_leads_to_panic");
        let db_path = home_dir.join("test.db");
        let creation_conn = Connection::open(db_path.as_path()).unwrap();
        creation_conn
            .execute(
                "create table fruits (kind text primary key, price integer not null)",
                [],
            )
            .unwrap();
        let conn_read_only =
            Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let conn_wrapped = ConnectionWrapperReal::new(conn_read_only);
        let subject = CustomQuery::<u128>::TopRecords {
            count: 12,
            ordered_by: Balance,
        };

        let _ = subject.query::<_, i64, _, _>(
            &conn_wrapped,
            |_feeder: AssemblerFeeder| "select kind, price from fruits".to_string(),
            TopStmConfig {
                limit_clause: "",
                gwei_min_resolution_clause: "",
                age_param: "",
            },
            RangeStmConfig {
                where_clause: "",
                gwei_min_resolution_clause: "",
                gwei_min_resolution_params: vec![],
                secondary_order_param: "",
            },
            |_row| Ok(()),
        );
    }

    #[test]
    #[should_panic(
        expected = "Broken code: PayableAccount with less than 1 Gwei passed through db query constrains; \
         wallet: 0x0000000000000000000000000061633336363563, balance: 565122333"
    )]
    fn remap_payable_accounts_getting_record_below_one_gwei_means_broken_database_query() {
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("abc123"),
                balance_wei: 4_888_123_457,
                last_paid_timestamp: SystemTime::now(), //unimportant
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("ac3665c"),
                balance_wei: 565_122_333,
                last_paid_timestamp: SystemTime::now(), //unimportant
                pending_payable_opt: None,
            },
        ];
        remap_payable_accounts(accounts);
    }

    #[test]
    #[should_panic(
        expected = "Broken code: ReceivableAccount with balance between 1 and 0 Gwei passed through db query \
         constrains; wallet: 0x0000000000000000000000000061633336363563, balance: 300122333"
    )]
    fn remap_receivable_accounts_getting_record_between_one_and_zero_gwei_means_broken_database_query(
    ) {
        let accounts = vec![
            ReceivableAccount {
                wallet: make_wallet("ac45123"),
                balance_wei: 4_888_123_457,
                last_received_timestamp: SystemTime::now(), //unimportant
            },
            ReceivableAccount {
                wallet: make_wallet("ac3665c"),
                balance_wei: 300_122_333,
                last_received_timestamp: SystemTime::now(), //unimportant
            },
        ];
        remap_receivable_accounts(accounts);
    }

    #[test]
    #[should_panic(
        expected = "Broken code: ReceivableAccount with balance between -1 and 0 Gwei passed through db query \
         constrains; wallet: 0x0000000000000000000000000061633336363563, balance: -290122333"
    )]
    fn remap_receivable_accounts_getting_record_between_minus_one_and_zero_gwei_means_broken_database_query(
    ) {
        let accounts = vec![
            ReceivableAccount {
                wallet: make_wallet("ac45123"),
                balance_wei: -4_000_123_457,
                last_received_timestamp: SystemTime::now(), //unimportant
            },
            ReceivableAccount {
                wallet: make_wallet("ac3665c"),
                balance_wei: -290_122_333,
                last_received_timestamp: SystemTime::now(), //unimportant
            },
        ];
        remap_receivable_accounts(accounts);
    }
}