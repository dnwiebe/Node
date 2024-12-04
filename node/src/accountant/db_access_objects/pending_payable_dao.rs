// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::utils::{
    from_time_t, to_time_t, DaoFactoryReal, VigilantRusqliteFlatten,
};
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::{checked_conversion, comma_joined_stringifiable};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::HashAndAmount;
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use masq_lib::utils::ExpectValue;
use rusqlite::Row;
use std::collections::HashSet;
use std::fmt::Debug;
use std::str::FromStr;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Debug, PartialEq, Eq)]
pub enum PendingPayableDaoError {
    InsertionFailed(String),
    UpdateFailed(String),
    SignConversionError(u64),
    RecordCannotBeRead,
    RecordDeletion(String),
    ErrorMarkFailed(String),
}

#[derive(Debug)]
pub struct TransactionHashes {
    pub rowid_results: Vec<(u64, H256)>,
    pub no_rowid_results: Vec<H256>,
}

pub trait PendingPayableDao {
    // Note that the order of the returned results is not guaranteed
    fn fingerprints_rowids(&self, hashes: &[H256]) -> TransactionHashes;
    fn return_all_errorless_fingerprints(&self) -> Vec<PendingPayableFingerprint>;
    fn insert_new_fingerprints(
        &self,
        hashes_and_amounts: &[HashAndAmount],
        batch_wide_timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError>;
    fn delete_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError>;
    fn increment_scan_attempts(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError>;
    fn mark_failures(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError>;
}

impl PendingPayableDao for PendingPayableDaoReal<'_> {
    fn fingerprints_rowids(&self, hashes: &[H256]) -> TransactionHashes {
        //Vec<(Option<u64>, H256)> {
        fn hash_and_rowid_in_single_row(row: &Row) -> rusqlite::Result<(u64, H256)> {
            let hash_str: String = row.get(0).expectv("hash");
            let hash = H256::from_str(&hash_str[2..]).expect("hash inserted right turned wrong");
            let sqlite_signed_rowid: i64 = row.get(1).expectv("rowid");
            let rowid = u64::try_from(sqlite_signed_rowid).expect("SQlite goes from 1 to i64:MAX");
            Ok((rowid, hash))
        }

        let sql = format!(
            "select transaction_hash, rowid from pending_payable where transaction_hash in ({})",
            comma_joined_stringifiable(hashes, |hash| format!("'{:?}'", hash))
        );

        let all_found_records = self
            .conn
            .prepare(&sql)
            .expect("Internal error")
            .query_map([], hash_and_rowid_in_single_row)
            .expect("map query failed")
            .vigilant_flatten()
            .collect::<Vec<(u64, H256)>>();
        let hashes_of_found_records = all_found_records
            .iter()
            .map(|(_, hash)| *hash)
            .collect::<HashSet<H256>>();
        let hashes_of_missing_rowids = hashes
            .iter()
            .filter(|hash| !hashes_of_found_records.contains(hash))
            .cloned()
            .collect();

        TransactionHashes {
            rowid_results: all_found_records,
            no_rowid_results: hashes_of_missing_rowids,
        }
    }

    fn return_all_errorless_fingerprints(&self) -> Vec<PendingPayableFingerprint> {
        let mut stm = self
            .conn
            .prepare(
                "select rowid, transaction_hash, amount_high_b, amount_low_b, \
                 payable_timestamp, attempt from pending_payable where process_error is null",
            )
            .expect("Internal error");
        stm.query_map([], |row| {
            let rowid: u64 = Self::get_with_expect(row, 0);
            let transaction_hash: String = Self::get_with_expect(row, 1);
            let amount_high_bytes: i64 = Self::get_with_expect(row, 2);
            let amount_low_bytes: i64 = Self::get_with_expect(row, 3);
            let timestamp: i64 = Self::get_with_expect(row, 4);
            let attempt: u16 = Self::get_with_expect(row, 5);
            Ok(PendingPayableFingerprint {
                rowid,
                timestamp: from_time_t(timestamp),
                hash: H256::from_str(&transaction_hash[2..]).unwrap_or_else(|e| {
                    panic!(
                        "Invalid hash format (\"{}\": {:?}) - database corrupt",
                        transaction_hash, e
                    )
                }),
                attempt,
                amount: checked_conversion::<i128, u128>(BigIntDivider::reconstitute(
                    amount_high_bytes,
                    amount_low_bytes,
                )),
                process_error: None,
            })
        })
        .expect("rusqlite failure")
        .vigilant_flatten()
        .collect()
    }

    fn insert_new_fingerprints(
        &self,
        hashes_and_amounts: &[HashAndAmount],
        batch_wide_timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError> {
        fn values_clause_for_fingerprints_to_insert(
            hashes_and_amounts: &[HashAndAmount],
            batch_wide_timestamp: SystemTime,
        ) -> String {
            let time_t = to_time_t(batch_wide_timestamp);
            comma_joined_stringifiable(hashes_and_amounts, |hash_and_amount| {
                let amount_checked = checked_conversion::<u128, i128>(hash_and_amount.amount);
                let (high_bytes, low_bytes) = BigIntDivider::deconstruct(amount_checked);
                format!(
                    "('{:?}', {}, {}, {}, 1, null)",
                    hash_and_amount.hash, high_bytes, low_bytes, time_t
                )
            })
        }

        let insert_sql = format!(
            "insert into pending_payable (\
            transaction_hash, amount_high_b, amount_low_b, payable_timestamp, attempt, process_error\
            ) values {}",
            values_clause_for_fingerprints_to_insert(hashes_and_amounts, batch_wide_timestamp)
        );
        match self
            .conn
            .prepare(&insert_sql)
            .expect("Internal error")
            .execute([])
        {
            Ok(x) if x == hashes_and_amounts.len() => Ok(()),
            Ok(x) => panic!(
                "expected {} changed rows but got {}",
                hashes_and_amounts.len(),
                x
            ),
            Err(e) => Err(PendingPayableDaoError::InsertionFailed(e.to_string())),
        }
    }

    fn delete_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        let sql = format!(
            "delete from pending_payable where rowid in ({})",
            Self::serialize_ids(ids)
        );
        match self
            .conn
            .prepare(&sql)
            .expect("delete command wrong")
            .execute([])
        {
            Ok(x) if x == ids.len() => Ok(()),
            Ok(num) => panic!(
                "deleting fingerprint, expected {} rows to be changed, but the actual number is {}",
                ids.len(),
                num
            ),
            Err(e) => Err(PendingPayableDaoError::RecordDeletion(e.to_string())),
        }
    }

    fn increment_scan_attempts(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        let sql = format!(
            "update pending_payable set attempt = attempt + 1 where rowid in ({})",
            Self::serialize_ids(ids)
        );
        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(num) if num == ids.len() => Ok(()),
            Ok(num) => panic!(
                "Database corrupt: updating fingerprints: expected to update {} rows but did {}",
                ids.len(),
                num
            ),
            Err(e) => Err(PendingPayableDaoError::UpdateFailed(e.to_string())),
        }
    }

    fn mark_failures(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        let sql = format!(
            "update pending_payable set process_error = 'ERROR' where rowid in ({})",
            Self::serialize_ids(ids)
        );
        match self
            .conn
            .prepare(&sql)
            .expect("Internal error")
            .execute([]) {
            Ok(num) if num == ids.len() => Ok(()),
            Ok(num) =>
                panic!(
                    "Database corrupt: marking failure at fingerprints: expected to change {} rows but did {}",
                    ids.len(), num
                )
            ,
            Err(e) => Err(PendingPayableDaoError::ErrorMarkFailed(e.to_string())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPayable {
    pub recipient_wallet: Wallet,
    pub hash: H256,
}

impl PendingPayable {
    pub fn new(recipient_wallet: Wallet, hash: H256) -> Self {
        Self {
            recipient_wallet,
            hash,
        }
    }
}

#[derive(Debug)]
pub struct PendingPayableDaoReal<'a> {
    conn: Box<dyn ConnectionWrapper + 'a>,
}

impl<'a> PendingPayableDaoReal<'a> {
    pub fn new(conn: Box<dyn ConnectionWrapper + 'a>) -> Self {
        Self { conn }
    }

    fn get_with_expect<T: rusqlite::types::FromSql>(row: &Row, index: usize) -> T {
        row.get(index).expect("database is corrupt")
    }

    fn serialize_ids(ids: &[u64]) -> String {
        comma_joined_stringifiable(ids, |id| id.to_string())
    }
}

pub trait PendingPayableDaoFactory {
    fn make(&self) -> Box<dyn PendingPayableDao>;
}

impl PendingPayableDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn PendingPayableDao> {
        Box::new(PendingPayableDaoReal::new(self.make_connection()))
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::checked_conversion;
    use crate::accountant::db_access_objects::pending_payable_dao::{
        PendingPayableDao, PendingPayableDaoError, PendingPayableDaoReal,
    };
    use crate::accountant::db_access_objects::utils::from_time_t;
    use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::HashAndAmount;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::database::test_utils::ConnectionWrapperMock;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags};
    use std::str::FromStr;
    use std::time::SystemTime;
    use web3::types::H256;

    #[test]
    fn insert_new_fingerprints_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "insert_new_fingerprints_happy_path",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash_1 = make_tx_hash(4546);
        let amount_1 = 55556;
        let hash_2 = make_tx_hash(6789);
        let amount_2 = 44445;
        let batch_wide_timestamp = from_time_t(200_000_000);
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let hash_and_amount_1 = HashAndAmount {
            hash: hash_1,
            amount: amount_1,
        };
        let hash_and_amount_2 = HashAndAmount {
            hash: hash_2,
            amount: amount_2,
        };

        let _ = subject
            .insert_new_fingerprints(
                &[hash_and_amount_1, hash_and_amount_2],
                batch_wide_timestamp,
            )
            .unwrap();

        let records = subject.return_all_errorless_fingerprints();
        assert_eq!(
            records,
            vec![
                PendingPayableFingerprint {
                    rowid: 1,
                    timestamp: batch_wide_timestamp,
                    hash: hash_and_amount_1.hash,
                    attempt: 1,
                    amount: hash_and_amount_1.amount,
                    process_error: None
                },
                PendingPayableFingerprint {
                    rowid: 2,
                    timestamp: batch_wide_timestamp,
                    hash: hash_and_amount_2.hash,
                    attempt: 1,
                    amount: hash_and_amount_2.amount,
                    process_error: None
                }
            ]
        )
    }

    #[test]
    fn insert_new_fingerprints_sad_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "insert_new_fingerprints_sad_path",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let hash = make_tx_hash(45466);
        let amount = 55556;
        let timestamp = from_time_t(200_000_000);
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));
        let hash_and_amount = HashAndAmount { hash, amount };

        let result = subject.insert_new_fingerprints(&[hash_and_amount], timestamp);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::InsertionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(expected = "expected 1 changed rows but got 0")]
    fn insert_new_fingerprints_number_of_returned_rows_different_than_expected() {
        let setup_conn = Connection::open_in_memory().unwrap();
        // injecting a by-plan failing statement into the mocked connection in order to provoke
        // a reaction that would've been untestable directly on the table the act is closely coupled with
        let statement = {
            setup_conn
                .execute("create table example (id integer)", [])
                .unwrap();
            setup_conn.prepare("select id from example").unwrap()
        };
        let wrapped_conn = ConnectionWrapperMock::default().prepare_result(Ok(statement));
        let hash_1 = make_tx_hash(4546);
        let amount_1 = 55556;
        let batch_wide_timestamp = from_time_t(200_000_000);
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));
        let hash_and_amount = HashAndAmount {
            hash: hash_1,
            amount: amount_1,
        };

        let _ = subject.insert_new_fingerprints(&[hash_and_amount], batch_wide_timestamp);
    }

    #[test]
    fn fingerprints_rowids_when_records_reachable() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "fingerprints_rowids_when_records_reachable",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let timestamp = from_time_t(195_000_000);
        // use full range tx hashes because SqLite has tendencies to see the value as a hex and convert it to an integer,
        // then complain about its excessive size if supplied in unquoted strings
        let hash_1 =
            H256::from_str("b4bc263278d3a82a652a8d73a6bfd8ec0ba1a63923bbb4f38147fb8a943da26a")
                .unwrap();
        let hash_2 =
            H256::from_str("5a2909e7bb71943c82a94d9beb04e230351541fc14619ee8bb9b7372ea88ba39")
                .unwrap();
        let hash_and_amount_1 = HashAndAmount {
            hash: hash_1,
            amount: 4567,
        };
        let hash_and_amount_2 = HashAndAmount {
            hash: hash_2,
            amount: 6789,
        };
        let fingerprints_init_input = vec![hash_and_amount_1, hash_and_amount_2];
        {
            subject
                .insert_new_fingerprints(&fingerprints_init_input, timestamp)
                .unwrap();
        }

        let result = subject.fingerprints_rowids(&[hash_1, hash_2]);

        let first_expected_pair = &(1, hash_1);
        assert!(
            result.rowid_results.contains(first_expected_pair),
            "Returned rowid pairs should have contained {:?} but all it did is {:?}",
            first_expected_pair,
            result.rowid_results
        );
        let second_expected_pair = &(2, hash_2);
        assert!(
            result.rowid_results.contains(second_expected_pair),
            "Returned rowid pairs should have contained {:?} but all it did is {:?}",
            second_expected_pair,
            result.rowid_results
        );
        assert_eq!(result.rowid_results.len(), 2);
    }

    #[test]
    fn fingerprints_rowids_when_nonexistent_records() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "fingerprints_rowids_when_nonexistent_records",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let hash_1 = make_tx_hash(11119);
        let hash_2 = make_tx_hash(22229);
        let hash_3 = make_tx_hash(33339);
        let hash_4 = make_tx_hash(44449);
        // For more illustrative results, I use the official tooling but also generate one extra record before the chief one for
        // this test, and in the end, I delete the first one. It leaves a single record still in but with the rowid 2 instead of
        // just an ambiguous 1
        subject
            .insert_new_fingerprints(
                &[HashAndAmount {
                    hash: hash_2,
                    amount: 8901234,
                }],
                SystemTime::now(),
            )
            .unwrap();
        subject
            .insert_new_fingerprints(
                &[HashAndAmount {
                    hash: hash_3,
                    amount: 1234567,
                }],
                SystemTime::now(),
            )
            .unwrap();
        subject.delete_fingerprints(&[1]).unwrap();

        let result = subject.fingerprints_rowids(&[hash_1, hash_2, hash_3, hash_4]);

        assert_eq!(result.rowid_results, vec![(2, hash_3),]);
        assert_eq!(result.no_rowid_results, vec![hash_1, hash_2, hash_4]);
    }

    #[test]
    fn return_all_errorless_fingerprints_works_when_no_records_with_error_marks() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "return_all_errorless_fingerprints_works_when_no_records_with_error_marks",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let batch_wide_timestamp = from_time_t(195_000_000);
        let hash_1 = make_tx_hash(11119);
        let amount_1 = 787;
        let hash_2 = make_tx_hash(10000);
        let amount_2 = 333;
        let hash_and_amount_1 = HashAndAmount {
            hash: hash_1,
            amount: amount_1,
        };
        let hash_and_amount_2 = HashAndAmount {
            hash: hash_2,
            amount: amount_2,
        };

        {
            subject
                .insert_new_fingerprints(
                    &[hash_and_amount_1, hash_and_amount_2],
                    batch_wide_timestamp,
                )
                .unwrap();
        }

        let result = subject.return_all_errorless_fingerprints();

        assert_eq!(
            result,
            vec![
                PendingPayableFingerprint {
                    rowid: 1,
                    timestamp: batch_wide_timestamp,
                    hash: hash_1,
                    attempt: 1,
                    amount: amount_1,
                    process_error: None
                },
                PendingPayableFingerprint {
                    rowid: 2,
                    timestamp: batch_wide_timestamp,
                    hash: hash_2,
                    attempt: 1,
                    amount: amount_2,
                    process_error: None
                }
            ]
        )
    }

    #[test]
    fn return_all_errorless_fingerprints_works_when_some_records_with_error_marks() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "return_all_errorless_fingerprints_works_when_some_records_with_error_marks",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let timestamp = from_time_t(198_000_000);
        let hash = make_tx_hash(10000);
        let amount = 333;
        let hash_and_amount_1 = HashAndAmount {
            hash: make_tx_hash(11119),
            amount: 2000,
        };
        let hash_and_amount_2 = HashAndAmount { hash, amount };
        {
            subject
                .insert_new_fingerprints(&[hash_and_amount_1, hash_and_amount_2], timestamp)
                .unwrap();
            subject.mark_failures(&[1]).unwrap();
        }

        let result = subject.return_all_errorless_fingerprints();

        assert_eq!(
            result,
            vec![PendingPayableFingerprint {
                rowid: 2,
                timestamp,
                hash,
                attempt: 1,
                amount,
                process_error: None
            }]
        )
    }

    #[test]
    #[should_panic(
        expected = "Invalid hash format (\"silly_hash\": Invalid character 'l' at position 0) - database corrupt"
    )]
    fn return_all_errorless_fingerprints_panics_on_malformed_hash() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "return_all_errorless_fingerprints_panics_on_malformed_hash",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        {
            wrapped_conn
                .prepare("insert into pending_payable \
                (rowid, transaction_hash, amount_high_b, amount_low_b, payable_timestamp, attempt, process_error) \
                values (1, 'silly_hash', 4, 111, 10000000000, 1, null)")
                .unwrap()
                .execute([])
                .unwrap();
        }
        let subject = PendingPayableDaoReal::new(wrapped_conn);

        let _ = subject.return_all_errorless_fingerprints();
    }

    #[test]
    fn delete_fingerprints_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "delete_fingerprints_happy_path",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprints(
                    &[
                        HashAndAmount {
                            hash: make_tx_hash(1234),
                            amount: 1111,
                        },
                        HashAndAmount {
                            hash: make_tx_hash(2345),
                            amount: 5555,
                        },
                        HashAndAmount {
                            hash: make_tx_hash(3456),
                            amount: 2222,
                        },
                    ],
                    SystemTime::now(),
                )
                .unwrap();
        }

        let result = subject.delete_fingerprints(&[2, 3]);

        assert_eq!(result, Ok(()));
        let records_in_the_db = subject.return_all_errorless_fingerprints();
        let record_left_in = &records_in_the_db[0];
        assert_eq!(record_left_in.hash, make_tx_hash(1234));
        assert_eq!(record_left_in.rowid, 1);
        assert_eq!(records_in_the_db.len(), 1);
    }

    #[test]
    fn delete_fingerprints_sad_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "delete_fingerprints_sad_path",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let rowid = 45;
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.delete_fingerprints(&[rowid]);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::RecordDeletion(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(
        expected = "deleting fingerprint, expected 2 rows to be changed, but the actual number is 1"
    )]
    fn delete_fingerprints_changed_different_number_of_rows_than_expected() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "delete_fingerprints_changed_different_number_of_rows_than_expected",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let rowid_1 = 1;
        let rowid_2 = 2;
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprints(
                    &[HashAndAmount {
                        hash: make_tx_hash(666666),
                        amount: 5555,
                    }],
                    SystemTime::now(),
                )
                .unwrap();
        }

        let _ = subject.delete_fingerprints(&[rowid_1, rowid_2]);
    }

    #[test]
    fn increment_scan_attempts_works() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "increment_scan_attempts_works",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash_1 = make_tx_hash(345);
        let hash_2 = make_tx_hash(456);
        let hash_3 = make_tx_hash(567);
        let hash_and_amount_1 = HashAndAmount {
            hash: hash_1,
            amount: 1122,
        };
        let hash_and_amount_2 = HashAndAmount {
            hash: hash_2,
            amount: 2233,
        };
        let hash_and_amount_3 = HashAndAmount {
            hash: hash_3,
            amount: 3344,
        };
        let timestamp = from_time_t(190_000_000);
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprints(
                    &[hash_and_amount_1, hash_and_amount_2, hash_and_amount_3],
                    timestamp,
                )
                .unwrap();
        }

        let result = subject.increment_scan_attempts(&[2, 3]);

        assert_eq!(result, Ok(()));
        let mut all_records = subject.return_all_errorless_fingerprints();
        assert_eq!(all_records.len(), 3);
        let record_1 = all_records.remove(0);
        assert_eq!(record_1.hash, hash_1);
        assert_eq!(record_1.attempt, 1);
        let record_2 = all_records.remove(0);
        assert_eq!(record_2.hash, hash_2);
        assert_eq!(record_2.attempt, 2);
        let record_3 = all_records.remove(0);
        assert_eq!(record_3.hash, hash_3);
        assert_eq!(record_3.attempt, 2);
    }

    #[test]
    fn increment_scan_attempts_works_sad_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "increment_scan_attempts_works_sad_path",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.increment_scan_attempts(&[1]);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::UpdateFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(
        expected = "Database corrupt: updating fingerprints: expected to update 2 rows but did 0"
    )]
    fn increment_scan_attempts_panics_on_unexpected_row_change_count() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "increment_scan_attempts_panics_on_unexpected_row_change_count",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(conn);

        let _ = subject.increment_scan_attempts(&[1, 2]);
    }

    #[test]
    fn mark_failures_works() {
        let home_dir =
            ensure_node_home_directory_exists("pending_payable_dao", "mark_failures_works");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash_1 = make_tx_hash(555);
        let amount_1 = 1234;
        let hash_2 = make_tx_hash(666);
        let amount_2 = 2345;
        let hash_and_amount_1 = HashAndAmount {
            hash: hash_1,
            amount: amount_1,
        };
        let hash_and_amount_2 = HashAndAmount {
            hash: hash_2,
            amount: amount_2,
        };
        let timestamp = from_time_t(190_000_000);
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprints(&[hash_and_amount_1, hash_and_amount_2], timestamp)
                .unwrap();
        }

        let result = subject.mark_failures(&[2]);

        assert_eq!(result, Ok(()));
        let assert_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        let mut assert_stm = assert_conn
            .prepare("select rowid, transaction_hash, amount_high_b, amount_low_b, payable_timestamp, attempt, process_error from pending_payable")
            .unwrap();
        let found_fingerprints = assert_stm
            .query_map([], |row| {
                let rowid: u64 = row.get(0).unwrap();
                let transaction_hash: String = row.get(1).unwrap();
                let amount_high_b: i64 = row.get(2).unwrap();
                let amount_low_b: i64 = row.get(3).unwrap();
                let timestamp: i64 = row.get(4).unwrap();
                let attempt: u16 = row.get(5).unwrap();
                let process_error: Option<String> = row.get(6).unwrap();
                Ok(PendingPayableFingerprint {
                    rowid,
                    timestamp: from_time_t(timestamp),
                    hash: H256::from_str(&transaction_hash[2..]).unwrap(),
                    attempt,
                    amount: checked_conversion::<i128, u128>(BigIntDivider::reconstitute(
                        amount_high_b,
                        amount_low_b,
                    )),
                    process_error,
                })
            })
            .unwrap()
            .flatten()
            .collect::<Vec<PendingPayableFingerprint>>();
        assert_eq!(
            *found_fingerprints,
            vec![
                PendingPayableFingerprint {
                    rowid: 1,
                    timestamp,
                    hash: hash_1,
                    attempt: 1,
                    amount: amount_1,
                    process_error: None
                },
                PendingPayableFingerprint {
                    rowid: 2,
                    timestamp,
                    hash: hash_2,
                    attempt: 1,
                    amount: amount_2,
                    process_error: Some("ERROR".to_string())
                }
            ]
        )
    }

    #[test]
    fn mark_failures_sad_path() {
        let home_dir =
            ensure_node_home_directory_exists("pending_payable_dao", "mark_failures_sad_path");
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.mark_failures(&[1]);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::ErrorMarkFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(
        expected = "Database corrupt: marking failure at fingerprints: expected to change 2 rows but did 0"
    )]
    fn mark_failures_panics_on_wrong_row_change_count() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "mark_failures_panics_on_wrong_row_change_count",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(conn);

        let _ = subject.mark_failures(&[10, 20]);
    }
}
