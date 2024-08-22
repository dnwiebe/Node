use crate::bit_queue::BitQueue;
use crate::country_block_serde::CountryBlockSerializer;
use crate::country_block_stream::CountryBlock;
use std::io;

const COUNTRY_BLOCK_BIT_SIZE: usize = 64;
#[allow(unused_must_use)]
pub fn ip_country(
    _args: Vec<String>,
    stdin: &mut dyn io::Read,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> i32 {
    let mut serializer = CountryBlockSerializer::new();
    let mut csv_rdr = csv::Reader::from_reader(stdin);
    let mut errors = csv_rdr
        .records()
        .map(|string_record_result| match string_record_result {
            Ok(string_record) => CountryBlock::try_from(string_record),
            Err(e) => Err(format!("CSV format error: {:?}", e)),
        })
        .enumerate()
        .flat_map(|(idx, country_block_result)| match country_block_result {
            Ok(country_block) => {
                serializer.add(country_block);
                None
            }
            Err(e) => Some(format!("Line {}: {}", idx + 1, e)),
        })
        .collect::<Vec<String>>();
    let (ipv4_bit_queue, ipv6_bit_queue) = serializer.finish();
    if let Err(error) = generate_rust_code(ipv4_bit_queue, ipv6_bit_queue, stdout) {
        errors.push(format!("Error generating Rust code: {:?}", error))
    }
    if errors.is_empty() {
        0
    } else {
        let error_list = errors.join("\n");
        write!(
            stdout,
            r#"
            *** DO NOT USE THIS CODE ***
            It will produce incorrect results.
            The process that generated it found these errors:

{}

            Fix the errors and regenerate the code.
            *** DO NOT USE THIS CODE ***
"#,
            error_list
        );
        write!(stderr, "{}", error_list);
        1
    }
}

fn generate_rust_code(
    ipv4_bit_queue: BitQueue,
    ipv6_bit_queue: BitQueue,
    output: &mut dyn io::Write,
) -> Result<(), io::Error> {
    write!(output, "\n// GENERATED CODE: REGENERATE, DO NOT MODIFY!\n")?;
    //TODO add number of country blocks to each run and create getters to retrieve number of blocks
    generate_country_data("ipv4_country_data", ipv4_bit_queue, output)?;
    generate_country_data("ipv6_country_data", ipv6_bit_queue, output)?;
    Ok(())
}

fn generate_country_data(
    name: &str,
    mut bit_queue: BitQueue,
    output: &mut dyn io::Write,
) -> Result<(), io::Error> {
    let bit_queue_len = bit_queue.len();
    writeln!(output)?;
    writeln!(output, "pub fn {}() -> (Vec<u64>, usize) {{", name)?;
    writeln!(output, "    (")?;
    write!(output, "        vec![")?;
    let mut values_written = 0usize;
    while bit_queue.len() >= COUNTRY_BLOCK_BIT_SIZE {
        write_value(
            &mut bit_queue,
            COUNTRY_BLOCK_BIT_SIZE,
            &mut values_written,
            output,
        )?;
    }
    if !bit_queue.is_empty() {
        let bit_count = bit_queue.len();
        write_value(&mut bit_queue, bit_count, &mut values_written, output)?;
    }
    write!(output, "\n        ],\n")?;
    writeln!(output, "        {}", bit_queue_len)?;
    writeln!(output, "    )")?;
    writeln!(output, "}}")?;
    Ok(())
}

fn write_value(
    bit_queue: &mut BitQueue,
    bit_count: usize,
    values_written: &mut usize,
    output: &mut dyn io::Write,
) -> Result<(), io::Error> {
    if (*values_written & 0b11) == 0 {
        write!(output, "\n            ")?;
    } else {
        write!(output, " ")?;
    }
    let value = bit_queue
        .take_bits(bit_count)
        .expect("There should be bits left!");
    write!(output, "0x{:016X},", value)?;
    *values_written += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::min;
    use std::io;
    use std::io::BufRead;
    use std::io::Read;
    use std::io::Write;
    use std::io::{Error, ErrorKind};
    use std::sync::{Arc, Mutex};

    #[allow(unused)]
    pub struct StdStreams<'a> {
        pub stdin: &'a mut (dyn io::Read + Send),
        pub stdout: &'a mut (dyn io::Write + Send),
        pub stderr: &'a mut (dyn io::Write + Send),
    }

    pub trait Command<T> {
        fn go(&mut self, streams: &mut StdStreams<'_>, args: &[String]) -> T;
    }

    pub struct ByteArrayWriter {
        inner_arc: Arc<Mutex<ByteArrayWriterInner>>,
    }

    pub struct ByteArrayWriterInner {
        byte_array: Vec<u8>,
        next_error: Option<Error>,
    }

    impl Default for ByteArrayWriter {
        fn default() -> Self {
            ByteArrayWriter {
                inner_arc: Arc::new(Mutex::new(ByteArrayWriterInner {
                    byte_array: vec![],
                    next_error: None,
                })),
            }
        }
    }

    impl ByteArrayWriter {
        pub fn new() -> ByteArrayWriter {
            Self::default()
        }

        pub fn inner_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
            self.inner_arc.clone()
        }

        pub fn get_bytes(&self) -> Vec<u8> {
            self.inner_arc.lock().unwrap().byte_array.clone()
        }

        pub fn reject_next_write(&mut self, error: Error) {
            self.inner_arc().lock().unwrap().next_error = Some(error);
        }
    }

    impl Write for ByteArrayWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut inner = self.inner_arc.lock().unwrap();
            if let Some(next_error) = inner.next_error.take() {
                Err(next_error)
            } else {
                for byte in buf {
                    inner.byte_array.push(*byte)
                }
                Ok(buf.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub struct ByteArrayReader {
        byte_array: Vec<u8>,
        position: usize,
        next_error: Option<Error>,
    }

    impl ByteArrayReader {
        pub fn new(byte_array: &[u8]) -> ByteArrayReader {
            ByteArrayReader {
                byte_array: byte_array.to_vec(),
                position: 0,
                next_error: None,
            }
        }
    }

    impl Read for ByteArrayReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.next_error.take() {
                Some(error) => Err(error),
                None => {
                    let to_copy = min(buf.len(), self.byte_array.len() - self.position);
                    #[allow(clippy::needless_range_loop)]
                    for idx in 0..to_copy {
                        buf[idx] = self.byte_array[self.position + idx]
                    }
                    self.position += to_copy;
                    Ok(to_copy)
                }
            }
        }
    }

    impl BufRead for ByteArrayReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            match self.next_error.take() {
                Some(error) => Err(error),
                None => Ok(&self.byte_array[self.position..]),
            }
        }

        fn consume(&mut self, amt: usize) {
            let result = self.position + amt;
            self.position = if result < self.byte_array.len() {
                result
            } else {
                self.byte_array.len()
            }
        }
    }

    pub struct FakeStreamHolder {
        pub stdin: ByteArrayReader,
        pub stdout: ByteArrayWriter,
        pub stderr: ByteArrayWriter,
    }

    impl Default for FakeStreamHolder {
        fn default() -> Self {
            FakeStreamHolder {
                stdin: ByteArrayReader::new(&[0; 0]),
                stdout: ByteArrayWriter::new(),
                stderr: ByteArrayWriter::new(),
            }
        }
    }

    impl FakeStreamHolder {}

    static PROPER_TEST_DATA: &str = "0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.4.0,1.0.7.255,AU
1.0.8.0,1.0.15.255,CN
1.0.16.0,1.0.31.255,JP
1.0.32.0,1.0.63.255,CN
1.0.64.0,1.0.127.255,JP
1.0.128.0,1.0.255.255,TH
1.1.0.0,1.1.0.255,CN
0:0:0:0:0:0:0:0,0:255:255:255:0:0:0:0,ZZ
1:0:0:0:0:0:0:0,1:0:0:255:0:0:0:0,AU
1:0:1:0:0:0:0:0,1:0:3:255:0:0:0:0,CN
1:0:4:0:0:0:0:0,1:0:7:255:0:0:0:0,AU
1:0:8:0:0:0:0:0,1:0:15:255:0:0:0:0,CN
1:0:16:0:0:0:0:0,1:0:31:255:0:0:0:0,JP
1:0:32:0:0:0:0:0,1:0:63:255:0:0:0:0,CN
1:0:64:0:0:0:0:0,1:0:127:255:0:0:0:0,JP
1:0:128:0:0:0:0:0,1:0:255:255:0:0:0:0,TH
1:1:0:0:0:0:0:0,1:1:0:255:0:0:0:0,CN
";

    static BAD_TEST_DATA: &str = "0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.7.255,AU
1.0.8.0,1.0.15.255
1.0.16.0,1.0.31.255,JP,
BOOGA,BOOGA,BOOGA
1.0.63.255,1.0.32.0,CN
1.0.64.0,1.0.64.0,JP
1.0.128.0,1.0.255.255,TH
1.1.0.0,1.1.0.255,CN
0:0:0:0:0:0:0:0,0:255:255:255:0:0:0:0,ZZ
1:0:0:0:0:0:0:0,1:0:0:255:0:0:0:0,AU
1:0:1:0:0:0:0:0,1:0:3:255:0:0:0:0,CN
1:0:4:0:0:0:0:0,1:0:7:255:0:0:0:0,AU
1:0:8:0:0:0:0:0,1:0:15:255:0:0:0:0,CN
1:0:16:0:0:0:0:0,1:0:31:255:0:0:0:0,JP
BOOGA,BOOGA,BOOGA
1:0:32:0:0:0:0:0,1:0:63:255:0:0:0:0,CN
1:0:64:0:0:0:0:0,1:0:127:255:0:0:0:0,JP
1:0:128:0:0:0:0:0,1:0:255:255:0:0:0:0,TH
1:1:0:0:0:0:0:0,1:1:0:255:0:0:0:0,CN
";

    #[test]
    fn happy_path_test() {
        let mut stdin = ByteArrayReader::new(PROPER_TEST_DATA.as_bytes());
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();

        let result = ip_country(vec![], &mut stdin, &mut stdout, &mut stderr);

        assert_eq!(result, 0);
        let stdout_string = String::from_utf8(stdout.get_bytes()).unwrap();
        let stderr_string = String::from_utf8(stderr.get_bytes()).unwrap();
        assert_eq!(
            stdout_string,
            r#"
// GENERATED CODE: REGENERATE, DO NOT MODIFY!

pub fn ipv4_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x0080000300801003, 0x82201C0902E01807, 0x28102E208388840B, 0x605C0100AB76020E,
            0x0000000000000000,
        ],
        271
    )
}

pub fn ipv6_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x3000040000400007, 0x00C0001400020000, 0xA80954B000000700, 0x4000000F0255604A,
            0x0300004000040004, 0xE04AAC8380003800, 0x00018000A4000001, 0x2AB0003485C0001C,
            0x0600089000000781, 0xC001D20700007000, 0x00424000001E04AA, 0x15485C0001C00018,
            0xC90000007812AB00, 0x2388000700006002, 0x000001E04AAC00C5, 0xC0001C0001801924,
            0x0007812AB0063485, 0x0070000600C89000, 0x1E04AAC049D23880, 0xC000180942400000,
            0x12AB025549BA0001, 0x0040002580000078, 0xAC8B800038000300, 0x000000000001E04A,
        ],
        1513
    )
}
"#
            .to_string()
        );
        assert_eq!(stderr_string, "".to_string());
    }

    #[test]
    fn sad_path_test() {
        let mut stdin = ByteArrayReader::new(BAD_TEST_DATA.as_bytes());
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();

        let result = ip_country(vec![], &mut stdin, &mut stdout, &mut stderr);

        assert_eq!(result, 1);
        let stdout_string = String::from_utf8(stdout.get_bytes()).unwrap();
        let stderr_string = String::from_utf8(stderr.get_bytes()).unwrap();
        assert_eq!(
            stdout_string,
            r#"
// GENERATED CODE: REGENERATE, DO NOT MODIFY!

pub fn ipv4_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x0080000300801003, 0x5020000902E01807, 0xAB74038090000E1C, 0x00000000605C0100,
        ],
        239
    )
}

pub fn ipv6_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x3000040000400007, 0x00C0001400020000, 0xA80954B000000700, 0x4000000F0255604A,
            0x0300004000040004, 0xE04AAC8380003800, 0x00018000A4000001, 0x2AB0003485C0001C,
            0x0600089000000781, 0xC001D20700007000, 0x00424000001E04AA, 0x15485C0001C00018,
            0xC90000007812AB00, 0x2388000700006002, 0x000001E04AAC00C5, 0xC0001C0001801924,
            0x0007812AB0063485, 0x0070000600C89000, 0x1E04AAC049D23880, 0xC000180942400000,
            0x12AB025549BA0001, 0x0040002580000078, 0xAC8B800038000300, 0x000000000001E04A,
        ],
        1513
    )
}

            *** DO NOT USE THIS CODE ***
            It will produce incorrect results.
            The process that generated it found these errors:

Line 3: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 67, line: 4, record: 3 }), expected_len: 3, len: 2 })
Line 4: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 80, line: 5, record: 4 }), expected_len: 3, len: 2 })
Line 5: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 99, line: 6, record: 5 }), expected_len: 3, len: 4 })
Line 6: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'
Line 7: Ending address 1.0.32.0 is less than starting address 1.0.63.255
Line 17: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'

            Fix the errors and regenerate the code.
            *** DO NOT USE THIS CODE ***
"#
        );
        assert_eq!(stderr_string,
r#"Line 3: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 67, line: 4, record: 3 }), expected_len: 3, len: 2 })
Line 4: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 80, line: 5, record: 4 }), expected_len: 3, len: 2 })
Line 5: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 99, line: 6, record: 5 }), expected_len: 3, len: 4 })
Line 6: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'
Line 7: Ending address 1.0.32.0 is less than starting address 1.0.63.255
Line 17: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'"#
.to_string()
        );
    }

    #[test]
    fn write_error_test() {
        let mut subject = BitQueue::new();
        let output = &mut ByteArrayWriter::new();

        subject.add_bits(0b11011, 5);
        subject.add_bits(0b00111001110011100, 17);
        subject.add_bits(0b1, 1);

        output.reject_next_write(Error::new(ErrorKind::WriteZero, "Bad file Descriptor"));
        let result = generate_country_data("ipv4_country_data", subject, output).unwrap_err();
        assert_eq!(result.kind(), ErrorKind::WriteZero)
    }

    #[test]
    fn write_error_from_ip_country() {
        let stdin = &mut ByteArrayReader::new(PROPER_TEST_DATA.as_bytes());
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        stdout.reject_next_write(Error::new(ErrorKind::WriteZero, "Bad file Descriptor"));

        let result = ip_country(vec![], stdin, stdout, stderr);

        assert_eq!(result, 1);
        let stdout_string = String::from_utf8(stdout.get_bytes()).unwrap();
        let stderr_string = String::from_utf8(stderr.get_bytes()).unwrap();
        assert_eq!(stderr_string, "Error generating Rust code: Custom { kind: WriteZero, error: \"Bad file Descriptor\" }");
        assert_eq!(stdout_string, "\n            *** DO NOT USE THIS CODE ***\n            It will produce incorrect results.\n            The process that generated it found these errors:\n\nError generating Rust code: Custom { kind: WriteZero, error: \"Bad file Descriptor\" }\n\n            Fix the errors and regenerate the code.\n            *** DO NOT USE THIS CODE ***\n");
    }
}