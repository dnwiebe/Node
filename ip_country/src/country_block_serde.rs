use crate::bit_queue::BitQueue;
use crate::country_block_serde::semi_private_items::{
    DeserializerPrivate, Difference, IPIntoOctets, IPIntoSegments, PlusMinusOneIP,
};
use crate::country_block_stream::{Country, CountryBlock, IpRange};
use crate::country_finder;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::{BitOrAssign, Deref, ShlAssign};

/*

Compressed Data Format

Country IP-address data is stored in compressed format as a literal Vec<u64>. In order to
traverse it, it's fed into a BitQueue and then retrieved as a series of variably-sized bit strings.
IPv4 data is stored in one Vec<u64>, and IPv6 data is stored in a different one.

Conceptually, the compressed data format is a sequence of two-element records:

<IP address at beginning of country block>, <index of country in COUNTRIES list>
<IP address at beginning of country block>, <index of country in COUNTRIES list>
<IP address at beginning of country block>, <index of country in COUNTRIES list>
[...]

Each block is assumed to end at the address immediately before the one where the next block starts.
If the data contains no block starting at the lowest possible address (0.0.0.0 for IPv4,
0:0:0:0:0:0:0:0 for IPv6), the deserializer will invent one starting at that address, ending just
before the first address specified in the data, and having country index 0. The last block ends at
the maximum possible address: 255.255.255.255 for IPv4, FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
for IPv6.

The index of the country in the COUNTRIES list is specified as nine bits. At the time this code was
written, there were 250 countries in ISO3166, so we could have used eight bits; but 250 is close
enough to 256 that we added an extra bit for future-proofing.

The block-start IP addresses are specified in compressed fashion. Only the parts (octets for IPv4,
segments for IPv6) of the start address that are different from the corresponding segments of the
previous address are stored, like this:

<difference count minus one> <differences>

For IPv4, the difference-count-minus-one is stored as two bits, and for IPv6 it's stored as three
bits. Make sure you add 1 to the value before you use it. (The data is stored this way because
there can't be no changes (that'd imply a zero-length block), but it _is_ possible that every part
of the new start address is different, and that number wouldn't fit into the available bit field.)

Each difference is stored as two fields: an index and a value, like this:

<index> <value>

The index refers to the number of the address part that's different, and the value is the new
address part. For IPv4, the index is two bits long and the value is eight bits long. For IPv6,
the index is three bits long and the value is sixteen bits long.

Since every start address is composed of differences from the address before it, the very first
start address is compared against 255.255.255.254 for IPv4 and
FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFE for IPv6.

Examples

Here are two compressed IPv4 records, with whitespace for clarity:

11 00 00000001 01 00000010 10 00000011 11 00000100 011101101
00 00 11111111 011101011

This says:
1. There are 4 (3 + 1) differences. Octet 0 is 1; octet 1 is 2; octet 2 is 3; octet 3 is 4. The
country index is 237, which is "US" in the COUNTRIES list.
2. There is 1 (0 + 1) difference. Octet 0 changes to 255. The country index is 235, which is "GB"
in the COUNTRIES list.

It would deserialize into three CountryBlocks:
CountryBlock { // this block is implied by the fact that the first start address wasn't 0.0.0.0
    pub ip_range: IpRange::V4(Ipv4Addr.from_str("0.0.0.0").unwrap(), Ipv4Addr.from_str("1.2.3.3").unwrap()),
    pub country: Country::try_from("ZZ").unwrap(), // generated blocks are always for ZZ
}
CountryBlock {
    pub ip_range: IpRange::V4(Ipv4Addr.from_str("1.2.3.4").unwrap(), Ipv4Addr.from_str("255.2.3.3").unwrap()),
    pub country: Country::try_from("US").unwrap(),
}
CountryBlock {
    pub ip_range: IpRange::V4(Ipv4Addr.from_str("255.2.3.4").unwrap(), Ipv4Addr.from_str("255.255.255.255").unwrap()),
    pub country: Country::try_from("GB").unwrap(),
}

Here are two compressed IPv6 records, with whitespace for clarity:

111
    000 0000000000000001
    001 0000000000000010
    010 0000000000000011
    011 0000000000000100
    100 0000000000000000
    101 0000000000000000
    110 0000000000000000
    111 0000000000000000
    011101101
000
    000 0000000011111111
    011101011

This says:
1. There are 8 (7 + 1) differences. Segment 0 is 1; segment 1 is 2; segment 2 is 3; segment 3 is 4;
and the other four segments are all 0. The country index is 237, which is "US" in the COUNTRIES
list.
2. There is 1 (0 + 1) difference. Segment 0 changes to 255. The country index is 235, which is "GB"
in the COUNTRIES list.

It would deserialize into three CountryBlocks:
CountryBlock { // this block is implied by the fact that the first start address wasn't 0.0.0.0
    pub ip_range: IpRange::V6(Ipv6Addr.from_str("0:0:0:0:0:0:0:0").unwrap(), Ipv6Addr.from_str("1:2:3:3:FFFF:FFFF:FFFF:FFFF").unwrap()),
    pub country: Country::try_from("ZZ").unwrap(), // generated blocks are always for ZZ
}
CountryBlock {
    pub ip_range: IpRange::V6(Ipv6Addr.from_str("1:2:3:4:0:0:0:0").unwrap(), Ipv6Addr.from_str("FF:2:3:3:FFFF:FFFF:FFFF:FFFF").unwrap()),
    pub country: Country::try_from("US").unwrap(),
}
CountryBlock {
    pub ip_range: IpRange::V6(Ipv6Addr.from_str("FF:2:3:4:0:0:0:0").unwrap(), Ipv6Addr.from_str("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF").unwrap()),
    pub country: Country::try_from("GB").unwrap(),
}

 */

pub struct CountryBlockSerializer {
    ipv4: VersionedIPSerializer<Ipv4Addr, u8, 4>,
    ipv6: VersionedIPSerializer<Ipv6Addr, u16, 8>,
}

impl CountryBlockSerializer {
    pub fn new() -> Self {
        Self {
            ipv4: VersionedIPSerializer::new(
                Ipv4Addr::new(0xFF, 0xFF, 0xFF, 0xFE),
                Ipv4Addr::new(0xFF, 0xFF, 0xFF, 0xFF),
            ),
            ipv6: VersionedIPSerializer::new(
                Ipv6Addr::new(
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE,
                ),
                Ipv6Addr::new(
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ),
            ),
        }
    }

    pub fn add(&mut self, country_block: CountryBlock) {
        match country_block.ip_range {
            IpRange::V4(start, end) => self.ipv4.add_ip(start, end, country_block.country.index),
            IpRange::V6(start, end) => self.ipv6.add_ip(start, end, country_block.country.index),
        }
    }

    pub fn finish(mut self) -> (BitQueue, BitQueue) {
        let last_ipv4 = Ipv4Addr::new(0xFF, 0xFF, 0xFF, 0xFF);
        let last_ipv6 = Ipv6Addr::new(
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        );
        if self.ipv4.prev_end.ip != last_ipv4 {
            self.ipv4
                .add_ip(Ipv4Addr::plus_one_ip(self.ipv4.prev_end.ip), last_ipv4, 0);
        }
        if self.ipv6.prev_end.ip != last_ipv6 {
            self.ipv6
                .add_ip(Ipv6Addr::plus_one_ip(self.ipv6.prev_end.ip), last_ipv6, 0);
        }
        (self.ipv4.bit_queue, self.ipv6.bit_queue)
    }
}

struct VersionedIPSerializer<IPType, SegmentNumRep, const SegmentsCount: usize> {
    prev_start: VersionedIP<IPType, SegmentNumRep, SegmentsCount>,
    prev_end: VersionedIP<IPType, SegmentNumRep, SegmentsCount>,
    bit_queue: BitQueue,
}

trait Serializer<IPType> {
    fn add_ip(&mut self, start: IPType, end: IPType, country_index: usize);
}

impl Serializer<Ipv4Addr> for VersionedIPSerializer<Ipv4Addr, u8, 4> {
    fn add_ip(&mut self, start: Ipv4Addr, end: Ipv4Addr, country_index: usize) {
        self.add_ip_generic(start, end, country_index, 2, 2, 8)
    }
}

impl Serializer<Ipv6Addr> for VersionedIPSerializer<Ipv6Addr, u16, 8> {
    fn add_ip(&mut self, start: Ipv6Addr, end: Ipv6Addr, country_index: usize) {
        self.add_ip_generic(start, end, country_index, 3, 3, 16)
    }
}

impl<IPType, SegmentNumRep, const SegmentsCount: usize>
    VersionedIPSerializer<IPType, SegmentNumRep, SegmentsCount>
where
    IPType: PlusMinusOneIP + IPIntoSegments<SegmentNumRep, SegmentsCount> + Copy + PartialEq,
    SegmentNumRep: PartialEq,
    u64: From<SegmentNumRep>,
{
    fn add_ip_generic(
        &mut self,
        start: IPType,
        end: IPType,
        country_index: usize,
        difference_count_bit_count: usize,
        index_bit_count: usize,
        segment_bit_count: usize,
    ) {
        let expected_start = IPType::plus_one_ip(self.prev_end.ip);
        if start != expected_start {
            self.add_ip_generic(
                expected_start,
                IPType::minus_one_ip(start),
                0,
                difference_count_bit_count,
                index_bit_count,
                segment_bit_count,
            )
        }
        let differences = Self::ips_into_differences(self.prev_start.ip, start);
        let difference_count_minus_one = (differences.len() - 1) as u64;
        self.bit_queue
            .add_bits(difference_count_minus_one, difference_count_bit_count);
        differences.into_iter().for_each(|difference| {
            self.bit_queue
                .add_bits(difference.index as u64, index_bit_count);
            self.bit_queue.add_bits(difference.value, segment_bit_count);
        });
        self.bit_queue.add_bits(country_index as u64, 9);
        self.prev_start.ip = start;
        self.prev_end.ip = end;
    }
}

impl<IPType, SegmentNumRep, const SegmentsCount: usize>
    VersionedIPSerializer<IPType, SegmentNumRep, SegmentsCount>
where
    IPType: IPIntoSegments<SegmentNumRep, SegmentsCount>,
    SegmentNumRep: PartialEq,
    u64: From<SegmentNumRep>,
{
    fn new(
        prev_start: IPType,
        prev_end: IPType,
    ) -> VersionedIPSerializer<IPType, SegmentNumRep, SegmentsCount> {
        let prev_start = VersionedIP::new(prev_start);
        let prev_end = VersionedIP::new(prev_end);
        let bit_queue = BitQueue::new();
        Self {
            prev_start,
            prev_end,
            bit_queue,
        }
    }

    fn ips_into_differences(from: IPType, to: IPType) -> Vec<Difference> {
        let pairs = from.segments().into_iter().zip(to.segments().into_iter());
        pairs
            .enumerate()
            .flat_map(
                |(index, (from_segment, to_segment)): (_, (SegmentNumRep, SegmentNumRep))| {
                    if to_segment == from_segment {
                        None
                    } else {
                        Some(Difference {
                            index,
                            value: u64::from(to_segment),
                        })
                    }
                },
            )
            .collect()
    }
}

// Rust forces public visibility on traits that come to be used for type boundaries in any public
// interface (as in structs). This is how we can meet these requirements while those implementations
// of these traits will be ineffective from farther than this file. It works for prevention of
// namespace pollution in this kind of trait to be implemented on massively common types such as
// Ipv4Addr or Ipv6Addr
mod semi_private_items {
    use crate::bit_queue::BitQueue;

    pub trait IPIntoSegments<BitsPerSegment, const SegmentsCount: usize> {
        fn segments(&self) -> [BitsPerSegment; SegmentsCount];
    }

    pub trait IPIntoOctets<const OctetsCount: usize> {
        fn octets(&self) -> [u8; OctetsCount];
    }

    pub trait PlusMinusOneIP {
        fn plus_one_ip(ip: Self) -> Self;
        fn minus_one_ip(ip: Self) -> Self;
    }

    pub trait DeserializerPrivate<IPType> {
        fn max_ip_value() -> IPType;
        fn read_difference_count(bit_queue: &mut BitQueue) -> Option<usize>;
        fn read_differences(bit_queue: &mut BitQueue, difference_count: usize) -> Vec<Difference>;
    }

    pub struct Difference {
        pub index: usize,
        pub value: u64,
    }
}

impl IPIntoSegments<u8, 4> for Ipv4Addr {
    fn segments(&self) -> [u8; 4] {
        self.octets()
    }
}

impl IPIntoSegments<u16, 8> for Ipv6Addr {
    fn segments(&self) -> [u16; 8] {
        self.segments()
    }
}

impl IPIntoOctets<4> for Ipv4Addr {
    fn octets(&self) -> [u8; 4] {
        self.segments()
    }
}

impl IPIntoOctets<16> for Ipv6Addr {
    fn octets(&self) -> [u8; 16] {
        self.octets()
    }
}

impl PlusMinusOneIP for Ipv4Addr {
    fn plus_one_ip(ip: Self) -> Self {
        let old_data: u32 = integer_from_ip_generic(ip);
        let new_data = old_data.overflowing_add(1).0;
        Ipv4Addr::from(new_data)
    }
    fn minus_one_ip(ip: Self) -> Self {
        let old_data: u32 = integer_from_ip_generic(ip);
        let new_data = old_data.overflowing_sub(1).0;
        Ipv4Addr::from(new_data)
    }
}

impl PlusMinusOneIP for Ipv6Addr {
    fn plus_one_ip(ip: Self) -> Self {
        let old_data: u128 = integer_from_ip_generic(ip);
        let new_data = old_data.overflowing_add(1).0;
        Ipv6Addr::from(new_data)
    }

    fn minus_one_ip(ip: Self) -> Self {
        let old_data: u128 = integer_from_ip_generic(ip);
        let new_data = old_data.overflowing_sub(1).0;
        Ipv6Addr::from(new_data)
    }
}

fn integer_from_ip_generic<IPType, UnsignedInt, const OctetsCount: usize>(ip: IPType) -> UnsignedInt
where
    IPType: IPIntoOctets<OctetsCount>,
    UnsignedInt: From<u8> + BitOrAssign + ShlAssign,
{
    let segments = ip.octets();
    let mut bit_data = UnsignedInt::from(0u8);
    segments.into_iter().for_each(|octet| {
        bit_data <<= UnsignedInt::from(8u8);
        bit_data |= UnsignedInt::from(octet);
    });
    bit_data
}

#[derive(Debug)]
pub struct CountryBlockDeserializer<IPType, SegmentNumRep, const SegmentsCount: usize> {
    prev_record: StreamRecord<IPType, SegmentNumRep, SegmentsCount>,
    bit_queue: BitQueue,
    empty: bool,
}

pub trait DeserializerPublic {
    fn new(country_data: (Vec<u64>, usize)) -> Self;
    fn next(&mut self) -> Option<CountryBlock>;
}

impl DeserializerPublic for CountryBlockDeserializer<Ipv4Addr, u8, 4> {
    fn new(country_data: (Vec<u64>, usize)) -> Self {
        Self::new_generic(country_data, Ipv4Addr::new(0xFF, 0xFF, 0xFF, 0xFE))
    }

    fn next(&mut self) -> Option<CountryBlock> {
        self.next_generic()
    }
}

impl DeserializerPublic for CountryBlockDeserializer<Ipv6Addr, u16, 8> {
    fn new(country_data: (Vec<u64>, usize)) -> Self {
        Self::new_generic(
            country_data,
            Ipv6Addr::new(
                0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE,
            ),
        )
    }

    fn next(&mut self) -> Option<CountryBlock> {
        self.next_generic()
    }
}

impl DeserializerPrivate<Ipv4Addr> for CountryBlockDeserializer<Ipv4Addr, u8, 4> {
    fn max_ip_value() -> Ipv4Addr {
        Ipv4Addr::new(0xFF, 0xFF, 0xFF, 0xFF)
    }

    fn read_difference_count(bit_queue: &mut BitQueue) -> Option<usize> {
        Some((bit_queue.take_bits(2)? + 1) as usize)
    }

    fn read_differences(bit_queue: &mut BitQueue, difference_count: usize) -> Vec<Difference> {
        Self::read_differences_generic(bit_queue, difference_count, 2, 8)
    }
}

impl DeserializerPrivate<Ipv6Addr> for CountryBlockDeserializer<Ipv6Addr, u16, 8> {
    fn max_ip_value() -> Ipv6Addr {
        Ipv6Addr::new(
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        )
    }

    fn read_difference_count(bit_queue: &mut BitQueue) -> Option<usize> {
        Some((bit_queue.take_bits(3)? + 1) as usize)
    }

    fn read_differences(bit_queue: &mut BitQueue, difference_count: usize) -> Vec<Difference> {
        Self::read_differences_generic(bit_queue, difference_count, 3, 16)
    }
}

impl<IPType, SegmentNumRep, const SegmentsCount: usize>
    CountryBlockDeserializer<IPType, SegmentNumRep, SegmentsCount>
where
    Self: DeserializerPrivate<IPType>,
    IPType: IPIntoSegments<SegmentNumRep, SegmentsCount>
        + PlusMinusOneIP
        + From<[SegmentNumRep; SegmentsCount]>
        + Copy
        + Debug,
    SegmentNumRep: TryFrom<u64>,
    <SegmentNumRep as TryFrom<u64>>::Error: Debug,
    IpRange: From<(IPType, IPType)>,
{
    fn new_generic(
        country_data: (Vec<u64>, usize),
        previous_start: IPType,
    ) -> CountryBlockDeserializer<IPType, SegmentNumRep, SegmentsCount> {
        let mut bit_queue = bit_queue_from_country_data(country_data);
        let prev_record =
            CountryBlockDeserializer::<IPType, SegmentNumRep, SegmentsCount>::get_record_generic(
                &mut bit_queue,
                previous_start,
            )
            .expect("Empty BitQueue");
        Self {
            prev_record,
            bit_queue,
            empty: false,
        }
    }

    fn get_record_generic(
        bit_queue: &mut BitQueue,
        prev_start: IPType,
    ) -> Option<StreamRecord<IPType, SegmentNumRep, SegmentsCount>> {
        let segments: [SegmentNumRep; SegmentsCount] = prev_start.segments();
        let difference_count = Self::read_difference_count(bit_queue)?;
        let differences = Self::read_differences(bit_queue, difference_count);
        if differences.len() < difference_count {
            return None;
        }
        let country_idx = bit_queue.take_bits(9)? as usize;
        Some(StreamRecord::<IPType, SegmentNumRep, SegmentsCount>::new(
            differences,
            segments,
            country_idx,
        ))
    }

    fn next_generic(&mut self) -> Option<CountryBlock> {
        if self.empty {
            return None;
        }
        let next_record_opt =
            Self::get_record_generic(&mut self.bit_queue, self.prev_record.start.ip);
        match next_record_opt {
            Some(next_record) => {
                let prev_block = CountryBlock {
                    ip_range: IpRange::from((
                        self.prev_record.start.ip,
                        IPType::minus_one_ip(next_record.start.ip),
                    )),
                    country: Country::from(self.prev_record.country_idx),
                };
                self.prev_record = next_record;
                Some(prev_block)
            }
            None => {
                self.empty = true;
                Some(CountryBlock {
                    ip_range: IpRange::from((self.prev_record.start.ip, Self::max_ip_value())),
                    country: Country::from(self.prev_record.country_idx),
                })
            }
        }
    }

    fn read_differences_generic(
        bit_queue: &mut BitQueue,
        difference_count: usize,
        index_bit_count: usize,
        value_bit_count: usize,
    ) -> Vec<Difference> {
        (0..difference_count)
            .map(|_| {
                Some(Difference {
                    index: bit_queue.take_bits(index_bit_count)? as usize,
                    value: bit_queue.take_bits(value_bit_count)?,
                })
            })
            .flatten()
            .collect()
    }
}

struct VersionedIP<IPType, SegmentNumRep, const SegmentsCount: usize> {
    ip: IPType,
    segment_num_rep: PhantomData<SegmentNumRep>,
}

impl<IPType, SegmentNumRep, const SegmentsCount: usize>
    VersionedIP<IPType, SegmentNumRep, SegmentsCount>
{
    fn new(ip: IPType) -> VersionedIP<IPType, SegmentNumRep, SegmentsCount> {
        let segment_num_rep = Default::default();
        Self {
            ip,
            segment_num_rep,
        }
    }
}

impl<IPType, SegmentNumRep, const SegmentsCount: usize> Debug
    for VersionedIP<IPType, SegmentNumRep, SegmentsCount>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!("Vojta, this is for you: use the `write!()` macro and make this custom debug impl...it should probably print only the field with the ip and its value")
    }
}

#[derive(Debug)]
struct StreamRecord<IPType, SegmentNumRep, const SegmentsCount: usize> {
    start: VersionedIP<IPType, SegmentNumRep, SegmentsCount>,
    country_idx: usize,
}

impl<IPType, SegmentNumRep, const SegmentsCount: usize>
    StreamRecord<IPType, SegmentNumRep, SegmentsCount>
where
    IPType: From<[SegmentNumRep; SegmentsCount]>,
    SegmentNumRep: TryFrom<u64>,
    <SegmentNumRep>::Error: Debug,
{
    fn new(
        differences: Vec<Difference>,
        mut segments: [SegmentNumRep; SegmentsCount],
        country_idx: usize,
    ) -> StreamRecord<IPType, SegmentNumRep, SegmentsCount> {
        differences.into_iter().for_each(|d| {
            segments[d.index] = SegmentNumRep::try_from(d.value)
                .expect("Difference noted in a bigger number than which the IP segment can contain")
        });
        Self {
            start: VersionedIP::new(IPType::from(segments)),
            country_idx,
        }
    }
}

impl From<(Ipv4Addr, Ipv4Addr)> for IpRange {
    fn from((start, end): (Ipv4Addr, Ipv4Addr)) -> Self {
        IpRange::V4(start, end)
    }
}

impl From<(Ipv6Addr, Ipv6Addr)> for IpRange {
    fn from((start, end): (Ipv6Addr, Ipv6Addr)) -> Self {
        IpRange::V6(start, end)
    }
}

fn bit_queue_from_country_data(country_data_pair: (Vec<u64>, usize)) -> BitQueue {
    let (mut country_data, mut bit_count) = country_data_pair;
    let mut bit_queue = BitQueue::new();
    while bit_count >= 64 {
        bit_queue.add_bits(country_data.remove(0), 64);
        bit_count -= 64;
    }
    if bit_count > 0 {
        bit_queue.add_bits(country_data.remove(0), bit_count);
    }
    bit_queue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::country_block_stream::{Country, IpRange};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn ipv4_country_blocks() -> Vec<CountryBlock> {
        vec![
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("1.2.3.4").unwrap(),
                    Ipv4Addr::from_str("1.2.3.5").unwrap(),
                ),
                country: Country::try_from("AS").unwrap().clone(),
            },
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("1.2.3.6").unwrap(),
                    Ipv4Addr::from_str("6.7.8.9").unwrap(),
                ),
                country: Country::try_from("AD").unwrap().clone(),
            },
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("10.11.12.13").unwrap(),
                    Ipv4Addr::from_str("11.11.12.13").unwrap(),
                ),
                country: Country::try_from("AO").unwrap().clone(),
            },
        ]
    }

    fn ipv6_country_blocks() -> Vec<CountryBlock> {
        vec![
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("1:2:3:4:5:6:7:8").unwrap(),
                    Ipv6Addr::from_str("1:2:3:4:5:6:7:9").unwrap(),
                ),
                country: Country::try_from("AS").unwrap().clone(),
            },
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("1:2:3:4:5:6:7:A").unwrap(),
                    Ipv6Addr::from_str("B:C:D:E:F:10:11:12").unwrap(),
                ),
                country: Country::try_from("AD").unwrap().clone(),
            },
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("13:14:15:16:17:18:19:1A").unwrap(),
                    Ipv6Addr::from_str("14:14:15:16:17:18:19:1A").unwrap(),
                ),
                country: Country::try_from("AO").unwrap().clone(),
            },
        ]
    }

    #[test]
    fn add_works_for_ipv4() {
        let mut country_blocks = ipv4_country_blocks();
        let mut subject = CountryBlockSerializer::new();

        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));

        let (mut bit_queue, _) = subject.finish();
        {
            let (
                difference_count_minus_one,
                index1,
                value1,
                index2,
                value2,
                index3,
                value3,
                index4,
                value4,
                country_index,
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 3);
            assert_eq!((index1, value1), (0, 0));
            assert_eq!((index2, value2), (1, 0));
            assert_eq!((index3, value3), (2, 0));
            assert_eq!((index4, value4), (3, 0));
            assert_eq!(country_index, 0) // sentinel
        }
        {
            let (
                difference_count_minus_one,
                index1,
                value1,
                index2,
                value2,
                index3,
                value3,
                index4,
                value4,
                country_index,
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 3);
            assert_eq!((index1, value1), (0, 1));
            assert_eq!((index2, value2), (1, 2));
            assert_eq!((index3, value3), (2, 3));
            assert_eq!((index4, value4), (3, 4));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "AS".to_string()
            )
        }
        {
            let (difference_count_minus_one, index1, value1, country_index) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 0);
            assert_eq!((index1, value1), (3, 6));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "AD".to_string()
            )
        }
        {
            let (
                difference_count_minus_one,
                index1,
                value1,
                index2,
                value2,
                index3,
                value3,
                index4,
                value4,
                country_index,
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 3);
            assert_eq!((index1, value1), (0, 6));
            assert_eq!((index2, value2), (1, 7));
            assert_eq!((index3, value3), (2, 8));
            assert_eq!((index4, value4), (3, 10));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "ZZ".to_string()
            )
        }
        {
            let (
                difference_count_minus_one,
                index1,
                value1,
                index2,
                value2,
                index3,
                value3,
                index4,
                value4,
                country_index,
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 3);
            assert_eq!((index1, value1), (0, 10));
            assert_eq!((index2, value2), (1, 11));
            assert_eq!((index3, value3), (2, 12));
            assert_eq!((index4, value4), (3, 13));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "AO".to_string()
            )
        }
        {
            let (difference_count_minus_one, index1, value1, index2, value2, country_index) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 1);
            assert_eq!((index1, value1), (0, 11));
            assert_eq!((index2, value2), (3, 14));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "ZZ".to_string()
            )
        }
        assert_eq!(bit_queue.take_bits(1), None);
    }

    #[test]
    fn next_works_for_ipv4() {
        let mut serializer = CountryBlockSerializer::new();
        ipv4_country_blocks()
            .into_iter()
            .for_each(|country_block| serializer.add(country_block));
        let mut bit_queue = serializer.finish().0;
        let bit_queue_len = bit_queue.len();
        let mut bit_data: Vec<u64> = vec![];
        while bit_queue.len() >= 64 {
            let data = bit_queue.take_bits(64).unwrap();
            bit_data.push(data);
        }
        let remaining_bit_count = bit_queue.len();
        let data = bit_queue.take_bits(remaining_bit_count).unwrap();
        bit_data.push(data);
        let mut subject =
            CountryBlockDeserializer::<Ipv4Addr, u8, 4>::new((bit_data, bit_queue_len));

        let country_block1 = subject.next().unwrap();
        let country_block2 = subject.next().unwrap();
        let country_block3 = subject.next().unwrap();
        let country_block4 = subject.next().unwrap();
        let country_block5 = subject.next().unwrap();
        let country_block6 = subject.next().unwrap();
        let result = subject.next();

        let original_country_blocks = ipv4_country_blocks();
        assert_eq!(
            country_block1,
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    Ipv4Addr::from_str("1.2.3.3").unwrap()
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(country_block2, original_country_blocks[0]);
        assert_eq!(country_block3, original_country_blocks[1]);
        assert_eq!(
            country_block4,
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("6.7.8.10").unwrap(),
                    Ipv4Addr::from_str("10.11.12.12").unwrap(),
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(country_block5, original_country_blocks[2]);
        assert_eq!(
            country_block6,
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("11.11.12.14").unwrap(),
                    Ipv4Addr::from_str("255.255.255.255").unwrap(),
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(result, None);
    }

    #[test]
    fn finish_does_not_touch_complete_ipv4_list() {
        let mut country_blocks = ipv4_country_blocks();
        let mut subject = CountryBlockSerializer::new();
        subject.add(CountryBlock {
            ip_range: IpRange::V4(
                Ipv4Addr::from_str("0.0.0.0").unwrap(),
                Ipv4Addr::from_str("1.2.3.3").unwrap(),
            ),
            country: Country::try_from("Sk").unwrap().clone(),
        });
        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));
        subject.add(CountryBlock {
            ip_range: IpRange::V4(
                Ipv4Addr::from_str("11.11.12.14").unwrap(),
                Ipv4Addr::from_str("255.255.255.255").unwrap(),
            ),
            country: Country::try_from("CZ").unwrap().clone(),
        });
        let mut bitqueue = subject.finish().0;
        let len = bitqueue.len();
        let mut vec_64 = vec![];
        while bitqueue.len() >= 64 {
            let data = bitqueue.take_bits(64).unwrap();
            vec_64.push(data);
        }
        let remaining_bit_count = bitqueue.len();
        let data = bitqueue.take_bits(remaining_bit_count).unwrap();
        vec_64.push(data);

        let mut deserializer = CountryBlockDeserializer::<Ipv4Addr, u8, 4>::new((vec_64, len));

        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "SK");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "AS");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "AD");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "ZZ");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "AO");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "CZ");
        let result = deserializer.next();
        assert_eq!(result, None);
    }

    #[test]
    fn add_works_for_ipv6() {
        let mut country_blocks = ipv6_country_blocks();
        let mut subject = CountryBlockSerializer::new();

        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));

        let (_, mut bit_queue) = subject.finish();
        {
            let (
                difference_count_minus_one,
                index1,
                value1,
                index2,
                value2,
                index3,
                value3,
                index4,
                value4,
                index5,
                value5,
                index6,
                value6,
                index7,
                value7,
                index8,
                value8,
                country_index,
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 7);
            assert_eq!((index1, value1), (0, 0));
            assert_eq!((index2, value2), (1, 0));
            assert_eq!((index3, value3), (2, 0));
            assert_eq!((index4, value4), (3, 0));
            assert_eq!((index5, value5), (4, 0));
            assert_eq!((index6, value6), (5, 0));
            assert_eq!((index7, value7), (6, 0));
            assert_eq!((index8, value8), (7, 0));
            assert_eq!(country_index, 0) // sentinel
        }
        {
            let (
                difference_count_minus_one,
                index1,
                value1,
                index2,
                value2,
                index3,
                value3,
                index4,
                value4,
                index5,
                value5,
                index6,
                value6,
                index7,
                value7,
                index8,
                value8,
                country_index,
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 7);
            assert_eq!((index1, value1), (0, 1));
            assert_eq!((index2, value2), (1, 2));
            assert_eq!((index3, value3), (2, 3));
            assert_eq!((index4, value4), (3, 4));
            assert_eq!((index5, value5), (4, 5));
            assert_eq!((index6, value6), (5, 6));
            assert_eq!((index7, value7), (6, 7));
            assert_eq!((index8, value8), (7, 8));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "AS".to_string()
            )
        }
        {
            let (difference_count_minus_one, index1, value1, country_index) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 0);
            assert_eq!((index1, value1), (7, 10));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "AD".to_string()
            )
        }
        {
            let (
                difference_count_minus_one,
                index1,
                value1,
                index2,
                value2,
                index3,
                value3,
                index4,
                value4,
                index5,
                value5,
                index6,
                value6,
                index7,
                value7,
                index8,
                value8,
                country_index,
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 7);
            assert_eq!((index1, value1), (0, 0xB));
            assert_eq!((index2, value2), (1, 0xC));
            assert_eq!((index3, value3), (2, 0xD));
            assert_eq!((index4, value4), (3, 0xE));
            assert_eq!((index5, value5), (4, 0xF));
            assert_eq!((index6, value6), (5, 0x10));
            assert_eq!((index7, value7), (6, 0x11));
            assert_eq!((index8, value8), (7, 0x13));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "ZZ".to_string()
            )
        }
        {
            let (
                difference_count_minus_one,
                index1,
                value1,
                index2,
                value2,
                index3,
                value3,
                index4,
                value4,
                index5,
                value5,
                index6,
                value6,
                index7,
                value7,
                index8,
                value8,
                country_index,
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 7);
            assert_eq!((index1, value1), (0, 0x13));
            assert_eq!((index2, value2), (1, 0x14));
            assert_eq!((index3, value3), (2, 0x15));
            assert_eq!((index4, value4), (3, 0x16));
            assert_eq!((index5, value5), (4, 0x17));
            assert_eq!((index6, value6), (5, 0x18));
            assert_eq!((index7, value7), (6, 0x19));
            assert_eq!((index8, value8), (7, 0x1A));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "AO".to_string()
            )
        }
        {
            let (difference_count_minus_one, index1, value1, index2, value2, country_index) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap(),
            );
            assert_eq!(difference_count_minus_one, 1);
            assert_eq!((index1, value1), (0, 0x14));
            assert_eq!((index2, value2), (7, 0x1B));
            assert_eq!(
                Country::from(country_index as usize).iso3166,
                "ZZ".to_string()
            )
        }
        assert_eq!(bit_queue.take_bits(1), None);
    }

    #[test]
    fn next_works_for_ipv6() {
        let mut serializer = CountryBlockSerializer::new();
        ipv6_country_blocks()
            .into_iter()
            .for_each(|country_block| serializer.add(country_block));
        let mut bit_queue = serializer.finish().1;
        let bit_queue_len = bit_queue.len();
        let mut bit_data: Vec<u64> = vec![];
        while bit_queue.len() >= 64 {
            let data = bit_queue.take_bits(64).unwrap();
            bit_data.push(data);
        }
        let remaining_bit_count = bit_queue.len();
        let data = bit_queue.take_bits(remaining_bit_count).unwrap();
        bit_data.push(data);
        let mut subject =
            CountryBlockDeserializer::<Ipv6Addr, u16, 8>::new((bit_data, bit_queue_len));

        let country_block1 = subject.next().unwrap();
        let country_block2 = subject.next().unwrap();
        let country_block3 = subject.next().unwrap();
        let country_block4 = subject.next().unwrap();
        let country_block5 = subject.next().unwrap();
        let country_block6 = subject.next().unwrap();
        let result = subject.next();

        let original_country_blocks = ipv6_country_blocks();
        assert_eq!(
            country_block1,
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("0:0:0:0:0:0:0:0").unwrap(),
                    Ipv6Addr::from_str("1:2:3:4:5:6:7:7").unwrap()
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(country_block2, original_country_blocks[0]);
        assert_eq!(country_block3, original_country_blocks[1]);
        assert_eq!(
            country_block4,
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("B:C:D:E:F:10:11:13").unwrap(),
                    Ipv6Addr::from_str("13:14:15:16:17:18:19:19").unwrap(),
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(country_block5, original_country_blocks[2]);
        assert_eq!(
            country_block6,
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("14:14:15:16:17:18:19:1B").unwrap(),
                    Ipv6Addr::from_str("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF").unwrap(),
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(result, None);
    }

    #[test]
    fn finish_does_not_touch_complete_ipv6_list() {
        let mut country_blocks = ipv6_country_blocks();
        let mut subject = CountryBlockSerializer::new();
        subject.add(CountryBlock {
            ip_range: IpRange::V6(
                Ipv6Addr::from_str("0:0:0:0:0:0:0:0").unwrap(),
                Ipv6Addr::from_str("1:2:3:4:5:6:7:7").unwrap(),
            ),
            country: Country::from(0usize), // sentinel
        });
        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));
        subject.add(CountryBlock {
            ip_range: IpRange::V6(
                Ipv6Addr::from_str("14:14:15:16:17:18:19:1A").unwrap(),
                Ipv6Addr::from_str("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF").unwrap(),
            ),
            country: Country::try_from("CZ").unwrap().clone(),
        });
        let mut bitqueue = subject.finish().1;
        let len = bitqueue.len();
        let mut vec_64 = vec![];
        while bitqueue.len() >= 64 {
            let data = bitqueue.take_bits(64).unwrap();
            vec_64.push(data);
        }
        let remaining_bit_count = bitqueue.len();
        let data = bitqueue.take_bits(remaining_bit_count).unwrap();
        vec_64.push(data);

        let mut deserializer = CountryBlockDeserializer::<Ipv6Addr, u16, 8>::new((vec_64, len));

        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "ZZ");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "AS");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "AD");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "ZZ");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "AO");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "ZZ");
        let result = deserializer.next();
        assert_eq!(result.unwrap().country.iso3166, "CZ");
        let result = deserializer.next();
        assert_eq!(result, None);
    }
}
