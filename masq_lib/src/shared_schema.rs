// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::constants::{
    BASE_MAINNET_FULL_IDENTIFIER, BASE_SEPOLIA_FULL_IDENTIFIER, DEFAULT_GAS_PRICE, DEFAULT_UI_PORT,
    DEV_CHAIN_FULL_IDENTIFIER, ETH_MAINNET_FULL_IDENTIFIER, ETH_ROPSTEN_FULL_IDENTIFIER,
    HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT, POLYGON_AMOY_FULL_IDENTIFIER,
    POLYGON_MAINNET_FULL_IDENTIFIER,
};
use crate::crash_point::CrashPoint;
use clap::{App, Arg};
use lazy_static::lazy_static;

pub const BLOCKCHAIN_SERVICE_HELP: &str =
    "The Ethereum client you wish to use to provide Blockchain \
     exit services from your MASQ Node (e.g. http://localhost:8545, \
     https://ropsten.infura.io/v3/YOUR-PROJECT-ID, https://mainnet.infura.io/v3/YOUR-PROJECT-ID), \
     https://base-mainnet.g.alchemy.com/v2/d66UL0lPrltmweEqVsv3opBSVI3wkL8I, \
     https://polygon-mainnet.infura.io/v3/YOUR-PROJECT-ID";
pub const CHAIN_HELP: &str =
    "The blockchain network MASQ Node will configure itself to use. You must ensure the \
    Ethereum client specified by --blockchain-service-url communicates with the same blockchain network.";
pub const CONFIG_FILE_HELP: &str =
    "Optional TOML file containing configuration that doesn't often change. Should contain only \
     scalar items, string or numeric, whose names are exactly the same as the command-line parameters \
     they replace (except no '--' prefix). If you specify a relative path, or no path, the Node will \
     look for your config file starting in the --data-directory. If you specify an absolute path, \
     --data-directory will be ignored when searching for the config file. A few parameters \
     (such as --config-file, --generate-wallet, and --recover-wallet) must not be specified in a config file.";
pub const CONSUMING_PRIVATE_KEY_HELP: &str = "The private key for the Ethereum wallet from which you wish to pay \
     other Nodes for routing and exit services. Mostly this is used for testing; be careful using it for real \
     traffic, because this value is very sensitive: anyone who sees it can use it to drain your consuming wallet. \
     If you use it, don't put it on the command line (the environment is good, the config file is less so), \
     make sure you haven't already set up a consuming wallet with a derivation path, and make sure that you always \
     supply exactly the same private key every time you run the Node. A consuming private key is 64 case-insensitive \
     hexadecimal digits.";
pub const DATA_DIRECTORY_HELP: &str =
    "Directory in which the Node will store its persistent state, including at least its database \
    and by default its configuration file as well.\nNote: any existing database in the data directory \
    must have been created from the same chain this run is using, or the Node will be terminated.";
pub const DB_PASSWORD_HELP: &str =
    "A password or phrase to decrypt the encrypted material in the database, to include your \
     mnemonic seed (if applicable) and your list of previous neighbors. If you don't provide this \
     password, none of the encrypted data in your database will be used. This is a secret;\
     providing it on the command line or in a config file may be insecure";
pub const DNS_SERVERS_HELP: &str =
    "IP addresses of DNS Servers for host name look-up while providing exit \
     services for other MASQ Nodes (e.g. 1.0.0.1,1.1.1.1,8.8.8.8,9.9.9.9, etc.)";
pub const EARNING_WALLET_HELP: &str =
    "An Ethereum wallet address. Addresses must begin with 0x followed by 40 hexadecimal digits \
     (case-insensitive). If you already have a derivation-path earning wallet, don't supply this. \
     If you have supplied an earning wallet address before, either don't supply it again or be \
     careful to supply exactly the same one you supplied before.";
pub const ENTRY_DNS_HELP: &str = "Specify whether to use entry DNS. If you can't use HTTP proxying \
     to reroute your client's traffic through MASQ's Node, you can specify --entry-dns to start up \
     MASQ's local DNS server; but you will also need to subvert your network stack's DNS traffic \
     using dns_utility. This practice is not recommended but may be necessary in certain situations.";
pub const IP_ADDRESS_HELP: &str = "The public IP address of your MASQ Node: that is, the IPv4 \
     address at which other Nodes can contact yours. If you're running your Node behind \
     a router, this will be the IP address of the router. If this IP address starts with 192.168 or 10.0, \
     it's a local address rather than a public address, and other Nodes won't be able to see yours. \
     --ip is meaningless except in --neighborhood-mode standard.";
pub const LOG_LEVEL_HELP: &str =
    "The minimum severity of the logs that should appear in the Node's logfile. You should probably not specify \
     a level lower than the default unless you're doing testing or forensics: a Node at the 'trace' log level \
     generates a lot of log traffic. This will both consume your disk space and degrade your Node's performance. \
     You should probably not specify a level higher than the default unless you have security concerns about \
     persistent logs being kept on your computer: if your Node crashes, it's good to know why.";
pub const NEIGHBORS_HELP: &str = "One or more Node descriptors for running Nodes in the MASQ \
     One or more Node descriptors for active Nodes in the MASQ Network to which you'd like your Node to connect \
     on startup. A Node descriptor looks similar to one of these:\n\n\
     masq://polygon-mainnet:d2U3Dv1BqtS5t_Zz3mt9_sCl7AgxUlnkB4jOMElylrU@172.50.48.6:9342\n\
     masq://eth-mainnet:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542\n\
     masq://base-mainnet:ZjPLnb9RrgsRM1D9edqH8jx9DkbPZSWqqFqLnmdKhsk@112.55.78.0:7878\n\
     masq://polygon-amoy:A6PGHT3rRjaeFpD_rFi3qGEXAVPq7bJDfEUZpZaIyq8@14.10.50.6:10504\n\
     masq://base-sepolia:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@150.60.42.72:6642/4789/5254\n\n\
     Notice each of the different chain identifiers in the masq protocol prefix - they determine a family of chains \
     and also the network the descriptor belongs to (mainnet or a testnet). See also the last descriptor which shows \
     a configuration with multiple clandestine ports.\n\n\
     If you have more than one descriptor, separate them with commas. Whether single or multiple descriptors, they \
     should be enclosed by quotes. No default value is available; \
     if you don't specify a neighbor, your Node will start without being connected to any MASQ \
     Network, although other Nodes will be able to connect to yours if they know your Node's descriptor. \
     --neighbors is meaningless in --neighborhood-mode zero-hop.";

// generated valid encoded keys for future needs
// UJNoZW5p/PDVqEjpr3b+8jZ/93yPG8i5dOAgE1bhK+A
// ZjPLnb9RrgsRM1D9edqH8jx9DkbPZSWqqFqLnmdKhsk
// BE1ZIbcxwGTQjzzkkq3qSAK6YKsu8ncVzUfMxTdw5fc

pub const NEIGHBORHOOD_MODE_HELP: &str = "This configures the way the Node relates to other Nodes.\n\n\
     zero-hop means that your Node will operate as its own MASQ Network and will not communicate with any \
     other Nodes. --ip, --neighbors, and --clandestine-port are incompatible with --neighborhood_mode \
     zero-hop.\n\n\
     originate-only means that your Node will not accept connections from any other Node; it \
     will only originate connections to other Nodes. This will reduce your Node's opportunity to route \
     data (it will only ever have two neighbors, so the number of routes it can participate in is limited), \
     it will reduce redundancy in the MASQ Network, and it will prevent your Node from acting as \
     a connection point for other Nodes to get on the Network; but it will enable your Node to operate in \
     an environment where your network hookup is preventing you from accepting connections, and it means \
     that you don't have to forward any incoming ports through your router. --ip and --clandestine_port \
     are incompatible with --neighborhood_mode originate-only.\n\n\
     consume-only means that your Node will not accept connections from or route data for any other Node; \
     it will only consume services from the MASQ Network. This mode is appropriate for devices that \
     cannot maintain a constant IP address or stay constantly on the Network. --ip and --clandestine_port \
     are incompatible with --neighborhood_mode consume-only.\n\n\
     standard means that your Node will operate fully unconstrained, both originating and accepting \
     connections, both consuming and providing services, and when you operate behind a router, it \
     requires that you forward your clandestine port through that router to your Node's machine.";
pub const MAPPING_PROTOCOL_HELP: &str =
    "The Node can speak three protocols to your router to make it allow outside Nodes to connect inward \
    through it to your machine. These three protocols are pcp, pmp, and igdp. The Node can try them one \
    by one to determine which your router supports, but if you happen to know already, you can supply the \
    name of the protocol here. If you've taken care of port mapping in some other way, \
    and you don't need Node to negotiate with your router, say 'none' here and be sure to specify your \
    public IP address with the --ip parameter. If the Node communicates successfully with your router, \
    it will remember the protocol it used, and on its next run it will try that protocol first, unless \
    you specify a different protocol on the command line.";
pub const MIN_HOPS_HELP: &str =
    "The Node is a system that routes data through multiple Nodes to enhance security and privacy. \
    However, the level of anonymity and security provided depends on the number of hops specified \
    by the user. By default, the system allows the user to customize the number of hops within a \
    range of 1 to 6.\n\n\
    It's important to note that if the user selects less than 3 hops, the anonymity of their data \
    cannot be guaranteed. Here's a breakdown of the different hop counts and their implications:\n\n\
    1. A 1-hop route means that the exit Node will know the IP address of the originating Node. \
    Also, someone snooping traffic on the network will be able to see both the originating Node's IP \
    and the exit Node's IP in the same packet. A 1-hop route makes MASQ the equivalent of a VPN. \n\
    2. A 2-hop route removes the ability to see both the originating and exit IP addresses on the \
    same packet, but it means that the relay Node in the middle (which could be subverted by an attacker) \
    knows both IP addresses.\n\
    3. A 3-hop route is the shortest route that prevents any Node in the network (even the originating Node) \
    from knowing the IP addresses of all the Nodes in the route.\n\
    4. Increasing the number of hops to 4, 5, or 6 can enhance security, but it will also \
    increase the cost and latency of the route.\n\
    If you want to specify a minimum hops count, you can do so by entering a number after the \
    '--min-hops' parameter. For example, '--min-hops 4' would require at least 4 hops. If you fail \
    to provide this argument, the system will default to a minimum hops count of 3.";
pub const REAL_USER_HELP: &str =
    "The user whose identity Node will assume when dropping privileges after bootstrapping. Since Node refuses to \
     run with root privilege after bootstrapping, you might want to use this if you start the Node as root, or if \
     you start the Node using pkexec or some other method that doesn't populate the SUDO_xxx variables. Use a value \
     like <uid>:<gid>:<home directory>.";
pub const SCANS_HELP: &str =
    "The Node, when running, performs various periodic scans, including scanning for payables that need to be paid, \
    for pending payables that have arrived (and are no longer pending), for incoming receivables that need to be \
    recorded, and for delinquent Nodes that need to be banned. If you don't specify this parameter, or if you give \
    it the value 'on', these scans will proceed normally. But if you give the value 'off', the scans won't be \
    started when the Node starts, and will have to be triggered later manually and individually with the \
    MASQNode-UIv2 'scan' command. (If you don't, you'll most likely be delinquency-banned by all your neighbors.) \
    This parameter is most useful for testing.";
pub const RATE_PACK_HELP: &str = "\
     These four parameters specify your rates that your Node will use for charging other Nodes for your provided \
     services. These are ever present values, defaulted if left unspecified. The parameters must be always supplied \
     all together, delimited by vertical bars and in the right order.\n\n\
     1. Routing Byte Rate: This parameter indicates an amount of MASQ in wei demanded to process 1 byte of routed payload \
     while the Node is a common relay Node.\n\n\
     2. Routing Service Rate: This parameter indicates an amount of MASQ in wei demanded to provide services, unpacking \
     and repacking 1 CORES package, while the Node is a common relay Node.\n\n\
     3. Exit Byte Rate: This parameter indicates an amount of MASQ in wei demanded to process 1 byte of routed payload \
     while the Node acts as the exit Node.\n\n\
     4. Exit Service Rate: This parameter indicates an amount of MASQ in wei demanded to provide services, unpacking and \
     repacking 1 CORES package, while the Node acts as the exit Node.";
pub const PAYMENT_THRESHOLDS_HELP: &str = "\
     These are parameters that define thresholds to determine when and how much to pay other Nodes for routing and \
     exit services and the expectations the Node should have for receiving payments from other Nodes for routing and \
     exit services. The thresholds are also used to determine whether to offer services to other Nodes or enact a ban \
     since they have not paid mature debts. These are ever present values, no matter if the user's set any value, as \
     they have defaults. The parameters must be always supplied all together, delimited by vertical bars and in the right \
     order.\n\n\
     1. Debt Threshold gwei: Payables higher than this -- in gwei of MASQ -- will be suggested for payment immediately \
     upon passing the Maturity Threshold Sec age. Payables less than this can stay unpaid longer. Receivables higher than \
     this will be expected to be settled by other Nodes, but will never cause bans until they pass the Maturity Threshold Sec \
     + Payment Grace Period Sec age. Receivables less than this will survive longer without banning.\n\n\
     2. Maturity Threshold Sec: Large payables can get this old -- in seconds -- before the Accountant's scanner suggests \
     that it be paid.\n\n\
     3. Payment Grace Period Sec: A large receivable can get as old as Maturity Threshold Sec + Payment Grace Period Sec \
     -- in seconds -- before the Node that owes it will be banned.\n\n\
     4. Permanent Debt Allowed gwei: Receivables this small and smaller -- in gwei of MASQ -- will not cause bans no \
     matter how old they get.\n\n\
     5. Threshold Interval Sec: This interval -- in seconds -- begins after Maturity Threshold Sec for payables and after \
     Maturity Threshold Sec + Payment Grace Period Sec for receivables. During the interval, the amount of a payable that is \
     allowed to remain unpaid, or a pending receivable that won’t cause a ban, decreases linearly from the Debt Threshold gwei \
     to Permanent Debt Allowed gwei or Unban Below gwei.\n\n\
     6. Unban Below gwei: When a delinquent Node has been banned due to non-payment, the receivables balance must be paid \
     below this level -- in gwei of MASQ -- to cause them to be unbanned. In most cases, you'll want this to be set the same \
     as Permanent Debt Allowed gwei.";
pub const SCAN_INTERVALS_HELP:&str = "\
     These three intervals describe the length of three different scan cycles running automatically in the background \
     since the Node has connected to a qualified neighborhood that consists of neighbors enabling a complete 3-hop \
     route. Each parameter can be set independently, but by default are all the same which currently is most desirable \
     for the consistency of service payments to and from your Node. Technically, there doesn't have to be any lower \
     limit for the minimum of time you can set; two scans of the same sort would never run at the same time but the \
     next one is always scheduled not earlier than the end of the previous one. These are ever present values, no matter \
     if the user's set any value, they have defaults. The parameters must be always supplied all together, delimited by vertical \
     bars and in the right order.\n\n\
     1. Pending Payable Scan Interval: Amount of seconds between two sequential cycles of scanning for payments that are \
     marked as currently pending; the payments were sent to pay our debts, the payable. The purpose of this process is to \
     confirm the status of the pending payment; either the payment transaction was written on blockchain as successful or \
     failed.\n\n\
     2. Payable Scan Interval: Amount of seconds between two sequential cycles of scanning aimed to find payable accounts \
     of that meet the criteria set by the Payment Thresholds; these accounts are tracked on behalf of our creditors. If \
     they meet the Payment Threshold criteria, our Node will send a debt payment transaction to the creditor in question.\n\n\
     3. Receivable Scan Interval: Amount of seconds between two sequential cycles of scanning for payments on the \
     blockchain that have been sent by our creditors to us, which are credited against receivables recorded for services \
     provided.";

lazy_static! {
    pub static ref DEFAULT_UI_PORT_VALUE: String = DEFAULT_UI_PORT.to_string();
    pub static ref UI_PORT_HELP: String = format!(
        "The port at which user interfaces will connect to the Node. Best to accept the default unless \
        you know what you're doing. Must be between {} and {}.",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    pub static ref CLANDESTINE_PORT_HELP: String = format!(
        "The port this Node will advertise to other Nodes at which clandestine traffic will be \
         received. If you don't specify a clandestine port, the Node will choose an unused \
         one at random on first startup, then use that one for every subsequent run unless \
         you change it by specifying a different clandestine port here. --clandestine-port is \
         meaningless except in --neighborhood-mode standard. \
         Must be between {} and {} [default: last used port]",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    pub static ref GAS_PRICE_HELP: String = format!(
       "The Gas Price is the amount of gwei you will pay per unit of gas used in a transaction. \
       If left unspecified, MASQ Node will use the previously stored value (Default {}).",
       DEFAULT_GAS_PRICE);
}

// These Args are needed in more than one clap schema. To avoid code duplication, they're defined here and referred
// to from multiple places.
pub fn chain_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("chain")
        .long("chain")
        .value_name("CHAIN")
        .min_values(0)
        .max_values(1)
        .possible_values(official_chain_names())
        .help(CHAIN_HELP)
}

pub fn config_file_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("config-file")
        .long("config-file")
        .value_name("FILE-PATH")
        .min_values(0)
        .max_values(1)
        .required(false)
        .help(CONFIG_FILE_HELP)
}

pub fn data_directory_arg(help: &str) -> Arg {
    Arg::with_name("data-directory")
        .long("data-directory")
        .value_name("DATA-DIRECTORY")
        .required(false)
        .min_values(0)
        .max_values(1)
        .empty_values(false)
        .help(help)
}

pub fn official_chain_names() -> &'static [&'static str] {
    &[
        POLYGON_MAINNET_FULL_IDENTIFIER,
        ETH_MAINNET_FULL_IDENTIFIER,
        BASE_MAINNET_FULL_IDENTIFIER,
        BASE_SEPOLIA_FULL_IDENTIFIER,
        POLYGON_AMOY_FULL_IDENTIFIER,
        ETH_ROPSTEN_FULL_IDENTIFIER,
        DEV_CHAIN_FULL_IDENTIFIER,
    ]
}

pub fn db_password_arg(help: &str) -> Arg {
    Arg::with_name("db-password")
        .long("db-password")
        .value_name("DB-PASSWORD")
        .required(false)
        .min_values(0)
        .max_values(1)
        .help(help)
}

pub fn earning_wallet_arg<F>(help: &str, validator: F) -> Arg
where
    F: 'static,
    F: Fn(String) -> Result<(), String>,
{
    Arg::with_name("earning-wallet")
        .long("earning-wallet")
        .value_name("EARNING-WALLET")
        .required(false)
        .min_values(0)
        .max_values(1)
        .validator(validator)
        .help(help)
}

pub fn gas_price_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("gas-price")
        .long("gas-price")
        .value_name("GAS-PRICE")
        .min_values(0)
        .max_values(1)
        .validator(common_validators::validate_gas_price)
        .help(&GAS_PRICE_HELP)
}

pub fn min_hops_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("min-hops")
        .long("min-hops")
        .value_name("MIN-HOPS")
        .min_values(0)
        .max_values(1)
        .possible_values(&["1", "2", "3", "4", "5", "6"])
        .help(MIN_HOPS_HELP)
}

#[cfg(not(target_os = "windows"))]
pub fn real_user_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("real-user")
        .long("real-user")
        .value_name("REAL-USER")
        .required(false)
        .min_values(0)
        .max_values(1)
        .validator(common_validators::validate_real_user)
        .help(REAL_USER_HELP)
}

#[cfg(target_os = "windows")]
pub fn real_user_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("real-user")
        .long("real-user")
        .value_name("REAL-USER")
        .required(false)
        .takes_value(true)
        .validator(common_validators::validate_real_user)
        .hidden(true)
}

pub fn ui_port_arg(help: &str) -> Arg {
    Arg::with_name("ui-port")
        .long("ui-port")
        .value_name("UI-PORT")
        .takes_value(true)
        .default_value(&DEFAULT_UI_PORT_VALUE)
        .validator(common_validators::validate_ui_port)
        .help(help)
}

fn common_parameter_with_separate_u64_values<'a>(name: &'a str, help: &'a str) -> Arg<'a, 'a> {
    Arg::with_name(name)
        .long(name)
        .value_name(Box::leak(name.to_uppercase().into_boxed_str()))
        .min_values(0)
        .max_values(1)
        .validator(common_validators::validate_separate_u64_values)
        .help(help)
}

pub fn shared_app(head: App<'static, 'static>) -> App<'static, 'static> {
    head.arg(
        Arg::with_name("blockchain-service-url")
            .long("blockchain-service-url")
            .value_name("URL")
            .min_values(0)
            .max_values(1)
            .help(BLOCKCHAIN_SERVICE_HELP),
    )
    .arg(chain_arg())
    .arg(
        Arg::with_name("clandestine-port")
            .long("clandestine-port")
            .value_name("CLANDESTINE-PORT")
            .min_values(0)
            .validator(common_validators::validate_clandestine_port)
            .help(&CLANDESTINE_PORT_HELP),
    )
    .arg(config_file_arg())
    .arg(
        Arg::with_name("consuming-private-key")
            .long("consuming-private-key")
            .value_name("PRIVATE-KEY")
            .min_values(0)
            .max_values(1)
            .validator(common_validators::validate_private_key)
            .help(CONSUMING_PRIVATE_KEY_HELP),
    )
    .arg(
        Arg::with_name("crash-point")
            .long("crash-point")
            .value_name("CRASH-POINT")
            .min_values(0)
            .max_values(1)
            .possible_values(&CrashPoint::variants())
            .case_insensitive(true)
            .hidden(true),
    )
    .arg(data_directory_arg(DATA_DIRECTORY_HELP))
    .arg(db_password_arg(DB_PASSWORD_HELP))
    .arg(
        Arg::with_name("dns-servers")
            .long("dns-servers")
            .value_name("DNS-SERVERS")
            .min_values(0)
            .max_values(1)
            .validator(common_validators::validate_ip_addresses)
            .help(DNS_SERVERS_HELP),
    )
    .arg(earning_wallet_arg(
        EARNING_WALLET_HELP,
        common_validators::validate_ethereum_address,
    ))
    .arg(
        Arg::with_name("entry-dns")
            .long("entry-dns")
            .value_name("ENTRY-DNS")
            .required(false)
            .takes_value(false)
            .help(ENTRY_DNS_HELP),
    )
    .arg(
        Arg::with_name("fake-public-key")
            .long("fake-public-key")
            .value_name("FAKE-PUBLIC-KEY")
            .min_values(0)
            .max_values(1)
            .hidden(true),
    )
    .arg(gas_price_arg())
    .arg(
        Arg::with_name("ip")
            .long("ip")
            .value_name("IP")
            .min_values(0)
            .max_values(1)
            .validator(common_validators::validate_ip_address)
            .help(IP_ADDRESS_HELP),
    )
    .arg(
        Arg::with_name("log-level")
            .long("log-level")
            .value_name("FILTER")
            .min_values(0)
            .max_values(1)
            .possible_values(&["off", "error", "warn", "info", "debug", "trace"])
            .case_insensitive(true)
            .help(LOG_LEVEL_HELP),
    )
    .arg(
        Arg::with_name("mapping-protocol")
            .long("mapping-protocol")
            .value_name("MAPPING-PROTOCOL")
            .min_values(0)
            .max_values(1)
            .possible_values(&["pcp", "pmp", "igdp"])
            .case_insensitive(true)
            .help(MAPPING_PROTOCOL_HELP),
    )
    .arg(min_hops_arg())
    .arg(
        Arg::with_name("neighborhood-mode")
            .long("neighborhood-mode")
            .value_name("NEIGHBORHOOD-MODE")
            .min_values(0)
            .max_values(1)
            .possible_values(&["zero-hop", "originate-only", "consume-only", "standard"])
            .case_insensitive(true)
            .help(NEIGHBORHOOD_MODE_HELP),
    )
    .arg(
        Arg::with_name("neighbors")
            .long("neighbors")
            .value_name("NODE-DESCRIPTORS")
            .min_values(0)
            .help(NEIGHBORS_HELP),
    )
    .arg(real_user_arg())
    .arg(
        Arg::with_name("scans")
            .long("scans")
            .value_name("SCANS")
            .takes_value(true)
            .possible_values(&["on", "off"])
            .help(SCANS_HELP),
    )
    .arg(common_parameter_with_separate_u64_values(
        "scan-intervals",
        SCAN_INTERVALS_HELP,
    ))
    .arg(common_parameter_with_separate_u64_values(
        "rate-pack",
        RATE_PACK_HELP,
    ))
    .arg(common_parameter_with_separate_u64_values(
        "payment-thresholds",
        PAYMENT_THRESHOLDS_HELP,
    ))
}

pub mod common_validators {
    use crate::constants::LOWEST_USABLE_INSECURE_PORT;
    use regex::Regex;
    use std::net::IpAddr;
    use std::str::FromStr;
    use tiny_hderive::bip44::DerivationPath;

    pub fn validate_ip_address(address: String) -> Result<(), String> {
        match IpAddr::from_str(&address) {
            Ok(_) => Ok(()),
            Err(_) => Err(address),
        }
    }

    pub fn validate_ip_addresses(addresses: String) -> Result<(), String> {
        let errors = addresses
            .split(',')
            .map(|address| validate_ip_address(address.to_string()))
            .flat_map(|result| match result {
                Ok(_) => None,
                Err(e) => Some(format!("{:?}", e)),
            })
            .collect::<Vec<String>>()
            .join(";");
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn validate_clandestine_port(clandestine_port: String) -> Result<(), String> {
        match clandestine_port.parse::<u16>() {
            Ok(clandestine_port) if clandestine_port >= LOWEST_USABLE_INSECURE_PORT => Ok(()),
            _ => Err(clandestine_port),
        }
    }

    pub fn validate_private_key(key: String) -> Result<(), String> {
        if Regex::new("^[0-9a-fA-F]{64}$")
            .expect("Failed to compile regular expression")
            .is_match(&key)
        {
            Ok(())
        } else {
            Err(key)
        }
    }

    pub fn validate_gas_price(gas_price: String) -> Result<(), String> {
        match gas_price.parse::<u64>() {
            Ok(gp) if gp > 0 => Ok(()),
            _ => Err(gas_price),
        }
    }

    pub fn validate_earning_wallet(value: String) -> Result<(), String> {
        validate_ethereum_address(value.clone()).or_else(|_| validate_derivation_path(value))
    }

    pub fn validate_ethereum_address(address: String) -> Result<(), String> {
        if Regex::new("^0x[0-9a-fA-F]{40}$")
            .expect("Failed to compile regular expression")
            .is_match(&address)
        {
            Ok(())
        } else {
            Err(address)
        }
    }

    pub fn validate_derivation_path(path: String) -> Result<(), String> {
        let possible_path = path.parse::<DerivationPath>();

        match possible_path {
            Ok(derivation_path) => {
                validate_derivation_path_is_sufficiently_hardened(derivation_path, path)
            }
            Err(e) => Err(format!("{} is not valid: {:?}", path, e)),
        }
    }

    pub fn validate_derivation_path_is_sufficiently_hardened(
        derivation_path: DerivationPath,
        path: String,
    ) -> Result<(), String> {
        if derivation_path
            .iter()
            .filter(|child_nbr| child_nbr.is_hardened())
            .count()
            > 2
        {
            Ok(())
        } else {
            Err(format!("{} may be too weak", path))
        }
    }

    pub fn validate_real_user(triple: String) -> Result<(), String> {
        if Regex::new("^[0-9]*:[0-9]*:.*$")
            .expect("Failed to compile regular expression")
            .is_match(&triple)
        {
            Ok(())
        } else {
            Err(triple)
        }
    }

    pub fn validate_ui_port(port: String) -> Result<(), String> {
        match str::parse::<u16>(&port) {
            Ok(port_number) if port_number < LOWEST_USABLE_INSECURE_PORT => Err(port),
            Ok(_) => Ok(()),
            Err(_) => Err(port),
        }
    }

    pub fn validate_non_zero_u16(str: String) -> Result<(), String> {
        match str::parse::<u16>(&str) {
            Ok(num) if num > 0 => Ok(()),
            _ => Err(str),
        }
    }

    pub fn validate_separate_u64_values(values_with_delimiters: String) -> Result<(), String> {
        values_with_delimiters.split('|').try_for_each(|segment| {
            segment
                .parse::<u64>()
                .map_err(|_| {
                    "Supply positive numeric values separated by vertical bars like 111|222|333|..."
                        .to_string()
                })
                .map(|_| ())
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParamError {
    pub parameter: String,
    pub reason: String,
}

impl ParamError {
    pub fn new(parameter: &str, reason: &str) -> Self {
        Self {
            parameter: parameter.to_string(),
            reason: reason.to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfiguratorError {
    pub param_errors: Vec<ParamError>,
}

impl ConfiguratorError {
    pub fn new(param_errors: Vec<ParamError>) -> Self {
        Self { param_errors }
    }

    pub fn required(parameter: &str, reason: &str) -> Self {
        ConfiguratorError {
            param_errors: vec![ParamError::new(parameter, reason)],
        }
    }

    pub fn another_required(mut self, parameter: &str, reason: &str) -> Self {
        self.param_errors.push(ParamError::new(parameter, reason));
        self
    }

    pub fn extend(&mut self, extension: Self) {
        self.param_errors.extend(extension.param_errors);
    }

    pub fn len(&self) -> usize {
        self.param_errors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchains::chains::Chain;
    use crate::shared_schema::common_validators::validate_non_zero_u16;
    use crate::shared_schema::{common_validators, official_chain_names};
    use std::collections::HashSet;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            BLOCKCHAIN_SERVICE_HELP,
            "The Ethereum client you wish to use to provide Blockchain \
             exit services from your MASQ Node (e.g. http://localhost:8545, \
             https://ropsten.infura.io/v3/YOUR-PROJECT-ID, https://mainnet.infura.io/v3/YOUR-PROJECT-ID), \
             https://base-mainnet.g.alchemy.com/v2/d66UL0lPrltmweEqVsv3opBSVI3wkL8I, \
             https://polygon-mainnet.infura.io/v3/YOUR-PROJECT-ID"
        );
        assert_eq!(
            CHAIN_HELP,
            "The blockchain network MASQ Node will configure itself to use. You must ensure the \
             Ethereum client specified by --blockchain-service-url communicates with the same blockchain network."
        );
        assert_eq!(
            CONFIG_FILE_HELP,
            "Optional TOML file containing configuration that doesn't often change. Should contain only \
             scalar items, string or numeric, whose names are exactly the same as the command-line parameters \
             they replace (except no '--' prefix). If you specify a relative path, or no path, the Node will \
             look for your config file starting in the --data-directory. If you specify an absolute path, \
             --data-directory will be ignored when searching for the config file. A few parameters \
             (such as --config-file, --generate-wallet, and --recover-wallet) must not be specified in a config file."
        );
        assert_eq!(
            CONSUMING_PRIVATE_KEY_HELP,
            "The private key for the Ethereum wallet from which you wish to pay \
             other Nodes for routing and exit services. Mostly this is used for testing; be careful using it for real \
             traffic, because this value is very sensitive: anyone who sees it can use it to drain your consuming wallet. \
             If you use it, don't put it on the command line (the environment is good, the config file is less so), \
             make sure you haven't already set up a consuming wallet with a derivation path, and make sure that you always \
             supply exactly the same private key every time you run the Node. A consuming private key is 64 case-insensitive \
             hexadecimal digits."
        );
        assert_eq!(
            DATA_DIRECTORY_HELP,
            "Directory in which the Node will store its persistent state, including at \
             least its database and by default its configuration file as well.\nNote: any existing \
             database in the data directory must have been created from the same chain this run is using, \
             or the Node will be terminated."
        );
        assert_eq!(
            DB_PASSWORD_HELP,
            "A password or phrase to decrypt the encrypted material in the database, to include your \
             mnemonic seed (if applicable) and your list of previous neighbors. If you don't provide this \
             password, none of the encrypted data in your database will be used. This is a secret;\
             providing it on the command line or in a config file may be insecure"
        );
        assert_eq!(
            DNS_SERVERS_HELP,
            "IP addresses of DNS Servers for host name look-up while providing exit \
             services for other MASQ Nodes (e.g. 1.0.0.1,1.1.1.1,8.8.8.8,9.9.9.9, etc.)"
        );
        assert_eq!(
            EARNING_WALLET_HELP,
            "An Ethereum wallet address. Addresses must begin with 0x followed by 40 hexadecimal digits \
             (case-insensitive). If you already have a derivation-path earning wallet, don't supply this. \
             If you have supplied an earning wallet address before, either don't supply it again or be \
             careful to supply exactly the same one you supplied before."
        );
        assert_eq!(
            ENTRY_DNS_HELP,
            "Specify whether to use entry DNS. If you can't use HTTP proxying \
             to reroute your client's traffic through MASQ's Node, you can specify --entry-dns to start up \
             MASQ's local DNS server; but you will also need to subvert your network stack's DNS traffic \
             using dns_utility. This practice is not recommended but may be necessary in certain situations."
        );
        assert_eq!(
            IP_ADDRESS_HELP,
            "The public IP address of your MASQ Node: that is, the IPv4 \
             address at which other Nodes can contact yours. If you're running your Node behind \
             a router, this will be the IP address of the router. If this IP address starts with 192.168 or 10.0, \
             it's a local address rather than a public address, and other Nodes won't be able to see yours. \
             --ip is meaningless except in --neighborhood-mode standard."
        );
        assert_eq!(
            LOG_LEVEL_HELP,
            "The minimum severity of the logs that should appear in the Node's logfile. You should probably not specify \
             a level lower than the default unless you're doing testing or forensics: a Node at the 'trace' log level \
             generates a lot of log traffic. This will both consume your disk space and degrade your Node's performance. \
             You should probably not specify a level higher than the default unless you have security concerns about \
             persistent logs being kept on your computer: if your Node crashes, it's good to know why.");
        assert_eq!(
            NEIGHBORS_HELP,
            "One or more Node descriptors for running Nodes in the MASQ \
             One or more Node descriptors for active Nodes in the MASQ Network to which you'd like your Node to connect \
             on startup. A Node descriptor looks similar to one of these:\n\n\
                  masq://polygon-mainnet:d2U3Dv1BqtS5t_Zz3mt9_sCl7AgxUlnkB4jOMElylrU@172.50.48.6:9342\n\
                  masq://eth-mainnet:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542\n\
                  masq://base-mainnet:ZjPLnb9RrgsRM1D9edqH8jx9DkbPZSWqqFqLnmdKhsk@112.55.78.0:7878\n\
                  masq://polygon-amoy:A6PGHT3rRjaeFpD_rFi3qGEXAVPq7bJDfEUZpZaIyq8@14.10.50.6:10504\n\
                  masq://base-sepolia:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@150.60.42.72:6642/4789/5254\n\n\
             Notice each of the different chain identifiers in the masq protocol prefix - they determine a family of chains \
             and also the network the descriptor belongs to (mainnet or a testnet). See also the last descriptor which shows \
             a configuration with multiple clandestine ports.\n\n\
             If you have more than one descriptor, separate them with commas. Whether single or multiple descriptors, they \
             should be enclosed by quotes. No default value is available; \
             if you don't specify a neighbor, your Node will start without being connected to any MASQ \
             Network, although other Nodes will be able to connect to yours if they know your Node's descriptor. \
             --neighbors is meaningless in --neighborhood-mode zero-hop."
        );
        assert_eq!(
            NEIGHBORHOOD_MODE_HELP,
            "This configures the way the Node relates to other Nodes.\n\n\
             zero-hop means that your Node will operate as its own MASQ Network and will not communicate with any \
             other Nodes. --ip, --neighbors, and --clandestine-port are incompatible with --neighborhood_mode \
             zero-hop.\n\n\
             originate-only means that your Node will not accept connections from any other Node; it \
             will only originate connections to other Nodes. This will reduce your Node's opportunity to route \
             data (it will only ever have two neighbors, so the number of routes it can participate in is limited), \
             it will reduce redundancy in the MASQ Network, and it will prevent your Node from acting as \
             a connection point for other Nodes to get on the Network; but it will enable your Node to operate in \
             an environment where your network hookup is preventing you from accepting connections, and it means \
             that you don't have to forward any incoming ports through your router. --ip and --clandestine_port \
             are incompatible with --neighborhood_mode originate-only.\n\n\
             consume-only means that your Node will not accept connections from or route data for any other Node; \
             it will only consume services from the MASQ Network. This mode is appropriate for devices that \
             cannot maintain a constant IP address or stay constantly on the Network. --ip and --clandestine_port \
             are incompatible with --neighborhood_mode consume-only.\n\n\
             standard means that your Node will operate fully unconstrained, both originating and accepting \
             connections, both consuming and providing services, and when you operate behind a router, it \
             requires that you forward your clandestine port through that router to your Node's machine."
        );
        assert_eq!(
            MAPPING_PROTOCOL_HELP,
            "The Node can speak three protocols to your router to make it allow outside Nodes to connect inward \
             through it to your machine. These three protocols are pcp, pmp, and igdp. The Node can try them one \
             by one to determine which your router supports, but if you happen to know already, you can supply the \
             name of the protocol here. If you've taken care of port mapping in some other way, \
             and you don't need Node to negotiate with your router, say 'none' here and be sure to specify your \
             public IP address with the --ip parameter. If the Node communicates successfully with your router, \
             it will remember the protocol it used, and on its next run it will try that protocol first, unless \
             you specify a different protocol on the command line."
        );
        assert_eq!(
            MIN_HOPS_HELP,
            "The Node is a system that routes data through multiple Nodes to enhance security and privacy. \
             However, the level of anonymity and security provided depends on the number of hops specified \
             by the user. By default, the system allows the user to customize the number of hops within a \
             range of 1 to 6.\n\n\
             It's important to note that if the user selects less than 3 hops, the anonymity of their data \
             cannot be guaranteed. Here's a breakdown of the different hop counts and their implications:\n\n\
             1. A 1-hop route means that the exit Node will know the IP address of the originating Node. \
             Also, someone snooping traffic on the network will be able to see both the originating Node's IP \
             and the exit Node's IP in the same packet. A 1-hop route makes MASQ the equivalent of a VPN. \n\
             2. A 2-hop route removes the ability to see both the originating and exit IP addresses on the \
             same packet, but it means that the relay Node in the middle (which could be subverted by an attacker) \
             knows both IP addresses.\n\
             3. A 3-hop route is the shortest route that prevents any Node in the network (even the originating Node) \
             from knowing the IP addresses of all the Nodes in the route.\n\
             4. Increasing the number of hops to 4, 5, or 6 can enhance security, but it will also \
             increase the cost and latency of the route.\n\
             If you want to specify a minimum hops count, you can do so by entering a number after the \
             '--min-hops' parameter. For example, '--min-hops 4' would require at least 4 hops. If you fail \
             to provide this argument, the system will default to a minimum hops count of 3."
        );
        assert_eq!(
            REAL_USER_HELP,
            "The user whose identity Node will assume when dropping privileges after bootstrapping. Since Node refuses to \
             run with root privilege after bootstrapping, you might want to use this if you start the Node as root, or if \
             you start the Node using pkexec or some other method that doesn't populate the SUDO_xxx variables. Use a value \
             like <uid>:<gid>:<home directory>."
        );

        assert_eq!(
            DEFAULT_UI_PORT_VALUE.to_string(),
            DEFAULT_UI_PORT.to_string()
        );
        assert_eq!(
            UI_PORT_HELP.to_string(),
            format!(
                "The port at which user interfaces will connect to the Node. Best to accept the default unless \
                 you know what you're doing. Must be between {} and {}.",
                LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
            )
        );
        assert_eq!(
            CLANDESTINE_PORT_HELP.to_string(),
            format!(
                "The port this Node will advertise to other Nodes at which clandestine traffic will be \
                 received. If you don't specify a clandestine port, the Node will choose an unused \
                 one at random on first startup, then use that one for every subsequent run unless \
                 you change it by specifying a different clandestine port here. --clandestine-port is \
                 meaningless except in --neighborhood-mode standard. \
                 Must be between {} and {} [default: last used port]",
                LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
            )
        );
        assert_eq!(
            GAS_PRICE_HELP.to_string(),
            format!(
                "The Gas Price is the amount of gwei you will pay per unit of gas used in a transaction. \
                 If left unspecified, MASQ Node will use the previously stored value (Default {}).",
                DEFAULT_GAS_PRICE
            )
        );
        assert_eq!(
            RATE_PACK_HELP,
            "These four parameters specify your rates that your Node will use for charging other Nodes for your provided \
             services. These are ever present values, defaulted if left unspecified. The parameters must be always supplied \
             all together, delimited by vertical bars and in the right order.\n\n\
             1. Routing Byte Rate: This parameter indicates an amount of MASQ in wei demanded to process 1 byte of routed payload \
             while the Node is a common relay Node.\n\n\
             2. Routing Service Rate: This parameter indicates an amount of MASQ in wei demanded to provide services, unpacking \
             and repacking 1 CORES package, while the Node is a common relay Node.\n\n\
             3. Exit Byte Rate: This parameter indicates an amount of MASQ in wei demanded to process 1 byte of routed payload \
             while the Node acts as the exit Node.\n\n\
             4. Exit Service Rate: This parameter indicates an amount of MASQ in wei demanded to provide services, unpacking and \
             repacking 1 CORES package, while the Node acts as the exit Node."
        );
        assert_eq!(
            PAYMENT_THRESHOLDS_HELP,
            "These are parameters that define thresholds to determine when and how much to pay other Nodes for routing and \
             exit services and the expectations the Node should have for receiving payments from other Nodes for routing and \
             exit services. The thresholds are also used to determine whether to offer services to other Nodes or enact a ban \
             since they have not paid mature debts. These are ever present values, no matter if the user's set any value, as \
             they have defaults. The parameters must be always supplied all together, delimited by vertical bars and in the right order.\n\n\
             1. Debt Threshold gwei: Payables higher than this -- in gwei of MASQ -- will be suggested for payment immediately \
             upon passing the Maturity Threshold Sec age. Payables less than this can stay unpaid longer. Receivables higher than \
             this will be expected to be settled by other Nodes, but will never cause bans until they pass the Maturity Threshold Sec \
             + Payment Grace Period Sec age. Receivables less than this will survive longer without banning.\n\n\
             2. Maturity Threshold Sec: Large payables can get this old -- in seconds -- before the Accountant's scanner suggests \
             that it be paid.\n\n\
             3. Payment Grace Period Sec: A large receivable can get as old as Maturity Threshold Sec + Payment Grace Period Sec \
             -- in seconds -- before the Node that owes it will be banned.\n\n\
             4. Permanent Debt Allowed gwei: Receivables this small and smaller -- in gwei of MASQ -- will not cause bans no \
             matter how old they get.\n\n\
             5. Threshold Interval Sec: This interval -- in seconds -- begins after Maturity Threshold Sec for payables and after \
             Maturity Threshold Sec + Payment Grace Period Sec for receivables. During the interval, the amount of a payable that is \
             allowed to remain unpaid, or a pending receivable that won’t cause a ban, decreases linearly from the Debt Threshold gwei \
             to Permanent Debt Allowed gwei or Unban Below gwei.\n\n\
             6. Unban Below gwei: When a delinquent Node has been banned due to non-payment, the receivables balance must be paid \
             below this level -- in gwei of MASQ -- to cause them to be unbanned. In most cases, you'll want this to be set the same \
             as Permanent Debt Allowed gwei."
        );
        assert_eq!(
            SCAN_INTERVALS_HELP,
            "These three intervals describe the length of three different scan cycles running automatically in the background \
             since the Node has connected to a qualified neighborhood that consists of neighbors enabling a complete 3-hop \
             route. Each parameter can be set independently, but by default are all the same which currently is most desirable \
             for the consistency of service payments to and from your Node. Technically, there doesn't have to be any lower \
             limit for the minimum of time you can set; two scans of the same sort would never run at the same time but the \
             next one is always scheduled not earlier than the end of the previous one. These are ever present values, no matter \
             if the user's set any value, they have defaults. The parameters must be always supplied all together, delimited by \
             vertical bars and in the right order.\n\n\
             1. Pending Payable Scan Interval: Amount of seconds between two sequential cycles of scanning for payments that are \
             marked as currently pending; the payments were sent to pay our debts, the payable. The purpose of this process is to \
             confirm the status of the pending payment; either the payment transaction was written on blockchain as successful or \
             failed.\n\n\
             2. Payable Scan Interval: Amount of seconds between two sequential cycles of scanning aimed to find payable accounts \
             of that meet the criteria set by the Payment Thresholds; these accounts are tracked on behalf of our creditors. If \
             they meet the Payment Threshold criteria, our Node will send a debt payment transaction to the creditor in question.\n\n\
             3. Receivable Scan Interval: Amount of seconds between two sequential cycles of scanning for payments on the \
             blockchain that have been sent by our creditors to us, which are credited against receivables recorded for services \
             provided."
        )
    }

    #[test]
    fn validate_private_key_requires_a_key_that_is_64_characters_long() {
        let result = common_validators::validate_private_key(String::from("42"));

        assert_eq!(Err("42".to_string()), result);
    }

    #[test]
    fn validate_private_key_must_contain_only_hex_characters() {
        let result = common_validators::validate_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex",
        ));

        assert_eq!(
            Err("cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex".to_string()),
            result
        );
    }

    #[test]
    fn validate_private_key_handles_happy_path() {
        let result = common_validators::validate_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_ip_address_given_invalid_input() {
        assert_eq!(
            Err(String::from("not-a-valid-IP")),
            common_validators::validate_ip_address(String::from("not-a-valid-IP")),
        );
    }

    #[test]
    fn validate_ip_address_given_valid_input() {
        assert_eq!(
            Ok(()),
            common_validators::validate_ip_address(String::from("1.2.3.4"))
        );
    }

    #[test]
    fn validate_ui_port_complains_about_non_numeric_ui_port() {
        let result = common_validators::validate_ui_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn validate_ui_port_complains_about_ui_port_too_low() {
        let result = common_validators::validate_ui_port(String::from("1023"));

        assert_eq!(Err(String::from("1023")), result);
    }

    #[test]
    fn validate_ui_port_complains_about_ui_port_too_high() {
        let result = common_validators::validate_ui_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn validate_ui_port_works() {
        let result = common_validators::validate_ui_port(String::from("5335"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_badly_formatted_port_number() {
        let result = common_validators::validate_clandestine_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_low() {
        let result = common_validators::validate_clandestine_port(String::from("1024"));

        assert_eq!(Err(String::from("1024")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_high() {
        let result = common_validators::validate_clandestine_port(String::from("65536"));

        assert_eq!(result, Err(String::from("65536")));
    }

    #[test]
    fn validate_clandestine_port_accepts_port_if_provided() {
        let result = common_validators::validate_clandestine_port(String::from("4567"));

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn validate_gas_price_zero() {
        let result = common_validators::validate_gas_price("0".to_string());

        assert_eq!(result, Err(String::from("0")));
    }

    #[test]
    fn validate_gas_price_normal() {
        let result = common_validators::validate_gas_price("2".to_string());

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn validate_gas_price_max() {
        let max = 0xFFFFFFFFFFFFFFFFu64;
        let max_string = max.to_string();
        let result = common_validators::validate_gas_price(max_string);
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_not_digits_fails() {
        let result = common_validators::validate_gas_price("not".to_string());

        assert_eq!(result, Err(String::from("not")));
    }

    #[test]
    fn validate_gas_price_hex_fails() {
        let result = common_validators::validate_gas_price("0x0".to_string());

        assert_eq!(result, Err(String::from("0x0")));
    }

    #[test]
    fn validate_separate_u64_values_happy_path() {
        let result = common_validators::validate_separate_u64_values("4567|1111|444".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_separate_u64_values_sad_path_with_non_numeric_values() {
        let result = common_validators::validate_separate_u64_values("4567|foooo|444".to_string());

        assert_eq!(
            result,
            Err(String::from(
                "Supply positive numeric values separated by vertical bars like 111|222|333|..."
            ))
        )
    }

    #[test]
    fn validate_separate_u64_values_sad_path_bad_delimiters_generally() {
        let result = common_validators::validate_separate_u64_values("4567,555,444".to_string());

        assert_eq!(
            result,
            Err(String::from(
                "Supply positive numeric values separated by vertical bars like 111|222|333|..."
            ))
        )
    }

    #[test]
    fn validate_separate_u64_values_sad_path_bad_delimiters_at_the_end() {
        let result = common_validators::validate_separate_u64_values("|4567|5555|444".to_string());

        assert_eq!(
            result,
            Err(String::from(
                "Supply positive numeric values separated by vertical bars like 111|222|333|..."
            ))
        )
    }

    #[test]
    fn validate_non_zero_u16_happy_path() {
        let result = validate_non_zero_u16("456".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_non_zero_u16_sad_path_with_zero() {
        let result = validate_non_zero_u16("0".to_string());

        assert_eq!(result, Err("0".to_string()))
    }

    #[test]
    fn validate_non_zero_u16_sad_path_with_negative() {
        let result = validate_non_zero_u16("-123".to_string());

        assert_eq!(result, Err("-123".to_string()))
    }

    #[test]
    fn validate_non_zero_u16_too_big() {
        let result = validate_non_zero_u16("65536".to_string());

        assert_eq!(result, Err("65536".to_string()))
    }

    #[test]
    fn validate_non_zero_u16_sad_path_just_junk() {
        let result = validate_non_zero_u16("garbage".to_string());

        assert_eq!(result, Err("garbage".to_string()))
    }

    #[test]
    fn official_chain_names_are_reliable() {
        let expected_supported_chains = [
            Chain::PolyMainnet,
            Chain::EthMainnet,
            Chain::BaseMainnet,
            Chain::BaseSepolia,
            Chain::PolyAmoy,
            Chain::EthRopsten,
            Chain::Dev,
        ]
        .into_iter()
        .collect::<HashSet<Chain>>();

        let chain_names_recognizable_by_clap = official_chain_names();

        let chains_from_clap = chain_names_recognizable_by_clap
            .into_iter()
            .map(|chain_name| Chain::from(*chain_name))
            .collect::<HashSet<Chain>>();
        let differences = chains_from_clap
            .symmetric_difference(&expected_supported_chains)
            .collect::<Vec<&Chain>>();
        assert!(
            differences.is_empty(),
            "There are differences in the Clap schema in the collection of supported chains, \
        between the expected values {:?} and actual {:?}, specifically {:?}",
            expected_supported_chains,
            chains_from_clap,
            differences
        );
    }
}
