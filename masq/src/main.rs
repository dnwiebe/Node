// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io;
use masq_cli_lib::run_modes::Main;

fn main() {
    // let mut streams: StdStreams<'_> = StdStreams {
    //     stdin: &mut io::stdin(),
    //     stdout: &mut io::stdout(),
    //     stderr: &mut io::stderr(),
    // };

    let args: Vec<String> = std::env::args().collect();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to build a Runtime");

    let exit_code = rt.block_on(Main::default().go(&args));
    ::std::process::exit(i32::from(exit_code));
}
