use std::env;
use std::process;

use crate::config::Config;

use getopts::Options;

pub fn parse_args(name: &str) -> Option<Config> {
    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("c", "", "configuration path", "config");
    opts.optflag("h", "help", "print this help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            print!("{}", opts.usage(&format!("Usage: {} -c PATH", name)));
            return None;
        }
    };

    if matches.opt_present("h") {
        print!("{}", opts.usage(&format!("Usage: {} -c PATH", name)));
        process::exit(0);
    }

    let path = matches.opt_str("c").unwrap_or_default();
    match Config::new(path) {
        Ok(c) => Some(c),
        Err(e) => {
            log::error!("{}", e);
            None
        }
    }
}
