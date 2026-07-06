extern crate core;


mod log;
mod args;
mod tcp;
mod context;
mod pingora;
mod bid;

pub use args::Args;
use crate::context::CliResult;

pub fn cli_run(args: Args) -> CliResult {
    
    if args.bid {
        bid::bid_run(args)    
    }
    else if args.tcp {
        tcp::tcp_run(args)
    }
    else {
        pingora::pingora_run(args)
    }
}

