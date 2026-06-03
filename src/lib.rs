extern crate core;


mod log;
mod args;
mod tcp;
mod context;

pub use args::Args;
use crate::context::CliResult;

pub async fn cli_run(args: Args) -> CliResult {
    if args.tcp {
        tcp::tcp_run(args).await
    }
    else {
        pingora_run(args).await
    }
}



async fn pingora_run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("pingora TODO");

    Ok(())
}