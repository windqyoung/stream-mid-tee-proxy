use clap::Parser;
use stream_mid_tee_proxy::{cli_run, Args};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    cli_run(args)
}
