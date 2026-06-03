use crate::Args;

pub(crate) type CliResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone)]
pub(crate) struct Context {
    pub(crate) args: Args,
    pub(crate) req_id: u64,
    pub(crate) log_dir: String,
}

impl Context {
    pub(crate) fn new(args: Args, req_id: u64, log_dir: String) -> Self {
        Self {
            args,
            req_id,
            log_dir,
        }
    }
}


