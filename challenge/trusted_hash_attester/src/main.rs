mod config;
mod crypto;
mod flow;
mod pcr;
mod tpm;
mod util;
mod verify;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    flow::run(config::Config::from_args()?)
}
