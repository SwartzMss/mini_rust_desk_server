use flexi_logger::*;
use mini_rust_desk_common::{log,ResultType};
use mini_rust_desk_server::start_server;

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("debug")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    log::info!("id={}", mini_rust_desk_common::config::Config::get_id());
    crate::start_server();
    Ok(())
}