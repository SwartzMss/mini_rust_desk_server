use flexi_logger::*;
use mini_rust_desk_common::{log,ResultType};
use mini_rust_desk_server::*;

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("debug")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    parse_and_init_params();
    log::info!("id={}", mini_rust_desk_common::config::Config::get_id());
    log::info!("rendezvous-server={}", get_arg("rendezvous-server"));
    log::info!("relay-server={}", get_arg("relay-server"));
    log::info!("key={}", get_arg("key"));
    crate::start_server();
    Ok(())
}