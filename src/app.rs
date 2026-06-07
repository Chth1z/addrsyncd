use crate::cli::{CleanupMode, Cli, Command, parse_args};
use crate::config::Options;
use crate::control;
use crate::daemon::service::{self, CleanupSource};
use crate::error::AppError;
use crate::logger::Logger;

pub(crate) fn run_main<I, T>(args: I) -> Result<(), AppError>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = parse_args(args)?;
    run_cli(cli)
}

fn run_cli(cli: Cli) -> Result<(), AppError> {
    let (paths, command) = cli.into_parts();
    match command {
        Command::Run { daemon } => {
            let ready_fd = control::take_ready_fd_from_env();
            let opts = Options::load(&paths.config, &paths.work_dir)?;
            if daemon {
                return control::start_background(&opts);
            }
            let logger = Logger::new(&opts)?;
            let mut daemon = service::Daemon::new(opts, logger)?;
            daemon.run(ready_fd)
        }
        Command::Stop => crate::control::stop_background(&paths.work_dir),
        Command::Resync => crate::control::signal_resync(&paths.work_dir),
        Command::Cleanup { mode } => {
            let opts = Options::load(&paths.config, &paths.work_dir)?;
            let logger = Logger::new(&opts)?;
            let source = match mode {
                CleanupMode::Tracked => CleanupSource::Tracked,
                CleanupMode::Dump => CleanupSource::Dump,
            };
            service::cleanup_once(opts, logger, source)
        }
        Command::Pbr { request } => crate::netlink::pbr::run_request(request),
        Command::Status => crate::control::print_status(&paths.config, &paths.work_dir),
    }
}
