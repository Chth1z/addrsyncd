use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::error::AppError;

pub(crate) const DEFAULT_CONFIG_FILE: &str = "addrsyncd.toml";
pub(crate) const DEFAULT_WORK_DIR: &str = ".";

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) config: PathBuf,
    pub(crate) work_dir: PathBuf,
    pub(crate) command: Command,
}

#[derive(Debug)]
pub(crate) enum Command {
    Run { daemon: bool },
    Stop,
    Resync,
    Cleanup { mode: CleanupMode },
    Pbr { request: PbrRequest },
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupMode {
    Tracked,
    Dump,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PbrAction {
    Apply,
    Cleanup,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PbrFamily {
    Ipv4,
    Ipv6,
}

impl PbrFamily {
    pub(crate) fn as_i32(self) -> i32 {
        match self {
            Self::Ipv4 => libc::AF_INET,
            Self::Ipv6 => libc::AF_INET6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PbrRequest {
    pub(crate) action: PbrAction,
    pub(crate) family: PbrFamily,
    pub(crate) mark: u32,
    pub(crate) mask: u32,
    pub(crate) table: u32,
    pub(crate) pref: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimePaths {
    pub(crate) config: PathBuf,
    pub(crate) work_dir: PathBuf,
}

impl Cli {
    pub(crate) fn into_parts(self) -> (RuntimePaths, Command) {
        (
            RuntimePaths {
                config: self.config,
                work_dir: self.work_dir,
            },
            self.command,
        )
    }
}

pub(crate) fn parse_args<I, T>(args: I) -> Result<Cli, AppError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(|a| a.into()).collect();

    let mut config = PathBuf::from(DEFAULT_CONFIG_FILE);
    let mut work_dir = PathBuf::from(DEFAULT_WORK_DIR);
    let mut i = 1;

    while i < args.len() {
        if arg_is(&args[i], "-c") || arg_is(&args[i], "--config") {
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| AppError::message("-c/--config requires a value"))?;
            config = PathBuf::from(value);
            i += 1;
        } else if arg_is(&args[i], "-d") || arg_is(&args[i], "--work-dir") {
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| AppError::message("-d/--work-dir requires a value"))?;
            work_dir = PathBuf::from(value);
            i += 1;
        } else if arg_is(&args[i], "-h") || arg_is(&args[i], "--help") {
            print_usage();
            std::process::exit(0);
        } else if arg_is(&args[i], "-v") || arg_is(&args[i], "--version") {
            println!("addrsyncd {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        } else {
            break;
        }
    }

    let sub = args
        .get(i)
        .ok_or_else(|| AppError::message("subcommand required (run|stop|resync|cleanup|pbr|status)"))?;
    i += 1;

    let command = if arg_is(sub, "run") {
        parse_run_command(&args, &mut i)?
    } else if arg_is(sub, "stop") {
        if i < args.len() {
            return Err(AppError::message(format!(
                "stop: unknown option '{}'",
                render_arg(&args[i])
            )));
        }
        Command::Stop
    } else if arg_is(sub, "resync") {
        if i < args.len() {
            return Err(AppError::message(format!(
                "resync: unknown option '{}'",
                render_arg(&args[i])
            )));
        }
        Command::Resync
    } else if arg_is(sub, "cleanup") {
        parse_cleanup_command(&args, &mut i)?
    } else if arg_is(sub, "pbr") {
        parse_pbr_command(&args, &mut i)?
    } else if arg_is(sub, "status") {
        if i < args.len() {
            return Err(AppError::message(format!(
                "status: unknown option '{}'",
                render_arg(&args[i])
            )));
        }
        Command::Status
    } else {
        return Err(AppError::message(format!(
            "unknown subcommand '{}' (expected run|stop|resync|cleanup|pbr|status)",
            render_arg(sub)
        )));
    };

    Ok(Cli {
        config,
        work_dir,
        command,
    })
}

fn parse_run_command(args: &[OsString], i: &mut usize) -> Result<Command, AppError> {
    let mut daemon = false;
    while *i < args.len() {
        if arg_is(&args[*i], "--daemon") {
            daemon = true;
        } else if arg_is(&args[*i], "-h") || arg_is(&args[*i], "--help") {
            print_run_usage();
            std::process::exit(0);
        } else {
            return Err(AppError::message(format!(
                "run: unknown option '{}'",
                render_arg(&args[*i])
            )));
        }
        *i += 1;
    }
    Ok(Command::Run { daemon })
}

fn parse_cleanup_command(args: &[OsString], i: &mut usize) -> Result<Command, AppError> {
    let mut mode = CleanupMode::Dump;
    while *i < args.len() {
        if arg_is(&args[*i], "--mode") {
            *i += 1;
            let value = args.get(*i).ok_or_else(|| {
                AppError::message("cleanup: --mode requires a value (tracked|dump)")
            })?;
            if arg_is(value, "tracked") {
                mode = CleanupMode::Tracked;
            } else if arg_is(value, "dump") {
                mode = CleanupMode::Dump;
            } else {
                return Err(AppError::message(format!(
                    "cleanup: unknown mode '{}' (expected tracked|dump)",
                    render_arg(value)
                )));
            }
        } else if arg_is(&args[*i], "-h") || arg_is(&args[*i], "--help") {
            print_cleanup_usage();
            std::process::exit(0);
        } else {
            return Err(AppError::message(format!(
                "cleanup: unknown option '{}'",
                render_arg(&args[*i])
            )));
        }
        *i += 1;
    }
    Ok(Command::Cleanup { mode })
}

fn parse_pbr_command(args: &[OsString], i: &mut usize) -> Result<Command, AppError> {
    let action_arg = args
        .get(*i)
        .ok_or_else(|| AppError::message("pbr: action required (apply|cleanup|status)"))?;
    *i += 1;

    let action = if arg_is(action_arg, "apply") {
        PbrAction::Apply
    } else if arg_is(action_arg, "cleanup") {
        PbrAction::Cleanup
    } else if arg_is(action_arg, "status") {
        PbrAction::Status
    } else if arg_is(action_arg, "-h") || arg_is(action_arg, "--help") {
        print_pbr_usage();
        std::process::exit(0);
    } else {
        return Err(AppError::message(format!(
            "pbr: unknown action '{}' (expected apply|cleanup|status)",
            render_arg(action_arg)
        )));
    };

    let mut family: Option<PbrFamily> = None;
    let mut mark: Option<u32> = None;
    let mut mask: Option<u32> = None;
    let mut table: Option<u32> = None;
    let mut pref: Option<u32> = None;

    while *i < args.len() {
        if arg_is(&args[*i], "--family") {
            *i += 1;
            family = Some(parse_pbr_family(next_required(args, *i, "pbr: --family requires a value (4|6)")?)?);
        } else if arg_is(&args[*i], "--mark") {
            *i += 1;
            mark = Some(parse_u32_arg(next_required(args, *i, "pbr: --mark requires a value")?, "pbr: invalid --mark")?);
        } else if arg_is(&args[*i], "--mask") {
            *i += 1;
            mask = Some(parse_u32_arg(next_required(args, *i, "pbr: --mask requires a value")?, "pbr: invalid --mask")?);
        } else if arg_is(&args[*i], "--table") {
            *i += 1;
            table = Some(parse_u32_arg(next_required(args, *i, "pbr: --table requires a value")?, "pbr: invalid --table")?);
        } else if arg_is(&args[*i], "--pref") {
            *i += 1;
            pref = Some(parse_u32_arg(next_required(args, *i, "pbr: --pref requires a value")?, "pbr: invalid --pref")?);
        } else if arg_is(&args[*i], "-h") || arg_is(&args[*i], "--help") {
            print_pbr_usage();
            std::process::exit(0);
        } else {
            return Err(AppError::message(format!(
                "pbr: unknown option '{}'",
                render_arg(&args[*i])
            )));
        }
        *i += 1;
    }

    let request = PbrRequest {
        action,
        family: family.ok_or_else(|| AppError::message("pbr: --family is required"))?,
        mark: mark.ok_or_else(|| AppError::message("pbr: --mark is required"))?,
        mask: mask.ok_or_else(|| AppError::message("pbr: --mask is required"))?,
        table: table.ok_or_else(|| AppError::message("pbr: --table is required"))?,
        pref: pref.ok_or_else(|| AppError::message("pbr: --pref is required"))?,
    };
    if request.mask == 0 {
        return Err(AppError::message("pbr: --mask must be non-zero"));
    }
    if request.table == 0 || request.pref == 0 {
        return Err(AppError::message("pbr: --table and --pref must be positive"));
    }

    Ok(Command::Pbr { request })
}

fn next_required<'a>(args: &'a [OsString], i: usize, msg: &str) -> Result<&'a OsString, AppError> {
    args.get(i).ok_or_else(|| AppError::message(msg))
}

fn parse_pbr_family(arg: &OsString) -> Result<PbrFamily, AppError> {
    if arg_is(arg, "4") || arg_is(arg, "ipv4") {
        Ok(PbrFamily::Ipv4)
    } else if arg_is(arg, "6") || arg_is(arg, "ipv6") {
        Ok(PbrFamily::Ipv6)
    } else {
        Err(AppError::message(format!(
            "pbr: invalid --family '{}' (expected 4|6)",
            render_arg(arg)
        )))
    }
}

fn parse_u32_arg(arg: &OsString, msg: &str) -> Result<u32, AppError> {
    let raw = render_arg(arg);
    let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        raw.parse::<u32>()
    };
    parsed.map_err(|_| AppError::message(format!("{msg}: {raw}")))
}

fn arg_is(arg: &OsString, expected: &str) -> bool {
    arg == OsStr::new(expected)
}

fn render_arg(arg: &OsString) -> String {
    arg.to_string_lossy().into_owned()
}

fn print_usage() {
    println!(
        "addrsyncd {} - Address to ip-rule sync daemon\n\
         \n\
         USAGE:\n\
           addrsyncd [OPTIONS] <COMMAND>\n\
         \n\
         OPTIONS:\n\
           -c, --config <PATH>    Config file [default: {}]\n\
           -d, --work-dir <PATH>  Working directory [default: {}]\n\
           -h, --help             Show this help\n\
           -v, --version          Show version\n\
         \n\
         COMMANDS:\n\
           run [--daemon]                   Start the daemon\n\
           stop                             Stop a running daemon\n\
           resync                           Signal a full resync\n\
           cleanup [--mode tracked|dump]    Cleanup stale rules\n\
           pbr <apply|cleanup|status> ...   Manage Flux policy routing\n\
           status                           Print daemon status",
        env!("CARGO_PKG_VERSION"),
        DEFAULT_CONFIG_FILE,
        DEFAULT_WORK_DIR
    );
}

fn print_run_usage() {
    println!(
        "USAGE:\n  addrsyncd [OPTIONS] run [--daemon]\n\
         \n\
         OPTIONS:\n  --daemon    Start in background mode"
    );
}

fn print_cleanup_usage() {
    println!(
        "USAGE:\n  addrsyncd [OPTIONS] cleanup [--mode tracked|dump]\n\
         \n\
         OPTIONS:\n  --mode <tracked|dump>    Cleanup source mode (default: dump)"
    );
}

fn print_pbr_usage() {
    println!(
        "USAGE:\n  addrsyncd [OPTIONS] pbr <apply|cleanup|status> --family <4|6> --mark <MARK> --mask <MASK> --table <ID> --pref <PREF>\n\
         \n\
         OPTIONS:\n  --family <4|6>    Address family\n  --mark <MARK>     fwmark value (decimal or 0x hex)\n  --mask <MASK>     fwmark mask (decimal or 0x hex)\n  --table <ID>      Routing table id\n  --pref <PREF>     Rule priority"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_run_with_global_paths_and_daemon() {
        let cli = parse_args([
            "addrsyncd",
            "-c",
            "conf/addrsyncd.toml",
            "-d",
            "/data/local/tmp",
            "run",
            "--daemon",
        ])
        .expect("parse");

        assert_eq!(cli.config, PathBuf::from("conf/addrsyncd.toml"));
        assert_eq!(cli.work_dir, PathBuf::from("/data/local/tmp"));
        match cli.command {
            Command::Run { daemon } => assert!(daemon),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parse_cleanup_mode_default_is_dump() {
        let cli = parse_args(["addrsyncd", "cleanup"]).expect("parse");
        match cli.command {
            Command::Cleanup { mode } => assert_eq!(mode, CleanupMode::Dump),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parse_cleanup_mode_tracked() {
        let cli = parse_args(["addrsyncd", "cleanup", "--mode", "tracked"]).expect("parse");
        match cli.command {
            Command::Cleanup { mode } => assert_eq!(mode, CleanupMode::Tracked),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parse_stop_uses_default_work_dir() {
        let cli = parse_args(["addrsyncd", "stop"]).expect("parse");
        assert_eq!(cli.work_dir, PathBuf::from("."));
        match cli.command {
            Command::Stop => {}
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parse_rejects_unknown_subcommand() {
        let err = parse_args(["addrsyncd", "start"]).expect_err("must fail");
        let rendered = err.to_string();
        assert!(rendered.contains("unknown subcommand"));
        assert!(rendered.contains("start"));
    }

    #[test]
    fn parse_pbr_apply_with_masked_mark() {
        let cli = parse_args([
            "addrsyncd",
            "pbr",
            "apply",
            "--family",
            "4",
            "--mark",
            "0x14",
            "--mask",
            "0xff",
            "--table",
            "2025",
            "--pref",
            "2025",
        ])
        .expect("parse");

        match cli.command {
            Command::Pbr { request } => {
                assert_eq!(request.action, PbrAction::Apply);
                assert_eq!(request.family, PbrFamily::Ipv4);
                assert_eq!(request.mark, 0x14);
                assert_eq!(request.mask, 0xff);
                assert_eq!(request.table, 2025);
                assert_eq!(request.pref, 2025);
            }
            _ => panic!("unexpected command"),
        }
    }
}
