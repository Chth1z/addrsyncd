#[cfg(not(any(target_os = "linux", target_os = "android")))]
compile_error!("addrsyncd only supports linux/android");

mod app;
mod cli;
mod config;
mod control;
mod daemon;
mod error;
mod ip_key;
mod kernel;
mod logger;
mod netlink;

fn main() {
    if let Err(err) = app::run_main(std::env::args_os()) {
        eprintln!("addrsyncd: {err}");
        std::process::exit(1);
    }
}
