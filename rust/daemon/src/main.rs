#![allow(unused)]
use log::{debug, error, info};
use shared::logging::init_logger;
use std::os::unix::process::CommandExt;

mod injector;
mod netlink;

fn main() {
    init_logger("CleveresTrickyDaemon");
    info!("Starting CleveresTricky Rust Native Daemon...");

    // Anti-debug checks
    if check_debugger() {
        error!("Debugger detected. Exiting.");
        std::process::exit(1);
    }

    // Set process name
    unsafe {
        libc::prctl(
            libc::PR_SET_NAME,
            c"kworker/u0:0-events".as_ptr() as *const libc::c_char,
        );
    }

    // Start Netlink Process Connector monitoring
    if let Err(e) = netlink::start_monitoring() {
        error!("Netlink monitoring failed: {:?}", e);
        std::process::exit(1);
    }
}

fn check_debugger() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(stripped) = line.strip_prefix("TracerPid:") {
            if let Ok(pid) = stripped.trim().parse::<i32>() {
                if pid != 0 {
                    return true;
                }
            }
        }
    }
    false
}
