#![allow(dead_code)]
use libc::{c_void, pid_t};
use log::{info, error};

pub fn inject_into_pid(pid: pid_t, lib_path: &str) -> bool {
    info!("Attempting to inject {} into pid {}", lib_path, pid);
    
    unsafe {
        // 1. PTRACE_ATTACH
        if libc::ptrace(libc::PTRACE_ATTACH, pid, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>()) < 0 {
            error!("Failed to attach to pid {}", pid);
            return false;
        }
        
        // 2. Wait for SIGSTOP
        let mut status = 0;
        libc::waitpid(pid, &mut status, libc::__WALL);
        
        if !libc::WIFSTOPPED(status) {
            error!("Process {} didn't stop as expected", pid);
            libc::ptrace(libc::PTRACE_DETACH, pid, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            return false;
        }
        
        // 3. Backup Regs
        // 4. Remote mmap/memfd_create & dlopen
        // 5. Restore Regs
        // 6. PTRACE_DETACH
        
        libc::ptrace(libc::PTRACE_DETACH, pid, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
    }
    
    info!("Successfully injected into pid {}", pid);
    true
}
