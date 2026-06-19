#![allow(dead_code)]

pub mod logging {
    use log::LevelFilter;
    use android_logger::Config;

    pub fn init_logger(tag: &str) {
        android_logger::init_once(
            Config::default()
                .with_tag(tag)
                .with_max_level(LevelFilter::Debug),
        );
    }
}

pub mod process_util {
    pub fn get_process_name(pid: i32) -> Option<String> {
        let path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = std::fs::read_to_string(&path) {
            if let Some(first) = cmdline.split('\0').next() {
                return Some(first.to_string());
            }
        }
        None
    }
}

pub mod hardware_sim;
