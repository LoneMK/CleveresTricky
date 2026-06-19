use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../patch_rkp.sh");
    println!("cargo:rerun-if-changed=../../service/src/main/java/cleveres/tricky/cleverestech/RkpInterceptor.kt");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = Path::new(&manifest_dir).join("../..").canonicalize().unwrap();
    
    // Instead of using the hacky shell script, we migrate the logic to build.rs
    // For legacy support during migration, we can execute the patch script directly,
    // or we can implement the byte-replacement directly in Rust.
    
    let patch_script = project_root.join("patch_rkp.sh");
    if patch_script.exists() {
        // Run the bash script if we are in a unix environment or bash is available
        // A better approach is translating the python regex replacement directly into this Rust script
        let status = Command::new("bash")
            .arg(patch_script.to_str().unwrap())
            .current_dir(&project_root)
            .status();
            
        if let Ok(s) = status {
            if !s.success() {
                println!("cargo:warning=Failed to apply patch_rkp.sh");
            }
        }
    }
}
