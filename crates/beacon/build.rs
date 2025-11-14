use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../src");
    println!("cargo:rerun-if-changed=../../rsbuild.config.ts");
    println!("cargo:rerun-if-changed=../../package.json");

    // 使用 which 查找 pnpm 可执行文件
    let pnpm_path = which::which("pnpm")
        .expect("pnpm executable not found in PATH. Please ensure pnpm is installed and available in your PATH.");

    println!(
        "cargo:warning=Building frontend with pnpm at {:?}...",
        pnpm_path
    );

    let status = Command::new(&pnpm_path)
        .arg("build")
        .current_dir("../../") // 在项目根目录执行
        .status()
        .expect("Failed to execute pnpm build");

    if !status.success() {
        panic!("pnpm build failed with exit code: {:?}", status.code());
    }

    println!("cargo:warning=Frontend build completed successfully");
}
