fn build_windows() {
    let file = "src/platform/windows.cc";
    cc::Build::new().file(file).compile("windows");
    println!("cargo:rustc-link-lib=WtsApi32");
    println!("cargo:rerun-if-changed={}", file);
}

fn main() {
    build_windows();
    println!("cargo:rerun-if-changed=build.rs");
}