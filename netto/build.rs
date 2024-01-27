use std::path::PathBuf;

const SRC: &str = "src/bpf/prog.bpf.c";

fn main() {
    let mut out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    out_dir.push("prog.bpf.rs");
    
    libbpf_cargo::SkeletonBuilder::new()
        .source(SRC)
        .clang_args("-O3")
        .build_and_generate(out_dir)
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}