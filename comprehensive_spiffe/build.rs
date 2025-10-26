fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR").expect("$OUT_DIR")).join("fdset.bin");
    tonic_prost_build::configure()
        .file_descriptor_set_path(fds_path)
        .compile_protos(&["proto/workloadapi.proto"], &["proto"])?;
    Ok(())
}
