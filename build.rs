fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "grpc")]
    let fds_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR").expect("$OUT_DIR")).join("fdset.bin");
    #[cfg(feature = "grpc")]
    tonic_build::configure()
        .file_descriptor_set_path(fds_path)
        .compile_protos(&["proto/test.proto"], &["proto"])?;
    Ok(())
}
