use std::{env, fs, path::PathBuf};

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to find protoc");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR env var not set"));
    let generated_proto_dir = out_dir.join("proto_schemas");
    let generated_vc_path = generated_proto_dir.join("vc.rs");
    let module_shim_path = out_dir.join("proto_schemas_module.rs");

    println!("cargo:rerun-if-changed=src/proto_schemas/vc.proto");

    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc)
        .include("src/proto_schemas")
        .input("src/proto_schemas/vc.proto")
        .cargo_out_dir("proto_schemas")
        .run_from_script();

    let generated_vc_literal = format!("{:?}", generated_vc_path.to_string_lossy());
    fs::write(
        module_shim_path,
        format!("#[path = {generated_vc_literal}]\npub mod vc;\n"),
    )
    .expect("failed to write protobuf module shim");
}
