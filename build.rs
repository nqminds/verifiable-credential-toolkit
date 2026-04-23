fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to find protoc");

    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc)
        .include("src/proto_schemas")
        .input("src/proto_schemas/vc.proto")
        .out_dir("src/proto_schemas")
        .run_from_script();
}
