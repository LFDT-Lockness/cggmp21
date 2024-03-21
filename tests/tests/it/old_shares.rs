static OLD_SHARES: include_dir::Dir =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../test-data/old-shares");

#[test]
fn deserialize_old_shares() {
    for share in OLD_SHARES.files() {
        let file_name = share
            .path()
            .file_name()
            .expect("share doesn't have file name")
            .to_str()
            .expect("share name is not valid utf8");

        if file_name == "README.md" {
            continue;
        } else if file_name.contains("secp256k1") {
            deserialize_old_share_on_curve::<cggmp21::supported_curves::Secp256k1>(share);
        } else if file_name.contains("secp256r1") {
            deserialize_old_share_on_curve::<cggmp21::supported_curves::Secp256r1>(share);
        } else if file_name.contains("stark") {
            deserialize_old_share_on_curve::<cggmp21::supported_curves::Stark>(share);
        } else {
            panic!("couldn't figure out the curve from the share name {file_name}")
        }
    }
}

fn deserialize_old_share_on_curve<E: generic_ec::Curve>(share: &include_dir::File) {
    let ext = share
        .path()
        .extension()
        .expect("share file name doesn't have extension")
        .to_str()
        .expect("key share ext is not valid utf8");

    let _: cggmp21::IncompleteKeyShare<E> = match ext {
        "json" => serde_json::from_slice(share.contents()).expect("deserialize share"),
        "cbor" => {
            let bytes =
                hex::decode(share.contents()).expect("cbor key share has invalid hex encoding");
            ciborium::from_reader(bytes.as_slice()).expect("deserialize share")
        }
        _ => panic!("unknown extension {ext}"),
    };
}
