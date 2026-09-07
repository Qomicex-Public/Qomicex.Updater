//! minisign signature verification over the downloaded update package.

use std::path::Path;

pub fn verify_package(package: &Path, signature: &Path, public_key: &str) -> Result<(), String> {
    let sig_data = std::fs::read_to_string(signature)
        .map_err(|e| format!("cannot read signature {}: {e}", signature.display()))?;
    let pk = minisign_verify::PublicKey::decode(public_key)
        .map_err(|e| format!("embedded public key invalid: {e}"))?;
    let sig = minisign_verify::Signature::decode(&sig_data)
        .map_err(|e| format!("signature malformed: {e}"))?;
    let data = std::fs::read(package)
        .map_err(|e| format!("cannot read package {}: {e}", package.display()))?;
    pk.verify(&data, &sig, false)
        .map_err(|e| format!("minisign verify: {e}"))
}
