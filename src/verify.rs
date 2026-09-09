//! minisign signature verification over the downloaded update package.

use std::path::Path;

/// `tauri signer sign` emits the .sig as base64(minisign armor) — a single
/// line of base64. Plain minisign armor (starts with "untrusted comment")
/// is accepted as-is so hand-signed packages also work.
fn normalize_signature(raw: &str) -> Result<String, String> {
    if raw.trim_start().starts_with("untrusted comment") {
        return Ok(raw.to_string());
    }
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| format!("signature is neither minisign armor nor base64: {e}"))?;
    String::from_utf8(decoded).map_err(|e| format!("decoded signature is not utf-8: {e}"))
}

pub fn verify_package(package: &Path, signature: &Path, public_key: &str) -> Result<(), String> {
    let sig_data = std::fs::read_to_string(signature)
        .map_err(|e| format!("cannot read signature {}: {e}", signature.display()))?;
    let sig_text = normalize_signature(&sig_data)?;
    let pk = minisign_verify::PublicKey::decode(public_key)
        .map_err(|e| format!("embedded public key invalid: {e}"))?;
    let sig = minisign_verify::Signature::decode(&sig_text)
        .map_err(|e| format!("signature malformed: {e}"))?;
    let data = std::fs::read(package)
        .map_err(|e| format!("cannot read package {}: {e}", package.display()))?;
    pk.verify(&data, &sig, false)
        .map_err(|e| format!("minisign verify: {e}"))
}
