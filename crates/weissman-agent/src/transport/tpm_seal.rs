//! Seal spool IKM with live TPM 2.0 tools (`tpm2-tss` / tpm2-tools).
//!
//! Success is only reported after a real `tpm2_unseal` of 32 bytes. Missing
//! `/dev/tpmrm0` / `/dev/tpm0` or missing `tpm2_*` binaries returns `None` /
//! `false` — this module never fakes a TPM.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PUB_NAME: &str = ".user-7.pub";
const PRIV_NAME: &str = ".user-7.priv";

#[must_use]
pub fn tpm_device_present() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

fn tpm_device_path() -> Option<&'static str> {
    if Path::new("/dev/tpmrm0").exists() {
        Some("/dev/tpmrm0")
    } else if Path::new("/dev/tpm0").exists() {
        Some("/dev/tpm0")
    } else {
        None
    }
}

fn tpm2_tools_available() -> bool {
    Command::new("tpm2_createprimary")
        .arg("-h")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn tpm2(dev: &str, bin: &str, args: &[&str], work: &Path) -> bool {
    Command::new(bin)
        .env("TPM2TOOLS_TCTI", format!("device:{dev}"))
        .current_dir(work)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn work_dir(state_dir: &Path) -> Option<PathBuf> {
    let work = state_dir.join(".tpm-ctx");
    std::fs::create_dir_all(&work).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700));
    }
    Some(work)
}

fn pub_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PUB_NAME)
}

fn priv_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PRIV_NAME)
}

fn wipe(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let n = meta.len() as usize;
        let _ = std::fs::File::create(path).and_then(|mut f| f.write_all(&vec![0u8; n]));
    }
    let _ = std::fs::remove_file(path);
}

/// Unseal the 32-byte IKM previously sealed into `state_dir`.
#[must_use]
pub fn unseal_ikm(state_dir: &Path) -> Option<[u8; 32]> {
    let dev = tpm_device_path()?;
    if !tpm2_tools_available() {
        return None;
    }
    let pub_p = pub_path(state_dir);
    let priv_p = priv_path(state_dir);
    if !pub_p.is_file() || !priv_p.is_file() {
        return None;
    }
    let work = work_dir(state_dir)?;
    let primary = work.join("primary.ctx");
    let key_ctx = work.join("key.ctx");
    let out = work.join("unsealed");
    let _ = std::fs::remove_file(&out);
    if !tpm2(
        dev,
        "tpm2_createprimary",
        &["-C", "o", "-c", "primary.ctx", "-Q"],
        &work,
    ) {
        return None;
    }
    if !tpm2(
        dev,
        "tpm2_load",
        &[
            "-C",
            "primary.ctx",
            "-u",
            pub_p.to_str()?,
            "-r",
            priv_p.to_str()?,
            "-c",
            "key.ctx",
            "-Q",
        ],
        &work,
    ) {
        let _ = std::fs::remove_file(&primary);
        return None;
    }
    if !tpm2(
        dev,
        "tpm2_unseal",
        &["-c", "key.ctx", "-o", "unsealed", "-Q"],
        &work,
    ) {
        let _ = std::fs::remove_file(&primary);
        let _ = std::fs::remove_file(&key_ctx);
        return None;
    }
    let raw = std::fs::read(&out).ok();
    wipe(&out);
    let _ = std::fs::remove_file(&primary);
    let _ = std::fs::remove_file(&key_ctx);
    let raw = raw?;
    if raw.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Some(k)
}

/// Seal `ikm` to the TPM. Returns true only when a subsequent unseal would be
/// possible (objects written). Caller should still `unseal_ikm` to confirm.
#[must_use]
pub fn seal_ikm(state_dir: &Path, ikm: &[u8; 32]) -> bool {
    let Some(dev) = tpm_device_path() else {
        return false;
    };
    if !tpm2_tools_available() {
        return false;
    }
    let Some(work) = work_dir(state_dir) else {
        return false;
    };
    if std::fs::create_dir_all(state_dir).is_err() {
        return false;
    }
    let secret = work.join("secret.bin");
    if std::fs::write(&secret, ikm).is_err() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600));
    }
    let pub_p = pub_path(state_dir);
    let priv_p = priv_path(state_dir);
    let ok = tpm2(
        dev,
        "tpm2_createprimary",
        &["-C", "o", "-c", "primary.ctx", "-Q"],
        &work,
    ) && tpm2(
        dev,
        "tpm2_create",
        &[
            "-C",
            "primary.ctx",
            "-i",
            "secret.bin",
            "-u",
            pub_p.to_str().unwrap_or(""),
            "-r",
            priv_p.to_str().unwrap_or(""),
            "-Q",
        ],
        &work,
    );
    wipe(&secret);
    let _ = std::fs::remove_file(work.join("primary.ctx"));
    if !ok {
        let _ = std::fs::remove_file(&pub_p);
        let _ = std::fs::remove_file(&priv_p);
        return false;
    }
    pub_p.is_file() && priv_p.is_file()
}
