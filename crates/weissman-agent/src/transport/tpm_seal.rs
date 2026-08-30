//! Seal spool IKM with the native TPM 2.0 ESAPI (`tss-esapi`).
//!
//! Success is only reported after a real ESAPI `unseal` of 32 bytes. Missing
//! `/dev/tpmrm0` / `/dev/tpm0`, a musl build (no `libtss2`), or ESAPI failure
//! returns `None` / `false` — this module never fakes a TPM and never shells
//! out to `tpm2-tools`.

use std::io::Write;
use std::path::{Path, PathBuf};

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
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        esapi::unseal_ikm(state_dir, tpm_device_path()?)
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = state_dir;
        None
    }
}

/// Seal `ikm` to the TPM. Returns true only when a subsequent unseal would be
/// possible (objects written). Caller should still `unseal_ikm` to confirm.
#[must_use]
pub fn seal_ikm(state_dir: &Path, ikm: &[u8; 32]) -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let Some(dev) = tpm_device_path() else {
            return false;
        };
        esapi::seal_ikm(state_dir, ikm, dev)
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = (state_dir, ikm);
        false
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod esapi {
    use super::{priv_path, pub_path, wipe};
    use std::convert::TryFrom;
    use std::path::Path;
    use std::str::FromStr;
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::handles::ObjectHandle;
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
    use tss_esapi::interface_types::resource_handles::Hierarchy;
    use tss_esapi::structures::{
        Digest, KeyedHashScheme, Private, Public, PublicBuilder, PublicKeyedHashParameters,
        SensitiveData, SymmetricCipherParameters, SymmetricDefinitionObject,
    };
    use tss_esapi::traits::{Marshall, UnMarshall};
    use tss_esapi::{Context, TctiNameConf};

    fn open_context(dev: &str) -> Option<Context> {
        // Device path is only `/dev/tpmrm0` or `/dev/tpm0` from our own check.
        // Never honor a host TCTI env var — that would be injection surface.
        let tcti = TctiNameConf::from_str(&format!("device:{dev}")).ok()?;
        Context::new(tcti).ok()
    }

    fn primary_public() -> Option<Public> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .ok()?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                SymmetricDefinitionObject::AES_128_CFB,
            ))
            .with_symmetric_cipher_unique_identifier(Digest::default())
            .build()
            .ok()
    }

    fn sealed_public() -> Option<Public> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_user_with_auth(true)
            .build()
            .ok()?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .ok()
    }

    fn write_0600(path: &Path, bytes: &[u8]) -> bool {
        if let Some(dir) = path.parent() {
            if std::fs::create_dir_all(dir).is_err() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        if std::fs::write(path, bytes).is_err() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        true
    }

    pub(super) fn seal_ikm(state_dir: &Path, ikm: &[u8; 32], dev: &str) -> bool {
        let Some(mut context) = open_context(dev) else {
            return false;
        };
        let Some(primary_pub) = primary_public() else {
            return false;
        };
        let Some(sealed_pub) = sealed_public() else {
            return false;
        };
        let Ok(sensitive) = SensitiveData::try_from(ikm.to_vec()) else {
            return false;
        };
        let created = context.execute_with_nullauth_session(|ctx| {
            let primary = ctx.create_primary(
                Hierarchy::Owner,
                primary_pub.clone(),
                None,
                None,
                None,
                None,
            )?;
            let child = ctx.create(
                primary.key_handle,
                sealed_pub.clone(),
                None,
                Some(sensitive),
                None,
                None,
            )?;
            let _ = ctx.flush_context(ObjectHandle::from(primary.key_handle));
            Ok::<_, tss_esapi::Error>((child.out_private, child.out_public))
        });
        let Ok((private, public)) = created else {
            return false;
        };
        let Ok(pub_bytes) = public.marshall() else {
            return false;
        };
        let priv_bytes = private.to_vec();
        let pub_p = pub_path(state_dir);
        let priv_p = priv_path(state_dir);
        if !write_0600(&pub_p, &pub_bytes) || !write_0600(&priv_p, &priv_bytes) {
            wipe(&pub_p);
            wipe(&priv_p);
            return false;
        }
        pub_p.is_file() && priv_p.is_file()
    }

    pub(super) fn unseal_ikm(state_dir: &Path, dev: &str) -> Option<[u8; 32]> {
        let pub_p = pub_path(state_dir);
        let priv_p = priv_path(state_dir);
        let pub_bytes = std::fs::read(&pub_p).ok()?;
        let priv_bytes = std::fs::read(&priv_p).ok()?;
        let public = Public::unmarshall(&pub_bytes).ok()?;
        let private = Private::try_from(priv_bytes).ok()?;
        let mut context = open_context(dev)?;
        let Some(primary_pub) = primary_public() else {
            return None;
        };
        let opened = context.execute_with_nullauth_session(|ctx| {
            let primary = ctx.create_primary(
                Hierarchy::Owner,
                primary_pub.clone(),
                None,
                None,
                None,
                None,
            )?;
            let loaded = ctx.load(primary.key_handle, private.clone(), public.clone())?;
            let data = ctx.unseal(ObjectHandle::from(loaded))?;
            let _ = ctx.flush_context(ObjectHandle::from(loaded));
            let _ = ctx.flush_context(ObjectHandle::from(primary.key_handle));
            Ok::<_, tss_esapi::Error>(data)
        });
        let data = opened.ok()?;
        let raw = data.as_slice();
        if raw.len() != 32 {
            return None;
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(raw);
        Some(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_invokes_host_tpm2_cli() {
        let src = include_str!("tpm_seal.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(
            !prod.contains("std::process"),
            "native ESAPI must not spawn a host process"
        );
        assert!(!prod.contains("TPM2TOOLS"));
        assert!(prod.contains("tss_esapi"));
        let _ = tpm_device_present();
    }
}
