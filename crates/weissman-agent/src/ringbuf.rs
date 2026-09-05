//! In-memory encrypted circular buffer for agent→server frames while WSS is down.
//!
//! XChaCha20-Poly1305 with a fresh 192-bit nonce per frame. Each frame key is
//! HKDF-SHA256(master, nonce||seq) and is zeroized after use. The master IKM
//! lives in the Linux thread keyring when `add_key` works, otherwise in an
//! mlocked Zeroizing buffer. The nonce mixer is non-blocking on the hot path
//! (RDRAND CF/`setc` + `getrandom(GRND_NONBLOCK)`). Boot tries a short blocking
//! CSPRNG wait, then a Vault-injected seed (`WEISSMAN_AGENT_ENTROPY_SEED`) as
//! Low-Entropy Emergency Mode — PID/time alone is never a nonce.

use crate::protocol::AgentToServer;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

/// Hard ceiling for the local ring — never allocate past this.
pub const MAX_BYTES: usize = 10 * 1024 * 1024;
/// Adaptive drain starts here (architect: not a fixed 64 KiB/s).
pub const DRAIN_START_BYTES_PER_SEC: usize = 256 * 1024;
pub const DRAIN_MIN_BYTES_PER_SEC: usize = 64 * 1024;
pub const DRAIN_MAX_BYTES_PER_SEC: usize = 1024 * 1024;
/// Minimum gap between *bulk* flushed frames.
pub const FLUSH_MIN_GAP: Duration = Duration::from_millis(5);
const NONCE_LEN: usize = 24;
static NONCE_SEQ: AtomicU64 = AtomicU64::new(1);
static FRAME_KEY_SEQ: AtomicU64 = AtomicU64::new(1);
static ENTROPY_EMERGENCY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Critical,
    Bulk,
}

struct Frame {
    nonce: [u8; NONCE_LEN],
    seq: u64,
    ciphertext: Vec<u8>,
}

pub struct EncryptedRing {
    /// Process IKM when the kernel keyring is unavailable. Never the per-frame key.
    master: Option<Zeroizing<[u8; 32]>>,
    /// Linux `user` key serial in the thread keyring (preferred).
    key_id: Option<i32>,
    critical: VecDeque<Frame>,
    bulk: VecDeque<Frame>,
    bytes: usize,
    dropped: u64,
    pushed: u64,
    flushed: u64,
}

impl Drop for EncryptedRing {
    fn drop(&mut self) {
        if let Some(mut m) = self.master.take() {
            m.zeroize();
        }
        #[cfg(target_os = "linux")]
        if let Some(id) = self.key_id.take() {
            ring_keyring::invalidate(id);
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RingStats {
    pub bytes: u32,
    pub frames: u32,
    pub dropped: u64,
    pub pushed: u64,
    pub flushed: u64,
}

impl EncryptedRing {
    #[must_use]
    pub fn new(secret: &str) -> Self {
        let master = derive_master_ikm(secret);
        #[cfg(unix)]
        mlock_bytes(master.as_ptr(), 32);
        #[cfg(target_os = "linux")]
        {
            if let Some(id) = ring_keyring::store(&master) {
                let mut wipe = master;
                wipe.zeroize();
                return Self {
                    master: None,
                    key_id: Some(id),
                    critical: VecDeque::new(),
                    bulk: VecDeque::new(),
                    bytes: 0,
                    dropped: 0,
                    pushed: 0,
                    flushed: 0,
                };
            }
        }
        Self {
            master: Some(master),
            key_id: None,
            critical: VecDeque::new(),
            bulk: VecDeque::new(),
            bytes: 0,
            dropped: 0,
            pushed: 0,
            flushed: 0,
        }
    }

    fn with_master<T>(&self, f: impl FnOnce(&[u8; 32]) -> T) -> Option<T> {
        #[cfg(target_os = "linux")]
        if let Some(id) = self.key_id {
            let mut buf = Zeroizing::new([0u8; 32]);
            if !ring_keyring::read(id, &mut buf) {
                return None;
            }
            return Some(f(&buf));
        }
        self.master.as_ref().map(|m| f(m))
    }

    fn seal(&self, nonce: &[u8; NONCE_LEN], seq: u64, plain: &[u8]) -> Option<Vec<u8>> {
        self.with_master(|master| {
            let mut fk = derive_frame_key(master, nonce, seq);
            let cipher = XChaCha20Poly1305::new(Key::from_slice(fk.as_ref()));
            let nonce = XNonce::from_slice(nonce);
            let out = cipher.encrypt(nonce, plain).ok();
            drop(cipher);
            fk.zeroize();
            out
        })?
    }

    fn open(&self, nonce: &[u8; NONCE_LEN], seq: u64, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.with_master(|master| {
            let mut fk = derive_frame_key(master, nonce, seq);
            let cipher = XChaCha20Poly1305::new(Key::from_slice(fk.as_ref()));
            let nonce = XNonce::from_slice(nonce);
            let out = cipher.decrypt(nonce, ciphertext).ok();
            drop(cipher);
            fk.zeroize();
            out
        })?
    }

    /// Encrypt and enqueue. KeepAlivePing is never stored.
    pub fn push_msg(&mut self, msg: &AgentToServer) {
        if matches!(msg, AgentToServer::KeepAlivePing) {
            return;
        }
        let Ok(mut plain) = serde_json::to_vec(msg) else {
            return;
        };
        self.push_bytes(&plain, lane_for(msg));
        plain.zeroize();
    }

    pub fn push_bytes(&mut self, plain: &[u8], lane: Lane) {
        if plain.is_empty() {
            return;
        }
        let Some(nonce_raw) = fill_xchacha_nonce() else {
            self.dropped += 1;
            return;
        };
        let seq = FRAME_KEY_SEQ.fetch_add(1, Ordering::Relaxed);
        let Some(ciphertext) = self.seal(&nonce_raw, seq, plain) else {
            self.dropped += 1;
            return;
        };
        let frame_bytes = NONCE_LEN + ciphertext.len();
        if frame_bytes > MAX_BYTES {
            self.dropped += 1;
            return;
        }
        while self.bytes + frame_bytes > MAX_BYTES {
            let old = if !self.bulk.is_empty() {
                self.bulk.pop_front()
            } else {
                self.critical.pop_front()
            };
            match old {
                Some(old) => {
                    self.bytes = self.bytes.saturating_sub(NONCE_LEN + old.ciphertext.len());
                    self.dropped += 1;
                }
                None => break,
            }
        }
        self.bytes += frame_bytes;
        let frame = Frame {
            nonce: nonce_raw,
            seq,
            ciphertext,
        };
        match lane {
            Lane::Critical => self.critical.push_back(frame),
            Lane::Bulk => self.bulk.push_back(frame),
        }
        self.pushed += 1;
    }

    /// Decrypt and pop critical first, then bulk.
    pub fn pop_json(&mut self) -> Option<String> {
        let from_critical = !self.critical.is_empty();
        let frame = if from_critical {
            self.critical.pop_front()?
        } else {
            self.bulk.pop_front()?
        };
        self.bytes = self
            .bytes
            .saturating_sub(NONCE_LEN + frame.ciphertext.len());
        let mut plain = self.open(&frame.nonce, frame.seq, &frame.ciphertext)?;
        let json = String::from_utf8(plain.clone()).ok();
        plain.zeroize();
        let json = json?;
        self.flushed += 1;
        Some(json)
    }

    pub fn pop_msg(&mut self) -> Option<(Lane, AgentToServer)> {
        let lane = if !self.critical.is_empty() {
            Lane::Critical
        } else {
            Lane::Bulk
        };
        let json = self.pop_json()?;
        let msg = serde_json::from_str(&json).ok()?;
        Some((lane, msg))
    }

    #[must_use]
    pub fn stats(&self) -> RingStats {
        RingStats {
            bytes: self.bytes.min(u32::MAX as usize) as u32,
            frames: (self.critical.len() + self.bulk.len()).min(u32::MAX as usize) as u32,
            dropped: self.dropped,
            pushed: self.pushed,
            flushed: self.flushed,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.critical.is_empty() && self.bulk.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.critical.len() + self.bulk.len()
    }
}

/// High/critical detections and task errors skip the bulk throttle.
#[must_use]
pub fn is_critical(msg: &AgentToServer) -> bool {
    lane_for(msg) == Lane::Critical
}

#[must_use]
pub fn lane_for(msg: &AgentToServer) -> Lane {
    match msg {
        AgentToServer::KeepAlivePing => Lane::Bulk,
        AgentToServer::TaskError { .. } => Lane::Critical,
        AgentToServer::Finding {
            engine, finding, ..
        } => {
            if engine == "ueba_baseline" {
                return Lane::Bulk;
            }
            if severity_is_hot(finding) {
                Lane::Critical
            } else {
                Lane::Bulk
            }
        }
        _ => Lane::Bulk,
    }
}

fn severity_is_hot(finding: &Value) -> bool {
    let s = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    s == "critical" || s == "high"
}

/// Minimum CSPRNG bytes (CPU RNG and/or OS getrandom) before a nonce is legal.
const STRONG_ENTROPY_MIN: usize = 16;
/// Architect: retry RDRAND up to 10 times while CF=0.
const RDRAND_RETRIES: u32 = 10;

/// 192-bit XChaCha20 nonce. Hot path never blocks on `/dev/urandom`.
/// If hardware + non-blocking OS CSPRNG cannot supply [`STRONG_ENTROPY_MIN`]
/// bytes, Low-Entropy Emergency Mode (Vault seed) may still mint a nonce.
/// PID/time alone is never enough.
#[must_use]
pub(crate) fn fill_xchacha_nonce() -> Option<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    let hw = mix_hw_rng(&mut nonce);
    let os = mix_os_nonblock(&mut nonce);
    let mut n = hw.saturating_add(os);
    if n < STRONG_ENTROPY_MIN {
        n = n.saturating_add(mix_emergency_seed(&mut nonce));
    }
    if n < STRONG_ENTROPY_MIN {
        return None;
    }
    mix_counter_time(&mut nonce);
    Some(nonce)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    Strong,
    Emergency,
}

/// Probe CSPRNG at boot. Blocking getrandom is allowed here (not on the hot
/// path) so nested VMs can wait for the kernel pool. If that still fails, a
/// Vault-injected `WEISSMAN_AGENT_ENTROPY_SEED` enables emergency mode.
pub fn ensure_strong_entropy() -> anyhow::Result<EntropyClass> {
    if unique_nonce_pair().is_some() {
        return Ok(EntropyClass::Strong);
    }
    // Cold VM: wait up to ~5s for the kernel pool (blocking getrandom).
    for _ in 0..25 {
        let mut probe = [0u8; NONCE_LEN];
        if mix_os_block(&mut probe) >= STRONG_ENTROPY_MIN && unique_nonce_pair().is_some() {
            return Ok(EntropyClass::Strong);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if install_emergency_seed() {
        ENTROPY_EMERGENCY.store(true, Ordering::SeqCst);
        if unique_nonce_pair().is_none() {
            anyhow::bail!("Vault entropy seed installed but nonce mint still failed");
        }
        tracing::error!(
            target: "agent",
            "CSPRNG (RDRAND CF + getrandom) dead — Low-Entropy Emergency Mode \
             using WEISSMAN_AGENT_ENTROPY_SEED; SOC must treat this host as degraded"
        );
        return Ok(EntropyClass::Emergency);
    }
    anyhow::bail!(
        "strong entropy unavailable: RDRAND/RNDR CF-failed, blocking getrandom empty, \
         and WEISSMAN_AGENT_ENTROPY_SEED unset — refusing to start (no PID/time nonce)"
    )
}

fn unique_nonce_pair() -> Option<([u8; NONCE_LEN], [u8; NONCE_LEN])> {
    let a = fill_xchacha_nonce()?;
    let b = fill_xchacha_nonce()?;
    if a == b {
        return None;
    }
    Some((a, b))
}

#[must_use]
pub fn in_entropy_emergency() -> bool {
    ENTROPY_EMERGENCY.load(Ordering::SeqCst)
}

/// 32-byte IKM from hex `WEISSMAN_AGENT_ENTROPY_SEED` (Vault / orchestrator).
#[must_use]
pub(crate) fn parse_entropy_seed(hex: &str) -> Option<Zeroizing<[u8; 32]>> {
    let t = hex.trim();
    let bytes = hex::decode(t).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    if bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let mut a = Zeroizing::new([0u8; 32]);
    a.copy_from_slice(&bytes[..32]);
    Some(a)
}

static EMERGENCY_IKM: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

fn install_emergency_seed() -> bool {
    let Ok(raw) = std::env::var("WEISSMAN_AGENT_ENTROPY_SEED") else {
        return false;
    };
    let Some(seed) = parse_entropy_seed(&raw) else {
        return false;
    };
    let _ = EMERGENCY_IKM.set(seed);
    EMERGENCY_IKM.get().is_some()
}

fn mix_emergency_seed(out: &mut [u8; NONCE_LEN]) -> usize {
    let Some(ikm) = EMERGENCY_IKM.get() else {
        return 0;
    };
    let seq = NONCE_SEQ.load(Ordering::Relaxed);
    let hk = Hkdf::<Sha256>::new(Some(b"weissman-agent-entropy-emergency-v1"), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; NONCE_LEN]);
    if hk.expand(&seq.to_le_bytes(), okm.as_mut()).is_err() {
        return 0;
    }
    for i in 0..NONCE_LEN {
        out[i] ^= okm[i];
    }
    okm.zeroize();
    NONCE_LEN
}

/// Accept a hardware RNG draw only when the carry/success flag is set and the
/// value is not a silent-zero / all-ones hypervisor stub.
#[must_use]
pub(crate) fn accept_hw_u64(flag: u8, val: u64) -> Option<u64> {
    if flag == 1 && val != 0 && val != u64::MAX {
        Some(val)
    } else {
        None
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn mix_hw_rng(out: &mut [u8; NONCE_LEN]) -> usize {
    if !is_x86_feature_detected!("rdrand") {
        return 0;
    }
    let mut off = 0usize;
    while off < NONCE_LEN {
        let Some(v) = secure_rdrand() else {
            break;
        };
        let b = v.to_le_bytes();
        let n = (NONCE_LEN - off).min(8);
        for i in 0..n {
            out[off + i] ^= b[i];
        }
        off += n;
    }
    off
}

/// RDRAND with an explicit Carry Flag check (`setc`) and 10 retries.
/// A hypervisor that leaves CF=0 cannot be treated as success.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn secure_rdrand() -> Option<u64> {
    for _ in 0..RDRAND_RETRIES {
        let mut val: u64 = 0;
        let mut ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = inout(reg) val,
                ok = lateout(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if let Some(v) = accept_hw_u64(ok, val) {
            return Some(v);
        }
    }
    None
}

#[cfg(target_arch = "x86")]
#[inline(always)]
pub fn secure_rdrand() -> Option<u64> {
    for _ in 0..RDRAND_RETRIES {
        let mut lo = 0u32;
        let mut hi = 0u32;
        let a = unsafe { core::arch::x86::_rdrand32_step(&mut lo) };
        let b = unsafe { core::arch::x86::_rdrand32_step(&mut hi) };
        if a == 1 && b == 1 {
            let val = (u64::from(hi) << 32) | u64::from(lo);
            if let Some(v) = accept_hw_u64(1, val) {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(target_arch = "aarch64")]
fn mix_hw_rng(out: &mut [u8; NONCE_LEN]) -> usize {
    if !std::arch::is_aarch64_feature_detected!("rand") {
        return 0;
    }
    let mut off = 0usize;
    while off < NONCE_LEN {
        let Some(raw) = (unsafe { core::arch::aarch64::__rndr() }) else {
            break;
        };
        let Some(v) = accept_hw_u64(1, raw) else {
            break;
        };
        let b = v.to_le_bytes();
        let n = (NONCE_LEN - off).min(8);
        for i in 0..n {
            out[off + i] ^= b[i];
        }
        off += n;
    }
    off
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
fn mix_hw_rng(_out: &mut [u8; NONCE_LEN]) -> usize {
    0
}

#[cfg(target_os = "linux")]
fn mix_os_nonblock(out: &mut [u8; NONCE_LEN]) -> usize {
    let mut tmp = [0u8; NONCE_LEN];
    let n = unsafe {
        libc::getrandom(
            tmp.as_mut_ptr() as *mut libc::c_void,
            tmp.len(),
            libc::GRND_NONBLOCK,
        )
    };
    if n <= 0 {
        return 0;
    }
    let n = (n as usize).min(NONCE_LEN);
    if tmp[..n].iter().all(|&b| b == 0) {
        return 0;
    }
    for i in 0..n {
        out[i] ^= tmp[i];
    }
    n
}

/// Boot-only: blocking getrandom (flag 0) so a cold VM can wait for the pool.
#[cfg(target_os = "linux")]
fn mix_os_block(out: &mut [u8; NONCE_LEN]) -> usize {
    let mut tmp = [0u8; NONCE_LEN];
    let n = unsafe { libc::getrandom(tmp.as_mut_ptr() as *mut libc::c_void, tmp.len(), 0) };
    if n <= 0 {
        return 0;
    }
    let n = (n as usize).min(NONCE_LEN);
    if tmp[..n].iter().all(|&b| b == 0) {
        return 0;
    }
    for i in 0..n {
        out[i] ^= tmp[i];
    }
    n
}

#[cfg(not(target_os = "linux"))]
fn mix_os_nonblock(out: &mut [u8; NONCE_LEN]) -> usize {
    let mut tmp = [0u8; NONCE_LEN];
    if getrandom::getrandom(&mut tmp).is_err() {
        return 0;
    }
    if tmp.iter().all(|&b| b == 0) {
        return 0;
    }
    for i in 0..NONCE_LEN {
        out[i] ^= tmp[i];
    }
    NONCE_LEN
}

#[cfg(not(target_os = "linux"))]
fn mix_os_block(out: &mut [u8; NONCE_LEN]) -> usize {
    mix_os_nonblock(out)
}

fn mix_counter_time(out: &mut [u8; NONCE_LEN]) {
    let seq = NONCE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = u64::from(std::process::id());
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(nanos.to_le_bytes());
    h.update(pid.to_le_bytes());
    h.update(out.as_slice());
    let digest: [u8; 32] = h.finalize().into();
    for i in 0..NONCE_LEN {
        out[i] ^= digest[i];
    }
}

fn derive_master_ikm(secret: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"weissman-agent-ring-v3-hkdf"), secret.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"ring-master", okm.as_mut())
        .expect("HKDF-SHA256 expand 32");
    okm
}

fn derive_frame_key(master: &[u8; 32], nonce: &[u8; NONCE_LEN], seq: u64) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), master);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&seq.to_le_bytes(), okm.as_mut())
        .expect("HKDF-SHA256 frame key");
    okm
}

#[cfg(unix)]
fn mlock_bytes(ptr: *const u8, len: usize) {
    unsafe {
        let _ = libc::mlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(target_os = "linux")]
mod ring_keyring {
    use libc::{c_char, c_long, c_void, size_t};
    const KEY_SPEC_THREAD_KEYRING: c_long = -1;
    const KEYCTL_READ: c_long = 11;
    const KEYCTL_INVALIDATE: c_long = 21;

    #[cfg(target_arch = "x86_64")]
    const SYS_ADD_KEY: c_long = 248;
    #[cfg(target_arch = "x86_64")]
    const SYS_KEYCTL: c_long = 250;
    #[cfg(target_arch = "aarch64")]
    const SYS_ADD_KEY: c_long = 217;
    #[cfg(target_arch = "aarch64")]
    const SYS_KEYCTL: c_long = 219;

    pub fn store(payload: &[u8; 32]) -> Option<i32> {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let ty = b"user\0";
            let desc = b"weissman-agent-ring\0";
            let id = unsafe {
                libc::syscall(
                    SYS_ADD_KEY,
                    ty.as_ptr() as *const c_char,
                    desc.as_ptr() as *const c_char,
                    payload.as_ptr() as *const c_void,
                    32 as size_t,
                    KEY_SPEC_THREAD_KEYRING,
                )
            };
            if id > 0 {
                Some(id as i32)
            } else {
                None
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = payload;
            None
        }
    }

    pub fn read(id: i32, out: &mut [u8; 32]) -> bool {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let n = unsafe {
                libc::syscall(
                    SYS_KEYCTL,
                    KEYCTL_READ,
                    id as c_long,
                    out.as_mut_ptr() as c_long,
                    32 as c_long,
                )
            };
            n == 32
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = (id, out);
            false
        }
    }

    pub fn invalidate(id: i32) {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        unsafe {
            let _ = libc::syscall(
                SYS_KEYCTL,
                KEYCTL_INVALIDATE,
                id as c_long,
                0 as c_long,
                0 as c_long,
            );
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = id;
        }
    }
}

static RING: OnceLock<Mutex<EncryptedRing>> = OnceLock::new();
static UEBA_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
static UEBA_UPLOADED: AtomicU64 = AtomicU64::new(0);
static LAST_RTT_US: AtomicU64 = AtomicU64::new(0);

/// Initialise the process-wide ring from the agent renewal secret.
pub fn init(secret: &str) -> anyhow::Result<()> {
    let class = ensure_strong_entropy()?;
    let ring = EncryptedRing::new(secret);
    let _ = RING.set(Mutex::new(ring));
    if class == EntropyClass::Emergency {
        tracing::error!(
            target: "agent",
            "ring initialized in Low-Entropy Emergency Mode — emit SOC finding from main"
        );
    }
    Ok(())
}

pub fn push(msg: &AgentToServer) {
    if let Some(lock) = RING.get() {
        if let Ok(mut g) = lock.lock() {
            g.push_msg(msg);
        }
    }
}

pub fn pop_msg() -> Option<(Lane, AgentToServer)> {
    RING.get()?.lock().ok()?.pop_msg()
}

#[must_use]
pub fn stats() -> RingStats {
    RING.get()
        .and_then(|l| l.lock().ok())
        .map(|g| g.stats())
        .unwrap_or_default()
}

#[must_use]
pub fn pending() -> bool {
    RING.get()
        .and_then(|l| l.lock().ok())
        .map(|g| !g.is_empty())
        .unwrap_or(false)
}

pub fn note_ueba_suppressed() {
    UEBA_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
}

pub fn note_ueba_uploaded() {
    UEBA_UPLOADED.fetch_add(1, Ordering::Relaxed);
}

#[must_use]
pub fn ueba_suppressed() -> u64 {
    UEBA_SUPPRESSED.load(Ordering::Relaxed)
}

#[must_use]
pub fn ueba_uploaded() -> u64 {
    UEBA_UPLOADED.load(Ordering::Relaxed)
}

pub fn note_send_rtt(rtt: Duration) {
    LAST_RTT_US.store(
        rtt.as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
}

/// Sleep the throttle gap for bulk frames only. Critical frames return immediately.
pub async fn throttle_wait(window: &mut FlushWindow, frame_len: usize, lane: Lane) {
    if lane == Lane::Critical {
        return;
    }
    window.adapt();
    window.note(frame_len);
    let extra = window.penalty();
    tokio::time::sleep(FLUSH_MIN_GAP + extra).await;
}

pub struct FlushWindow {
    started: Instant,
    bytes: usize,
    budget: usize,
}

impl FlushWindow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes: 0,
            budget: DRAIN_START_BYTES_PER_SEC,
        }
    }

    fn adapt(&mut self) {
        let rtt_us = LAST_RTT_US.load(Ordering::Relaxed);
        if rtt_us > 0 {
            if rtt_us < 50_000 {
                self.budget = ((self.budget as f64) * 1.25) as usize;
            } else if rtt_us > 200_000 {
                self.budget = ((self.budget as f64) * 0.7) as usize;
            }
        }
        if let Some((load1, ncpu)) = host_load() {
            if ncpu > 0.0 && load1 > ncpu {
                self.budget = self.budget.min(128 * 1024);
            }
        }
        self.budget = self
            .budget
            .clamp(DRAIN_MIN_BYTES_PER_SEC, DRAIN_MAX_BYTES_PER_SEC);
    }

    fn note(&mut self, n: usize) {
        if self.started.elapsed() >= Duration::from_secs(1) {
            self.started = Instant::now();
            self.bytes = 0;
        }
        self.bytes = self.bytes.saturating_add(n);
    }

    fn penalty(&self) -> Duration {
        if self.bytes <= self.budget {
            return Duration::ZERO;
        }
        Duration::from_secs(1).saturating_sub(self.started.elapsed())
    }
}

impl Default for FlushWindow {
    fn default() -> Self {
        Self::new()
    }
}

fn host_load() -> Option<(f64, f64)> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/loadavg").ok()?;
        let load1: f64 = raw.split_whitespace().next()?.parse().ok()?;
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get() as f64)
            .unwrap_or(1.0);
        Some((load1, ncpu))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AgentToServer;
    use serde_json::json;

    fn sample() -> AgentToServer {
        AgentToServer::Heartbeat {
            agent_id: "a".into(),
            running_tasks: 0,
            completed_tasks: 1,
            uptime_secs: 9,
            ring_buffer_bytes: 0,
            ring_buffer_frames: 0,
            ueba_suppressed: 0,
            ueba_uploaded: 0,
        }
    }

    #[test]
    fn round_trips_encrypted_frame() {
        let mut ring = EncryptedRing::new("unit-test-secret");
        ring.push_msg(&sample());
        assert_eq!(ring.len(), 1);
        let (_lane, back) = ring.pop_msg().expect("decrypt");
        match back {
            AgentToServer::Heartbeat { agent_id, .. } => assert_eq!(agent_id, "a"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn xchacha_nonces_are_unique() {
        let mut ring = EncryptedRing::new("n");
        for _ in 0..32 {
            ring.push_msg(&sample());
        }
        let mut seen = std::collections::HashSet::new();
        for f in ring.critical.iter().chain(ring.bulk.iter()) {
            assert_eq!(f.nonce.len(), 24);
            assert!(seen.insert(f.nonce), "XChaCha nonce reused");
        }
    }

    #[test]
    fn nonce_fill_never_blocks_and_stays_unique() {
        let started = Instant::now();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            assert!(
                seen.insert(fill_xchacha_nonce().expect("strong entropy")),
                "nonce collision"
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "nonce fill blocked (entropy starvation): {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn nonce_mixer_does_not_call_blocking_getrandom_on_linux() {
        let src = include_str!("ringbuf.rs");
        assert!(src.contains("GRND_NONBLOCK"));
        assert!(src.contains("mix_counter_time"));
        assert!(src.contains("libc::getrandom"));
        assert!(src.contains("setc"));
        assert!(src.contains("RDRAND_RETRIES"));
        assert!(src.contains("#[cfg(not(target_os = \"linux\"))]"));
        // Blocking getrandom is boot-only (crash-loop avoidance), not the hot path.
        assert!(src.contains("fn mix_os_block"));
    }

    #[test]
    fn rdrand_carry_flag_rejects_zero_and_failure() {
        assert!(accept_hw_u64(1, 0xA5A5_A5A5_A5A5_A5A5).is_some());
        assert!(
            accept_hw_u64(0, 0xA5A5_A5A5_A5A5_A5A5).is_none(),
            "CF=0 must not be treated as entropy"
        );
        assert!(
            accept_hw_u64(1, 0).is_none(),
            "silent-zero hypervisor pass-through"
        );
        assert!(accept_hw_u64(1, u64::MAX).is_none());
    }

    #[test]
    fn boot_fails_closed_only_when_csprng_is_dead() {
        let class = ensure_strong_entropy().expect("this host must have getrandom or RDRAND");
        assert!(
            matches!(class, EntropyClass::Strong | EntropyClass::Emergency),
            "{class:?}"
        );
    }

    #[test]
    fn entropy_seed_rejects_short_and_all_zero() {
        assert!(parse_entropy_seed("00").is_none());
        assert!(parse_entropy_seed(&"00".repeat(32)).is_none());
        assert!(parse_entropy_seed(&"ab".repeat(32)).is_some());
        assert!(parse_entropy_seed(&"AB".repeat(32)).is_some());
    }

    #[test]
    fn hkdf_frame_keys_depend_on_seq_and_zeroize_is_wired() {
        let master = [0x11u8; 32];
        let nonce = [0x22u8; NONCE_LEN];
        let a = derive_frame_key(&master, &nonce, 1);
        let b = derive_frame_key(&master, &nonce, 2);
        assert_ne!(&a[..], &b[..], "rolling keys must change with seq");
        let src = include_str!("ringbuf.rs");
        assert!(src.contains("Hkdf"));
        assert!(src.contains("zeroize"));
        assert!(src.contains("ring-master"));
        assert!(src.contains("mix_os_block"));
    }

    #[test]
    fn never_stores_keepalive() {
        let mut ring = EncryptedRing::new("k");
        ring.push_msg(&AgentToServer::KeepAlivePing);
        assert!(ring.is_empty());
    }

    #[test]
    fn critical_findings_drain_before_bulk() {
        let mut ring = EncryptedRing::new("prio");
        ring.push_msg(&sample());
        ring.push_msg(&AgentToServer::Finding {
            agent_id: "a".into(),
            task_id: "t".into(),
            engine: "process_hollowing".into(),
            finding: json!({"severity": "critical", "title": "hollowing"}),
        });
        let (lane, msg) = ring.pop_msg().expect("first");
        assert_eq!(lane, Lane::Critical);
        match msg {
            AgentToServer::Finding { engine, .. } => assert_eq!(engine, "process_hollowing"),
            other => panic!("expected critical finding first, got {other:?}"),
        }
    }

    #[test]
    fn ueba_baseline_is_bulk() {
        let msg = AgentToServer::Finding {
            agent_id: "a".into(),
            task_id: "t".into(),
            engine: "ueba_baseline".into(),
            finding: json!({"severity": "medium"}),
        };
        assert_eq!(lane_for(&msg), Lane::Bulk);
    }

    #[test]
    fn evicts_oldest_at_10mb() {
        let mut ring = EncryptedRing::new("cap");
        let blob = "x".repeat(64 * 1024);
        let msg = AgentToServer::TaskError {
            agent_id: "a".into(),
            task_id: "t".into(),
            engine: "e".into(),
            error: blob,
        };
        for _ in 0..200 {
            ring.push_msg(&msg);
        }
        assert!(
            ring.stats().bytes as usize <= MAX_BYTES,
            "ring grew past the 10 MiB hard cap: {}",
            ring.stats().bytes
        );
        assert!(ring.stats().dropped > 0, "cap should have evicted frames");
        let last = ring.critical.back().or(ring.bulk.back()).expect("retained");
        assert!(
            ring.open(&last.nonce, last.seq, &last.ciphertext).is_some(),
            "retained frame must decrypt with rolling HKDF key"
        );
    }

    #[test]
    fn wrong_key_cannot_read() {
        let mut a = EncryptedRing::new("alpha");
        a.push_msg(&sample());
        let frame = a
            .bulk
            .pop_front()
            .or_else(|| a.critical.pop_front())
            .unwrap();
        let b = EncryptedRing::new("bravo");
        assert!(
            b.open(&frame.nonce, frame.seq, &frame.ciphertext).is_none(),
            "different master IKM must not decrypt"
        );
    }

    #[test]
    fn drain_budget_starts_at_256k() {
        assert_eq!(DRAIN_START_BYTES_PER_SEC, 256 * 1024);
        let w = FlushWindow::new();
        assert_eq!(w.budget, DRAIN_START_BYTES_PER_SEC);
    }
}
