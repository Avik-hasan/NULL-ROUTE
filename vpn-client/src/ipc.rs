//! Hardened Named-Pipe IPC server for GUI <-> elevated-service communication.
//!
//! ## Threat model
//! The service runs as LocalSystem. The GUI runs unprivileged in the interactive
//! session. Any *other* local process (including malware running as another
//! user or a lower-integrity process) MUST NOT be able to open the pipe and
//! drive the elevated service — that would be a textbook Local Privilege
//! Escalation (LPE).
//!
//! ## Mitigation
//! We construct an explicit `SECURITY_DESCRIPTOR` with a DACL that grants
//! `GENERIC_READ | GENERIC_WRITE` to exactly two trustees:
//!   1. `NT AUTHORITY\SYSTEM` (well-known SID S-1-5-18)
//!   2. The SID of the interactive user who owns the current session
//!      (resolved from this process token; for a LocalSystem service you would
//!      instead resolve the session user via `WTSQueryUserToken` — see
//!      `resolve_interactive_user_sid`).
//!
//! There is **no** ACE for `Everyone`/`Authenticated Users`, and we set the DACL
//! present-but-restrictive so default "world" access is denied.
//!
//! All Win32 handles are freed on every path (including errors) via RAII guards;
//! there are no `unwrap()`/`expect()` calls.

#![cfg(windows)]

use vpn_shared::{Result, VpnError};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::{
    CreateWellKnownSid, GetTokenInformation, TokenUser, WinLocalSystemSid, ACL,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, PSID,
};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Owns the heap allocations backing a `SECURITY_ATTRIBUTES` so they outlive the
/// pipe-creation call and are freed exactly once on drop.
pub struct PipeSecurity {
    pub(crate) _descriptor: Box<SECURITY_DESCRIPTOR>,
    pub(crate) acl: *mut ACL,
    pub(crate) _system_sid: Vec<u8>,
    pub(crate) _user_sid_buf: Vec<u8>,
    pub(crate) attributes: SECURITY_ATTRIBUTES,
}

// SAFETY: the raw pointers inside are only ever dereferenced on the thread that
// owns the value; we never share `&PipeSecurity` across threads mutably. The
// accept loop keeps it on a single task.
unsafe impl Send for PipeSecurity {}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.acl.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(self.acl as *mut _));
            }
            self.acl = std::ptr::null_mut();
        }
    }
}

impl PipeSecurity {
    pub fn attributes_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &self.attributes as *const _
    }
}

/// Resolve the **interactive** user's SID into a self-owned byte buffer.
pub fn resolve_interactive_user_sid() -> Result<Vec<u8>> {
    unsafe {
        let mut token = HANDLE::default();
        let session_id = WTSGetActiveConsoleSessionId();
        let have_interactive =
            session_id != 0xFFFF_FFFF && WTSQueryUserToken(session_id, &mut token).is_ok();
        if !have_interactive {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(|e| VpnError::SecurityDescriptor(format!("OpenProcessToken: {e}")))?;
        }

        struct TokenGuard(HANDLE);
        impl Drop for TokenGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
        let _tg = TokenGuard(token);

        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            return Err(VpnError::SecurityDescriptor(
                "GetTokenInformation returned zero length".into(),
            ));
        }
        let mut buf = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
        .map_err(|e| VpnError::SecurityDescriptor(format!("GetTokenInformation(TokenUser): {e}")))?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        if sid.is_invalid() {
            return Err(VpnError::SecurityDescriptor("token user SID invalid".into()));
        }
        let len = sid_length(sid);
        let mut owned = vec![0u8; len];
        std::ptr::copy_nonoverlapping(sid.0 as *const u8, owned.as_mut_ptr(), len);
        Ok(owned)
    }
}

/// SID length = 8 header bytes + 4 * SubAuthorityCount.
unsafe fn sid_length(sid: PSID) -> usize {
    let count = *((sid.0 as *const u8).add(1));
    8 + (count as usize) * 4
}

/// Build the well-known LocalSystem SID (S-1-5-18) into an owned buffer.
pub fn build_system_sid() -> Result<Vec<u8>> {
    unsafe {
        let mut len: u32 = 0;
        let _ = CreateWellKnownSid(WinLocalSystemSid, None, PSID::default(), &mut len);
        if len == 0 {
            return Err(VpnError::SecurityDescriptor(
                "CreateWellKnownSid sizing failed".into(),
            ));
        }
        let mut buf = vec![0u8; len as usize];
        CreateWellKnownSid(
            WinLocalSystemSid,
            None,
            PSID(buf.as_mut_ptr() as *mut _),
            &mut len,
        )
        .map_err(|e| VpnError::SecurityDescriptor(format!("CreateWellKnownSid: {e}")))?;
        Ok(buf)
    }
}
