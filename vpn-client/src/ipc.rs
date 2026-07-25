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

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use vpn_shared::{Result, VpnError, PIPE_NAME};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows::Win32::Security::{
    CreateWellKnownSid, GetTokenInformation, InitializeSecurityDescriptor,
    SetSecurityDescriptorDacl, TokenUser, WinLocalSystemSid, ACL, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, PSID,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;

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

/// Construct a `SECURITY_ATTRIBUTES` whose DACL grants access to SYSTEM + the
/// interactive user only.
pub fn build_pipe_security() -> Result<Box<PipeSecurity>> {
    let mut system_sid = build_system_sid()?;
    let mut user_sid = resolve_interactive_user_sid()?;

    let mut ea: [EXPLICIT_ACCESS_W; 2] = unsafe { core::mem::zeroed() };

    ea[0].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
        ptstrName: PWSTR(system_sid.as_mut_ptr() as *mut u16),
        ..unsafe { core::mem::zeroed() }
    };

    ea[1].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_USER,
        ptstrName: PWSTR(user_sid.as_mut_ptr() as *mut u16),
        ..unsafe { core::mem::zeroed() }
    };

    let mut acl: *mut ACL = std::ptr::null_mut();
    let rc = unsafe { SetEntriesInAclW(Some(&ea[..]), None, &mut acl) };
    if rc.0 != ERROR_SUCCESS.0 || acl.is_null() {
        return Err(VpnError::SecurityDescriptor(format!(
            "SetEntriesInAclW failed: {:#x}",
            rc.0
        )));
    }

    let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
    let psd = PSECURITY_DESCRIPTOR(descriptor.as_mut() as *mut _ as *mut _);
    unsafe {
        InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION).map_err(|e| {
            VpnError::SecurityDescriptor(format!("InitializeSecurityDescriptor: {e}"))
        })?;
        SetSecurityDescriptorDacl(psd, true, Some(acl), false)
            .map_err(|e| VpnError::SecurityDescriptor(format!("SetSecurityDescriptorDacl: {e}")))?;
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_mut() as *mut _ as *mut core::ffi::c_void,
        bInheritHandle: false.into(),
    };

    Ok(Box::new(PipeSecurity {
        _descriptor: descriptor,
        acl,
        _system_sid: system_sid,
        _user_sid_buf: user_sid,
        attributes,
    }))
}

/// Create a pipe-server instance with our restrictive ACL applied.
pub fn create_secured_server(sec: &PipeSecurity, first: bool) -> Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first);
    opts.reject_remote_clients(true);

    let server = unsafe {
        opts.create_with_security_attributes_raw(
            PIPE_NAME,
            sec.attributes_ptr() as *mut core::ffi::c_void,
        )
    }
    .map_err(|e| VpnError::Ipc(format!("create pipe: {e}")))?;
    Ok(server)
}
