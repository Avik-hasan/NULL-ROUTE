//! Linux TUN device wrapper (`/dev/net/tun`).
//!
//! Opens a TUN interface in IFF_TUN|IFF_NO_PI mode and exposes ASYNC read/write
//! of raw IP packets. The fd is put in non-blocking mode and driven by tokio's
//! `AsyncFd`, so tunnel IO never blocks a runtime worker thread.
//!
//! Syscalls go through the `libc` crate (stable ABI wrappers) rather than a
//! hand-rolled `extern "C"` block.
//!
//! NOTE: This module is `#[cfg(target_os = "linux")]`-gated by `main.rs`.
#![allow(dead_code)] // data-plane wiring is environment-specific.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

use vpn_shared::{Result, VpnError};

const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

// _IOW('T', 202, int) == 0x4004_54ca on Linux.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// A configured, non-blocking TUN interface with async IO.
pub struct TunDevice {
    inner: AsyncFd<TunFd>,
    pub name: String,
}

/// Owns the raw fd and closes it exactly once on drop.
struct TunFd(RawFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for TunFd {
    fn drop(&mut self) {
        // SAFETY: we exclusively own this fd for the lifetime of TunFd.
        unsafe {
            libc::close(self.0);
        }
    }
}

// Read/Write are implemented on `&TunFd` so `AsyncFd::try_io` (which yields a
// shared reference to the inner value) can drive them.
impl Read for &TunFd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: valid fd; buffer pointer/len describe a valid writable region.
        let n = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for &TunFd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: valid fd; buffer pointer/len describe a valid readable region.
        let n = unsafe { libc::write(self.0, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TunDevice {
    /// Create/attach a TUN device named `requested` (e.g. "cvpn0").
    pub fn open(requested: &str) -> Result<Self> {
        let name_bytes = requested.as_bytes();
        if name_bytes.len() >= 16 {
            return Err(VpnError::Config("tun name too long".into()));
        }

        // Open /dev/net/tun (O_RDWR | O_CLOEXEC).
        // SAFETY: NUL-terminated path literal; flags are valid.
        let fd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(VpnError::Io(format!(
                "open /dev/net/tun: {}",
                io::Error::last_os_error()
            )));
        }
        // Take ownership immediately so any early return closes the fd.
        let owned = TunFd(fd);

        // struct ifreq { char ifr_name[16]; union { short ifr_flags; ... }; }
        // sizeof(ifreq) == 40 on 64-bit Linux; flags live at byte offset 16.
        let mut ifr = [0u8; 40];
        ifr[..name_bytes.len()].copy_from_slice(name_bytes);
        let flags = (IFF_TUN | IFF_NO_PI).to_ne_bytes();
        ifr[16] = flags[0];
        ifr[17] = flags[1];

        // SAFETY: valid fd; ifr is a correctly sized ifreq buffer.
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(VpnError::Io(format!(
                "TUNSETIFF failed: {}",
                io::Error::last_os_error()
            )));
        }

        // Recover the (possibly kernel-adjusted) interface name.
        let end = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&ifr[..end]).into_owned();

        // Non-blocking mode is REQUIRED for AsyncFd; otherwise a read would
        // block the whole runtime worker.
        set_nonblocking(fd)?;

        let inner = AsyncFd::new(owned)
            .map_err(|e| VpnError::Io(format!("register tun with reactor: {e}")))?;
        Ok(Self { inner, name })
    }

    /// Read one IP packet from the tunnel (async, cancel-safe).
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self
                .inner
                .readable()
                .await
                .map_err(|e| VpnError::Io(e.to_string()))?;
            match guard.try_io(|inner| {
                let mut fd_ref: &TunFd = inner.get_ref();
                fd_ref.read(buf)
            }) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(VpnError::Io(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet into the tunnel (async).
    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self
                .inner
                .writable()
                .await
                .map_err(|e| VpnError::Io(e.to_string()))?;
            match guard.try_io(|inner| {
                let mut fd_ref: &TunFd = inner.get_ref();
                fd_ref.write(buf)
            }) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(VpnError::Io(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(VpnError::Io(format!(
            "F_GETFL: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: valid fd.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(VpnError::Io(format!(
            "F_SETFL O_NONBLOCK: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}
