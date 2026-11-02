//! macOS `utun` interface, created via `AF_SYSTEM` / `SYSPROTO_CONTROL` /
//! `com.apple.net.utun_control`.
//!
//! This is the same mechanism used by `BetterTether` and other user-space VPNs.
//! `utun` is a **layer-3** point-to-point tunnel: reads yield a 4-byte address
//! family header followed by a raw IP packet, and writes must prepend that
//! header. It is not a Wi-Fi interface and does not implement 802.11.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::process::{Command, Stdio};

const AF_SYSTEM: libc::c_int = 32;
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYS_CONTROL: u16 = 2;
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const UTUN_OPT_IFNAME: libc::c_int = 2;
/// `_IOW('c', 3, struct ctl_info)` where `ctl_info` is 100 bytes.
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

/// Address-family value in the utun 4-byte header for IPv4.
pub const AF_INET_HEADER: u32 = 2;
/// Address-family value in the utun 4-byte header for IPv6.
pub const AF_INET6_HEADER: u32 = 0x1e;

/// `struct ctl_info`.
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

/// `struct sockaddr_ctl`.
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

impl Default for SockaddrCtl {
    fn default() -> Self {
        Self {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: 0,
            sc_unit: 0,
            sc_reserved: [0; 5],
        }
    }
}

/// A configured `utun` interface. Dropping it rolls back the routes and DNS
/// state it added.
pub struct Utun {
    file: File,
    name: String,
    local: Option<Ipv4Addr>,
    routes_added: bool,
    dns_configured: bool,
    service_id: String,
}

impl Utun {
    /// Create a new `utunN` interface.
    pub fn open() -> io::Result<Utun> {
        // SAFETY: standard socket(2) call.
        let fd = unsafe { libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = FdGuard(fd);

        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let name = UTUN_CONTROL_NAME.as_bytes();
        info.ctl_name[..name.len()].copy_from_slice(name);

        // SAFETY: `info` is a valid `ctl_info` for CTLIOCGINFO.
        if unsafe { libc::ioctl(fd.0, CTLIOCGINFO, &mut info as *mut CtlInfo) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let ctl = SockaddrCtl {
            sc_id: info.ctl_id,
            ..SockaddrCtl::default()
        };
        // SAFETY: `ctl` is a valid sockaddr_ctl of the advertised length.
        let rc = unsafe {
            libc::connect(
                fd.0,
                &ctl as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buf = [0u8; 64];
        let mut len = buf.len() as libc::socklen_t;
        // SAFETY: `buf`/`len` are valid for getsockopt to write into.
        let rc = unsafe {
            libc::getsockopt(
                fd.0,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let ifname = String::from_utf8_lossy(&buf[..len.saturating_sub(1) as usize]).into_owned();
        // SAFETY: `fd` is owned from here on; the guard must not close it.
        let file = unsafe { File::from_raw_fd(fd.into_raw()) };

        Ok(Utun {
            file,
            name: ifname,
            local: None,
            routes_added: false,
            dns_configured: false,
            service_id: "mt7601u".to_string(),
        })
    }

    /// Interface name, e.g. `utun4`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Bound blocking reads with `SO_RCVTIMEO`, so a relay loop can poll for
    /// shutdown without a second thread.
    pub fn set_read_timeout(&self, timeout: std::time::Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        // SAFETY: `tv` is a valid timeval of the advertised size.
        let rc = unsafe {
            libc::setsockopt(
                self.file.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Put the interface socket into non-blocking mode (or restore blocking
    /// mode). A relay that injects packets must use this: a blocking `write`
    /// to an interface whose kernel queue is full stalls the whole relay, and
    /// everything behind it (including socket reads) starves until the
    /// interface drains.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let fd = self.file.as_raw_fd();
        // SAFETY: fcntl with a valid fd and flag values.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let updated = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        // SAFETY: as above.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, updated) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Write one IP packet with the `utun` header, without ever blocking:
    /// when the interface's queue is full this reports `WouldBlock`, so the
    /// caller can retry the packet on a later pass.
    pub fn try_write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.write_all(&frame_ipv4(packet))
            .and_then(|()| self.flush())
    }

    /// `ifconfig <name> <local> <peer> mtu <mtu> up`.
    pub fn configure(&mut self, local: Ipv4Addr, peer: Ipv4Addr, mtu: u32) -> io::Result<()> {
        let output = Command::new("ifconfig")
            .args([
                &self.name,
                &local.to_string(),
                &peer.to_string(),
                "mtu",
                &mtu.to_string(),
                "up",
            ])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "ifconfig failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        self.local = Some(local);
        Ok(())
    }

    /// Add the two "more specific" default routes (`0.0.0.0/1`, `128.0.0.0/1`)
    /// that override the existing default without deleting it.
    pub fn add_default_route(&mut self) -> io::Result<()> {
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let output = Command::new("route")
                .args(["add", "-net", net, "-interface", &self.name])
                .output()?;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "route add {net} failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
        }
        self.routes_added = true;
        Ok(())
    }

    /// Register the tunnel as the primary service and set its DNS servers via
    /// `scutil`. Without `PrimaryService` macOS `SCNetworkReachability` does not
    /// consider the system online (Safari/App Store stay offline).
    pub fn set_dns(&mut self, servers: &[Ipv4Addr], router: Ipv4Addr) -> io::Result<()> {
        let addresses = servers
            .iter()
            .map(|server| server.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let service = self.service_id.clone();

        let script = format!(
            "open\n\
             d.init\n\
             d.add Addresses * {local}\n\
             d.add InterfaceName {name}\n\
             d.add Router {router}\n\
             set State:/Network/Service/{service}/IPv4\n\
             d.init\n\
             d.add ServerAddresses * {addresses}\n\
             set State:/Network/Service/{service}/DNS\n\
             d.init\n\
             d.add DeviceName {name}\n\
             d.add Type Other\n\
             set State:/Network/Service/{service}/Interface\n\
             d.init\n\
             d.add PrimaryInterface {name}\n\
             d.add PrimaryService {service}\n\
             d.add Router {router}\n\
             set State:/Network/Global/IPv4\n\
             d.init\n\
             d.add ServerAddresses * {addresses}\n\
             set State:/Network/Global/DNS\n\
             quit\n",
            local = self
                .local
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            name = self.name,
            router = router,
            service = service,
            addresses = addresses,
        );

        let mut child = Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(script.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "scutil failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        self.dns_configured = true;
        Ok(())
    }

    /// Roll back routes and DNS state added by this interface.
    pub fn teardown(&mut self) {
        if self.routes_added {
            for net in ["0.0.0.0/1", "128.0.0.0/1"] {
                let _ = Command::new("route").args(["delete", "-net", net]).output();
            }
            self.routes_added = false;
        }

        if self.dns_configured {
            let service = self.service_id.clone();
            let script = format!(
                "open\n\
                 remove State:/Network/Service/{service}/IPv4\n\
                 remove State:/Network/Service/{service}/DNS\n\
                 remove State:/Network/Service/{service}/Interface\n\
                 d.init\n\
                 set State:/Network/Global/IPv4\n\
                 d.init\n\
                 set State:/Network/Global/DNS\n\
                 quit\n",
                service = service,
            );
            if let Ok(mut child) = Command::new("scutil")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(script.as_bytes());
                }
                let _ = child.wait();
            }
            self.dns_configured = false;
        }
    }
}

impl Read for Utun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for Utun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for Utun {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Small RAII guard so early-return paths close the raw fd.
struct FdGuard(RawFd);

impl FdGuard {
    fn into_raw(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        // SAFETY: the fd is owned by this guard unless `into_raw` was called.
        unsafe { libc::close(self.0) };
    }
}

/// True when running as root (`ifconfig`/`route`/`scutil` need it).
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Helper for building the utun write frame.
pub fn frame_ipv4(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + packet.len());
    out.extend_from_slice(&AF_INET_HEADER.to_be_bytes());
    out.extend_from_slice(packet);
    out
}

/// Helper for parsing a utun read frame into `(family, payload)`.
pub fn parse_frame(buffer: &[u8]) -> Option<(u32, &[u8])> {
    if buffer.len() < 4 {
        return None;
    }
    let family = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    Some((family, &buffer[4..]))
}
