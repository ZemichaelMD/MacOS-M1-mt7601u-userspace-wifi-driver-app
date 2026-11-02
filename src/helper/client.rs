//! Client half of the privileged helper: talks to the launchd daemon over its
//! Unix socket from the (unprivileged) GUI process.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::tunnel::relay::PacketTun;
use crate::tunnel::TunnelLink;

use super::{
    decode_error, decode_ifname, frame, FrameReader, StartRequest, KIND_ERROR, KIND_OK,
    KIND_PACKET, KIND_PING, KIND_START, KIND_STARTED, KIND_STOP, SOCKET_PATH,
};

/// How long to wait for the daemon to bring the interface up (`ifconfig`,
/// `route`, `scutil`).
const SETUP_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a status ping waits for its reply. Short: called from the UI.
const PING_TIMEOUT: Duration = Duration::from_millis(300);

/// How long `stop` waits for a parting reply before giving up.
const STOP_REPLY_TIMEOUT: Duration = Duration::from_millis(50);

/// How many bytes may wait for the daemon to drain its socket. Bounds memory
/// and turns sustained backpressure into dropped packets.
const PENDING_LIMIT: usize = 256 * 1024;

/// A connection to the privileged helper daemon.
///
/// The socket is non-blocking: every read and write takes what the kernel has
/// room for *right now* and returns. A blocking socket with timeouts is what
/// wedged the relay: unix sockets here have 8 KB buffers, so every saturated
/// write burned its whole timeout while moving almost nothing, and both ends
/// settled into moving a few KB per timeout — far less than the Wi-Fi link
/// supplies. Waiting is done with `poll` (or the bounded pending queue)
/// instead of blocking calls.
pub struct HelperClient {
    stream: UnixStream,
    reader: FrameReader,
    ifname: String,
    /// Outgoing bytes the daemon has not read yet (the socket was full). Frames
    /// are appended in order, so the daemon's frame reader reassembles them
    /// exactly.
    pending: Vec<u8>,
    /// Why the connection is unusable, once noticed. A dead daemon cannot be
    /// talked to again, so the relay is told to rebuild the link instead of
    /// waiting for the stall watchdog.
    broken: Option<String>,
}

impl HelperClient {
    /// Connect to the daemon's socket. Fails when the helper is not installed
    /// or not running.
    pub fn connect() -> io::Result<Self> {
        let stream = UnixStream::connect(SOCKET_PATH)?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            reader: FrameReader::default(),
            ifname: String::new(),
            pending: Vec::new(),
            broken: None,
        })
    }

    /// True when a daemon is reachable and answering. Uses a short timeout so it
    /// is safe to call from the UI thread.
    pub fn is_available() -> bool {
        match Self::connect() {
            Ok(mut client) => client.ping().is_ok(),
            Err(_) => false,
        }
    }

    /// liveness check.
    pub fn ping(&mut self) -> io::Result<()> {
        self.write_control(&frame(KIND_PING, &[]), PING_TIMEOUT)?;
        let (kind, body) = self.read_message(PING_TIMEOUT)?;
        match kind {
            KIND_OK => Ok(()),
            KIND_ERROR => Err(io::Error::other(decode_error(&body))),
            _ => Err(io::Error::other("unexpected reply from the helper")),
        }
    }

    /// Ask the daemon to create and configure the interface.
    pub fn start(&mut self, request: &StartRequest) -> Result<(), String> {
        self.write_control(&frame(KIND_START, &request.encode()), SETUP_TIMEOUT)
            .map_err(|error| format!("helper write failed: {error}"))?;
        let (kind, body) = self
            .read_message(SETUP_TIMEOUT)
            .map_err(|error| format!("helper did not answer: {error}"))?;
        match kind {
            KIND_STARTED => {
                self.ifname = decode_ifname(&body)
                    .ok_or_else(|| "malformed interface name from the helper".to_string())?;
                Ok(())
            }
            KIND_ERROR => Err(decode_error(&body)),
            _ => Err("unexpected reply from the helper".to_string()),
        }
    }

    /// Send one IP packet to the daemon, to be written to `utun`.
    ///
    /// The packet is queued first, then everything the socket accepts right
    /// now is written; the rest stays queued for the next call (or the
    /// relay's per-iteration `flush`). Draining is attempted even when the
    /// queue is already full — a full queue that is only ever flushed by a
    /// successful append could never drain again. An error then means the
    /// packet was dropped: the queue is full (the daemon is not draining) or
    /// the connection died.
    pub fn send_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if let Some(problem) = self.broken.clone() {
            return Err(io::Error::other(problem));
        }
        // Move the backlog before deciding: at the cap this is the only thing
        // that creates room, and skipping it would turn one burst that filled
        // the queue into a queue that never drains again.
        self.flush_pending();
        if let Some(problem) = self.broken.clone() {
            return Err(io::Error::other(problem));
        }
        let frame = frame(KIND_PACKET, packet);
        if self.pending.len() + frame.len() > PENDING_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the helper is not draining its socket; packet dropped",
            ));
        }
        self.pending.extend_from_slice(&frame);
        self.flush_pending();
        match &self.broken {
            Some(problem) => Err(io::Error::other(problem.clone())),
            None => Ok(()),
        }
    }

    /// Hand the socket everything it will take without blocking. A write that
    /// reports `WouldBlock` stops the loop: the kernel buffer is full and the
    /// rest waits for the next call. The daemon's frame reader reassembles the
    /// stream exactly, so a partially delivered buffer is safe to finish later.
    fn flush_pending(&mut self) {
        while !self.pending.is_empty() && self.broken.is_none() {
            match self.stream.write(&self.pending) {
                Ok(0) => {
                    self.broken
                        .get_or_insert_with(|| "the helper closed the connection".to_string());
                }
                Ok(length) => {
                    self.pending.drain(..length);
                }
                Err(error) if is_would_block(&error) => break,
                Err(error) => {
                    self.broken
                        .get_or_insert_with(|| format!("helper write failed: {error}"));
                }
            }
        }
    }

    /// Write a small control frame, waiting for room if the socket is briefly
    /// full. Data packets go through the queue instead; this is for the few
    /// bytes of the handshake, where giving up too early would leave the relay
    /// without a tunnel.
    fn write_control(&mut self, bytes: &[u8], within: Duration) -> io::Result<()> {
        let deadline = Instant::now() + within;
        let mut written = 0;
        while written < bytes.len() {
            match self.stream.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "the helper closed the connection",
                    ))
                }
                Ok(length) => written += length,
                Err(error) if is_would_block(&error) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() || !wait_for(&self.stream, libc::POLLOUT, remaining)? {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the helper is not reading its socket",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Read one message, waiting up to `within` for it.
    fn read_message(&mut self, within: Duration) -> io::Result<(u8, Vec<u8>)> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(message) = self.reader.next() {
                return Ok(message);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the helper did not answer in time",
                ));
            }
            if !wait_for(&self.stream, libc::POLLIN, remaining)? {
                continue;
            }
            let mut buffer = [0u8; 4096];
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the helper closed the connection",
                    ))
                }
                Ok(length) => self.reader.extend(&buffer[..length]),
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

impl PacketTun for HelperClient {
    fn read_packet(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            while let Some((kind, body)) = self.reader.next() {
                if kind == KIND_PACKET {
                    return Some(body);
                }
                // Ignore any control message during the relay.
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match wait_for(&self.stream, libc::POLLIN, remaining) {
                Ok(true) => {}
                Ok(false) => return None,
                Err(error) => {
                    self.broken
                        .get_or_insert_with(|| format!("helper poll failed: {error}"));
                    return None;
                }
            }
            let mut buffer = [0u8; 8192];
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    self.broken
                        .get_or_insert_with(|| "the helper closed the connection".to_string());
                    return None;
                }
                Ok(length) => self.reader.extend(&buffer[..length]),
                Err(error) if is_would_block(&error) => {}
                Err(error) => {
                    self.broken
                        .get_or_insert_with(|| format!("helper read failed: {error}"));
                    return None;
                }
            }
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        self.send_packet(packet).map_err(|error| error.to_string())
    }

    fn flush(&mut self) {
        self.flush_pending();
    }
}

impl TunnelLink for HelperClient {
    fn name(&self) -> String {
        self.ifname.clone()
    }

    fn stop(&mut self) {
        // Keep the stop request behind any queued packets so the daemon sees
        // it last. A connection that is already broken has nothing to do.
        if self.broken.is_none() {
            self.pending.extend_from_slice(&frame(KIND_STOP, &[]));
            self.flush_pending();
        }
        let _ = self.read_message(STOP_REPLY_TIMEOUT);
    }

    fn health(&self) -> Option<String> {
        self.broken.clone()
    }
}

/// The error message to show when the helper cannot be reached.
pub fn unavailable_message(error: &io::Error) -> String {
    format!(
        "the privileged helper is not running ({error}). Install it once with \
         `sudo mt7601u-macos --install-helper` (or run the GUI with sudo)"
    )
}

/// Non-blocking sockets report `WouldBlock` instead of waiting; a timeout can
/// still turn up from an inherited socket option, and means the same thing.
fn is_would_block(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Wait until `events` fire on the socket or `timeout` passes. Returns whether
/// the socket is ready. Polling is how this non-blocking client waits.
fn wait_for(stream: &UnixStream, events: libc::c_short, timeout: Duration) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events,
        revents: 0,
    };
    let millis = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
    loop {
        // SAFETY: poll with one valid pollfd.
        let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        return Ok(ready > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::{encode_error, encode_ifname};
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixListener;

    /// A one-shot daemon that answers a `Start` and then relays one packet.
    fn spawn_fake_daemon(listener: UnixListener) {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = FrameReader::default();
            let mut buffer = [0u8; 1024];
            // Wait for the START request.
            loop {
                let length = stream.read(&mut buffer).unwrap();
                reader.extend(&buffer[..length]);
                if let Some((kind, body)) = reader.next() {
                    assert_eq!(kind, KIND_START);
                    let request = StartRequest::decode(&body).unwrap();
                    assert_eq!(request.local, Ipv4Addr::new(10, 0, 0, 5));
                    break;
                }
            }
            stream
                .write_all(&frame(KIND_STARTED, &encode_ifname("utun9")))
                .unwrap();
            // Echo the first packet straight back.
            loop {
                let length = stream.read(&mut buffer).unwrap();
                reader.extend(&buffer[..length]);
                if let Some((kind, body)) = reader.next() {
                    assert_eq!(kind, KIND_PACKET);
                    stream.write_all(&frame(KIND_PACKET, &body)).unwrap();
                    break;
                }
            }
        });
    }

    fn temp_socket(tag: &str) -> (std::path::PathBuf, UnixListener) {
        // Unix socket paths are limited to ~104 bytes; keep the name short and
        // unique per test (they run in parallel in one process).
        let path = std::env::temp_dir().join(format!("mt7601u-{}-{tag}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        (path, listener)
    }

    fn client_for(path: &std::path::Path) -> HelperClient {
        let stream = UnixStream::connect(path).unwrap();
        stream.set_nonblocking(true).unwrap();
        HelperClient {
            stream,
            reader: FrameReader::default(),
            ifname: String::new(),
            pending: Vec::new(),
            broken: None,
        }
    }

    #[test]
    fn start_and_packet_round_trip() {
        let (path, listener) = temp_socket("roundtrip");
        spawn_fake_daemon(listener);

        let mut client = client_for(&path);
        client
            .start(&StartRequest {
                local: Ipv4Addr::new(10, 0, 0, 5),
                peer: Ipv4Addr::new(10, 0, 0, 1),
                mtu: 1500,
                router: Ipv4Addr::new(10, 0, 0, 1),
                dns: Vec::new(),
            })
            .unwrap();
        assert_eq!(client.name(), "utun9");

        client.write_packet(&[1, 2, 3, 4]).unwrap();
        assert_eq!(
            client.read_packet(Duration::from_millis(500)),
            Some(vec![1, 2, 3, 4])
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn start_surfaces_a_daemon_error() {
        let (path, listener) = temp_socket("error");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(&frame(KIND_ERROR, &encode_error("ifconfig failed")))
                .unwrap();
        });

        let mut client = client_for(&path);
        let error = client
            .start(&StartRequest {
                local: Ipv4Addr::LOCALHOST,
                peer: Ipv4Addr::LOCALHOST,
                mtu: 1500,
                router: Ipv4Addr::LOCALHOST,
                dns: Vec::new(),
            })
            .unwrap_err();
        assert!(error.contains("ifconfig failed"), "{error}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_closed_daemon_connection_marks_the_client_broken() {
        let (path, listener) = temp_socket("broken");
        std::thread::spawn(move || {
            // Answer the connection, then hang up: what a stopped or restarted
            // helper daemon looks like to the client.
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });

        let mut client = client_for(&path);
        assert_eq!(client.health(), None);
        assert_eq!(client.read_packet(Duration::from_millis(500)), None);
        let problem = client.health().expect("a hung-up daemon must be noticed");
        assert!(problem.contains("closed"), "unexpected message: {problem}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn writes_queue_under_backpressure_without_blocking() {
        // A daemon that connects but never reads: the client must queue what
        // the socket will not take and then drop, never block the relay or
        // mistake the backlog for a dead link.
        let (path, listener) = temp_socket("backpressure");
        std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
        });

        let mut client = client_for(&path);
        let packet = vec![0u8; 4000];
        let mut queued = 0usize;
        let error = loop {
            assert!(queued < 500, "the outgoing queue must cap");
            match client.write_packet(&packet) {
                Ok(()) => queued += 1,
                Err(error) => break error,
            }
        };
        assert!(
            queued > 8,
            "a burst should queue before dropping, not fail at once ({queued}: {error})"
        );
        assert_eq!(client.health(), None, "backpressure is not a dead link");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_full_queue_drains_once_the_daemon_reads_again() {
        // A daemon that ignores the socket long enough for the client's queue
        // to fill, then starts reading: the queued bytes must go out over the
        // same connection. A queue that is only flushed by a successful
        // append would stay full forever, which is exactly how a burst used
        // to wedge the relay until it was rebuilt.
        let (path, listener) = temp_socket("drain");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(300));
            let mut sink = [0u8; 4096];
            while let Ok(length) = stream.read(&mut sink) {
                if length == 0 {
                    break;
                }
            }
        });

        let mut client = client_for(&path);
        let packet = vec![0u8; 4000];
        let mut queued = 0usize;
        loop {
            assert!(queued < 500, "the outgoing queue must cap");
            match client.write_packet(&packet) {
                Ok(()) => queued += 1,
                Err(_) => break,
            }
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if client.write_packet(&packet).is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the queue never drained after the daemon read again"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(client.health(), None, "draining must not need a reconnect");

        let _ = std::fs::remove_file(&path);
    }
}
