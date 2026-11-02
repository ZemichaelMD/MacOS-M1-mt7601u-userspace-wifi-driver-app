//! Daemon half of the privileged helper, plus its installer.
//!
//! The daemon runs as root under launchd (`--helper-daemon`). It creates the
//! `utun` interface, runs `ifconfig`/`route`/`scutil` and shuffles IP packets
//! between that interface and the connected GUI over a Unix socket.
//!
//! Wire protocol: see [`super`].

use std::collections::VecDeque;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use crate::tunnel::relay::{PacketTun, MAX_BATCH};
use crate::tunnel::{self, Utun};

use super::{
    encode_error, encode_ifname, frame, FrameReader, StartRequest, HELPER_BINARY, KIND_ERROR,
    KIND_OK, KIND_PACKET, KIND_PING, KIND_START, KIND_STARTED, KIND_STOP, LABEL, PLIST_PATH,
    SOCKET_GID, SOCKET_PATH,
};

/// How long a relay iteration may block, per direction. Small: the relay moves
/// whole batches per iteration, so this only bounds how long an idle link waits
/// before the other direction is serviced.
const POLL: Duration = Duration::from_millis(4);
/// Read timeout while waiting for the client's first message.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
/// Per-round ceiling on bytes drained from the client socket, so a flood
/// cannot make a single round run forever.
const READ_BUDGET: usize = 256 * 1024;
/// Idle wait when a relay round moved nothing (no socket traffic, no packets).
const IDLE_WAIT: Duration = Duration::from_millis(2);
/// Upper bound on bytes queued toward the client. Keeps memory bounded and
/// suspends reading `utun` while the client is behind, so backpressure lands on
/// the network stack instead of growing this buffer.
const PENDING_LIMIT: usize = 256 * 1024;
/// How many downlink packets the relay may hold while the interface's kernel
/// queue is full. Bounded so a stuck interface costs a fixed amount of memory
/// and drops like a NIC would, instead of ever stalling the relay.
const INJECT_LIMIT: usize = 64;

/// Run the daemon until the process is killed. Intended for launchd.
pub fn run_daemon() -> io::Result<()> {
    // A stale socket from a previous run would make `bind` fail.
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;
    harden_socket(SOCKET_PATH)?;
    tracing::info!("privileged helper listening on {SOCKET_PATH}");

    // Sessions are served one at a time; the accept thread feeds this queue.
    let (session_tx, session_rx) = mpsc::channel::<(UnixStream, Vec<u8>)>();
    let relaying = Arc::new(AtomicBool::new(false));

    // Accept on a thread of its own so status pings are answered even while a
    // relay session occupies this loop. Without it, a client's probe (300 ms
    // timeout) fails during relaying, and the GUI wrongly concludes the helper
    // is gone — offering to reinstall it, which would kill the live session.
    let shared = Arc::clone(&relaying);
    std::thread::spawn(move || accept_loop(listener, session_tx, shared));

    for (stream, start) in session_rx {
        if let Err(error) = serve(stream, Some(start), Arc::clone(&relaying)) {
            tracing::warn!("helper session ended: {error}");
        }
    }
    Ok(())
}

/// Accept connections forever, answering pings inline and queueing starts.
fn accept_loop(
    listener: UnixListener,
    session_tx: mpsc::Sender<(UnixStream, Vec<u8>)>,
    relaying: Arc<AtomicBool>,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_connection(stream, &relaying, &session_tx),
            Err(error) => tracing::warn!("helper accept failed: {error}"),
        }
    }
}

/// Route one accepted connection: answer a ping straight away, queue a start,
/// or refuse a second session with a clear message.
fn handle_connection(
    mut stream: UnixStream,
    relaying: &AtomicBool,
    session_tx: &mpsc::Sender<(UnixStream, Vec<u8>)>,
) {
    match read_first_frame(&mut stream) {
        // A ping is a status probe: it must succeed even during a relay.
        Some((KIND_PING, _)) => {
            let _ = stream.write_all(&frame(KIND_OK, &[]));
        }
        Some((KIND_START, body)) => {
            if relaying.load(Ordering::SeqCst) {
                // Two callers rarely share one dongle gracefully; say so
                // instead of letting the second one time out.
                let _ = stream.write_all(&frame(
                    KIND_ERROR,
                    &encode_error(
                        "the helper is already relaying for another session \
                         (is a second app instance running?)",
                    ),
                ));
            } else {
                // The receiver only goes away when the daemon is stopping.
                let _ = session_tx.send((stream, body));
            }
        }
        _ => {}
    }
}

/// Read one complete frame, waiting up to the handshake timeout for it.
fn read_first_frame(stream: &mut UnixStream) -> Option<(u8, Vec<u8>)> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok()?;
    let mut reader = FrameReader::default();
    let mut buffer = [0u8; 8192];
    loop {
        if let Some(message) = reader.next() {
            return Some(message);
        }
        match stream.read(&mut buffer) {
            Ok(0) => return None,
            Ok(length) => reader.extend(&buffer[..length]),
            Err(error) if is_timeout(&error) => return None,
            Err(_) => return None,
        }
    }
}

/// Own the socket as `root:admin` and make it group-writable, so the interactive
/// user can reach the daemon without the socket being world-writable.
fn harden_socket(path: &str) -> io::Result<()> {
    let c = CString::new(path).map_err(|_| io::Error::other("bad socket path"))?;
    // SAFETY: `c` is a valid NUL-terminated path.
    if unsafe { libc::chown(c.as_ptr(), 0, SOCKET_GID) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `c` is a valid NUL-terminated path.
    if unsafe { libc::chmod(c.as_ptr(), 0o660) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bounded staging area between the client's downlink packets and the `utun`.
///
/// The relay must never block writing into the interface: a write that waits
/// for the kernel's queue stalls the loop, and the client then sees downlink
/// traffic freeze while its own queue fills. Packets the interface will not
/// take right now stay here, in order, and are retried at the start of the
/// next round; a backlog beyond [`INJECT_LIMIT`] drops like a NIC would.
#[derive(Default)]
struct InjectQueue {
    frames: VecDeque<Vec<u8>>,
    /// Set once the interface reports a full queue, for a single log line.
    busy: bool,
    /// Packets dropped because the queue stayed full or the interface errored.
    dropped: u64,
}

impl InjectQueue {
    /// Stage one packet, dropping it when the backing queue is already full.
    fn push(&mut self, packet: Vec<u8>) {
        if self.frames.len() < INJECT_LIMIT {
            self.frames.push_back(packet);
        } else {
            self.dropped += 1;
        }
    }

    /// Feed queued packets to `write` in order until it reports the interface
    /// busy (`WouldBlock`) or the queue empties. Any other error drops only
    /// the packet that caused it; the relay keeps going either way.
    fn deliver(&mut self, mut write: impl FnMut(&[u8]) -> io::Result<()>) {
        while let Some(front) = self.frames.front() {
            match write(front) {
                Ok(()) => {
                    self.frames.pop_front();
                }
                Err(error) if is_timeout(&error) => {
                    self.busy = true;
                    break;
                }
                Err(_) => {
                    self.frames.pop_front();
                    self.dropped += 1;
                }
            }
        }
    }
}

/// Block until the client socket has data (or room, when a write is waiting)
/// or the interface has a packet, up to `wait`. Called only after a round
/// moved nothing, so an idle relay sleeps instead of spinning.
fn wait_for_work(
    stream: &UnixStream,
    utun: &Utun,
    for_client_write: bool,
    for_utun_read: bool,
    wait: Duration,
) {
    let mut fds = [
        libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN | if for_client_write { libc::POLLOUT } else { 0 },
            revents: 0,
        },
        libc::pollfd {
            fd: utun.as_raw_fd(),
            events: if for_utun_read { libc::POLLIN } else { 0 },
            revents: 0,
        },
    ];
    // SAFETY: poll with two valid pollfds. Errors are not actionable here;
    // the next round simply tries again.
    let _ = unsafe { libc::poll(fds.as_mut_ptr(), 2, wait.as_millis() as i32) };
}

/// Handle one client: take its `Start` (already read by the accept thread, or
/// waited for here), bring the interface up, then relay until the client
/// disconnects or asks to stop.
fn serve(
    mut stream: UnixStream,
    first_start: Option<Vec<u8>>,
    relaying: Arc<AtomicBool>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut reader = FrameReader::default();
    let mut preloaded = first_start;
    let mut buffer = [0u8; 8192];

    // --- handshake: take the Start, answering pings ---
    let request = loop {
        let mut start = preloaded.take();
        while let Some((kind, body)) = reader.next() {
            match kind {
                KIND_START => {
                    start = Some(body);
                    break;
                }
                KIND_PING => stream.write_all(&frame(KIND_OK, &[]))?,
                _ => {}
            }
        }
        if let Some(body) = start {
            match StartRequest::decode(&body) {
                Some(request) => break request,
                None => {
                    let _ = stream.write_all(&frame(KIND_ERROR, &encode_error("malformed Start")));
                    return Ok(());
                }
            }
        }

        match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(length) => reader.extend(&buffer[..length]),
            Err(error) if is_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    };

    // Claim the single session slot; cleared when this session ends.
    struct ClearOnDrop(Arc<AtomicBool>);
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    relaying.store(true, Ordering::SeqCst);
    let _clear = ClearOnDrop(Arc::clone(&relaying));

    // --- bring the interface up ---
    let mut utun = match bring_up(&request) {
        Ok(utun) => utun,
        Err(error) => {
            let _ = stream.write_all(&frame(KIND_ERROR, &encode_error(&error)));
            return Ok(());
        }
    };
    let name = utun.name().to_string();
    stream.write_all(&frame(KIND_STARTED, &encode_ifname(&name)))?;
    utun.set_nonblocking(true)?;
    stream.set_nonblocking(true)?;
    tracing::info!("relaying on {name}");

    // --- relay ---
    //
    // Nothing in this loop may block: the client socket is non-blocking and
    // drained until the kernel says "no more room", and the interface socket
    // is non-blocking with a bounded staging queue. A single time-limited
    // write per round is what used to stall the link — unix sockets here have
    // 8 KB buffers, so under load every round burned its whole write timeout
    // moving a few KB, both ends settled there, and the client's queue
    // overflowed until the app tore the tunnel down. Draining until
    // `WouldBlock` instead means the relay runs exactly as fast as the two
    // kernels can move bytes.
    let mut buffer = [0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
    let mut inject = InjectQueue::default();
    let mut busy_logged = false;
    loop {
        let t_inject = Instant::now();
        let mut moved = false;

        // Hand the interface whatever it would not take last round before
        // touching anything else: a saturated kernel queue must never stop
        // this loop from reading the client.
        let queued_before = inject.frames.len();
        inject.deliver(|packet| utun.try_write_packet(packet));
        moved |= inject.frames.len() < queued_before;
        if inject.busy && !busy_logged {
            busy_logged = true;
            tracing::info!(
                "the kernel queue for {name} is full; holding downlink packets until it drains"
            );
        }
        let t_socket = Instant::now();

        // Socket writes: everything the kernel takes right now, this round.
        let mut client_gone = false;
        while !pending.is_empty() {
            match stream.write(&pending) {
                Ok(0) => {
                    client_gone = true;
                    break;
                }
                Ok(length) => {
                    pending.drain(..length);
                    moved = true;
                }
                Err(error) if is_timeout(&error) => break,
                Err(_) => {
                    client_gone = true;
                    break;
                }
            }
        }
        if client_gone {
            break;
        }

        // Socket reads: drain the client, bounded per round.
        let mut budget = READ_BUDGET;
        while budget > 0 {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    client_gone = true;
                    break;
                }
                Ok(length) => {
                    reader.extend(&buffer[..length]);
                    budget = budget.saturating_sub(length);
                    moved = true;
                }
                Err(error) if is_timeout(&error) => break,
                Err(_) => {
                    client_gone = true;
                    break;
                }
            }
        }
        if client_gone {
            break;
        }
        let t_frames = Instant::now();

        let mut stop = false;
        while let Some((kind, body)) = reader.next() {
            moved = true;
            match kind {
                KIND_PACKET => {
                    inject.push(body);
                    inject.deliver(|packet| utun.try_write_packet(packet));
                }
                KIND_STOP => stop = true,
                KIND_PING => pending.extend_from_slice(&frame(KIND_OK, &[])),
                _ => {}
            }
        }
        if stop {
            break;
        }
        let t_utun = Instant::now();

        // Drain everything the interface has queued in one pass, but only
        // while the queue toward the client has room: a client that stops
        // reading must not make this buffer grow without bound.
        if pending.len() < PENDING_LIMIT {
            let batch = utun.read_batch(POLL, MAX_BATCH);
            if !batch.is_empty() {
                moved = true;
                for packet in batch {
                    pending.extend_from_slice(&frame(KIND_PACKET, &packet));
                }
            }
        }

        // A round has no reason to take this long. If one does, the phase
        // breakdown says which call misbehaved.
        let elapsed = t_inject.elapsed();
        if elapsed > Duration::from_secs(1) {
            tracing::warn!(
                "relay round took {elapsed:?} (inject {:?}, socket {:?}, frames {:?}, utun {:?})",
                t_socket - t_inject,
                t_frames - t_socket,
                t_utun - t_frames,
                Instant::now() - t_utun,
            );
        }

        if !moved {
            // Nothing to move anywhere: wait for data (or room) instead of
            // spinning, then go around.
            wait_for_work(
                &stream,
                &utun,
                !pending.is_empty(),
                pending.len() < PENDING_LIMIT,
                IDLE_WAIT,
            );
        }
    }

    utun.teardown();
    if inject.dropped > 0 {
        let dropped = inject.dropped;
        tracing::info!(
            "relay on {name} stopped; routes and DNS restored \
             ({dropped} downlink packets dropped: the kernel queue was full)"
        );
    } else {
        tracing::info!("relay on {name} stopped; routes and DNS restored");
    }
    Ok(())
}

/// Create and configure the interface as root.
fn bring_up(request: &StartRequest) -> Result<Utun, String> {
    let mut utun = Utun::open().map_err(|error| format!("could not create utun: {error}"))?;
    utun.configure(request.local, request.peer, request.mtu)
        .map_err(|error| format!("ifconfig failed: {error}"))?;
    utun.add_default_route()
        .map_err(|error| format!("adding routes failed: {error}"))?;
    if !request.dns.is_empty() {
        if let Err(error) = utun.set_dns(&request.dns, request.router) {
            tracing::warn!("setting DNS failed: {error}");
        }
    }
    Ok(utun)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Install the helper binary and its LaunchDaemon. Must run as root.
pub fn install() -> Result<String, String> {
    require_root()?;
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;

    // Replacing a running helper kills whatever relay session it was serving.
    // When the installed helper is already this exact program and it answers,
    // leave it alone: reinstalling the same build gains nothing.
    if installed_matches(&exe) {
        return Ok("helper already installed and running".to_string());
    }

    std::fs::create_dir_all("/Library/PrivilegedHelperTools")
        .map_err(|error| format!("could not create PrivilegedHelperTools: {error}"))?;
    std::fs::copy(&exe, HELPER_BINARY)
        .map_err(|error| format!("could not copy the helper to {HELPER_BINARY}: {error}"))?;
    chown(HELPER_BINARY, 0, 0)?;
    chmod(HELPER_BINARY, 0o755)?;

    std::fs::write(PLIST_PATH, plist_xml())
        .map_err(|error| format!("could not write {PLIST_PATH}: {error}"))?;
    chown(PLIST_PATH, 0, 0)?;
    chmod(PLIST_PATH, 0o644)?;

    // Replace any previous instance before bootstrapping.
    let _ = launchctl(&["bootout", "system", PLIST_PATH]);
    launchctl(&["bootstrap", "system", PLIST_PATH])?;
    let _ = launchctl(&["kickstart", "-k", &format!("system/{LABEL}")]);

    Ok(format!(
        "helper installed at {HELPER_BINARY} and loaded as {LABEL}"
    ))
}

/// Whether the installed helper binary and plist match `exe` and the daemon
/// answers. A mismatch (an upgrade) still reinstalls.
fn installed_matches(exe: &std::path::Path) -> bool {
    let same_binary = match (std::fs::read(exe), std::fs::read(HELPER_BINARY)) {
        (Ok(current), Ok(installed)) => current == installed,
        _ => false,
    };
    let same_plist = std::fs::read_to_string(PLIST_PATH)
        .map(|plist| plist == plist_xml())
        .unwrap_or(false);
    same_binary && same_plist && crate::helper::HelperClient::is_available()
}

/// Remove the LaunchDaemon and the helper binary. Must run as root.
pub fn uninstall() -> Result<String, String> {
    require_root()?;
    let _ = launchctl(&["bootout", "system", PLIST_PATH]);
    let _ = std::fs::remove_file(PLIST_PATH);
    let _ = std::fs::remove_file(HELPER_BINARY);
    let _ = std::fs::remove_file(SOCKET_PATH);
    Ok("helper uninstalled".to_string())
}

/// Whether the daemon is reachable from this process.
pub fn is_running() -> bool {
    crate::helper::HelperClient::is_available()
}

fn require_root() -> Result<(), String> {
    if tunnel::is_root() {
        Ok(())
    } else {
        Err("this command needs root (run it with sudo)".to_string())
    }
}

fn launchctl(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|error| format!("could not run launchctl: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(format!(
            "launchctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn chown(path: &str, uid: u32, gid: u32) -> Result<(), String> {
    let c = CString::new(path).map_err(|error| error.to_string())?;
    // SAFETY: `c` is a valid NUL-terminated path.
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        return Err(format!("chown {path}: {}", io::Error::last_os_error()));
    }
    Ok(())
}

fn chmod(path: &str, mode: libc::mode_t) -> Result<(), String> {
    let c = CString::new(path).map_err(|error| error.to_string())?;
    // SAFETY: `c` is a valid NUL-terminated path.
    if unsafe { libc::chmod(c.as_ptr(), mode) } != 0 {
        return Err(format!("chmod {path}: {}", io::Error::last_os_error()));
    }
    Ok(())
}

/// The LaunchDaemon property list, pointing at the installed helper copy.
pub fn plist_xml() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20   <key>Label</key><string>{LABEL}</string>\n\
         \x20   <key>ProgramArguments</key>\n\
         \x20   <array>\n\
         \x20       <string>{HELPER_BINARY}</string>\n\
         \x20       <string>--helper-daemon</string>\n\
         \x20   </array>\n\
         \x20   <key>RunAtLoad</key><true/>\n\
         \x20   <key>KeepAlive</key><true/>\n\
         \x20   <key>UserName</key><string>root</string>\n\
         \x20   <key>StandardOutPath</key><string>/var/log/mt7601u-helper.log</string>\n\
         \x20   <key>StandardErrorPath</key><string>/var/log/mt7601u-helper.log</string>\n\
         </dict>\n\
         </plist>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_points_at_the_installed_helper() {
        let plist = plist_xml();
        assert!(plist.contains(HELPER_BINARY));
        assert!(plist.contains("--helper-daemon"));
        assert!(plist.contains(LABEL));
    }

    #[test]
    fn timeout_detection_covers_wouldblock_and_timedout() {
        assert!(is_timeout(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(is_timeout(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(!is_timeout(&io::Error::from(io::ErrorKind::BrokenPipe)));
    }

    #[test]
    fn inject_queue_delivers_in_order_when_the_interface_accepts() {
        let mut queue = InjectQueue::default();
        queue.push(vec![1]);
        queue.push(vec![2]);
        let mut seen = Vec::new();
        queue.deliver(|packet| {
            seen.push(packet.to_vec());
            Ok(())
        });
        assert_eq!(seen, vec![vec![1], vec![2]]);
        assert!(queue.frames.is_empty());
        assert!(!queue.busy);
        assert_eq!(queue.dropped, 0);
    }

    #[test]
    fn inject_queue_holds_packets_while_the_interface_is_busy() {
        let mut queue = InjectQueue::default();
        queue.push(vec![1]);
        queue.push(vec![2]);
        queue.deliver(|_| Err(io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(queue.busy);
        assert_eq!(queue.frames.len(), 2);
        assert_eq!(queue.dropped, 0);

        // Once the interface takes packets again the queue drains in order.
        let mut seen = Vec::new();
        queue.deliver(|packet| {
            seen.push(packet.to_vec());
            Ok(())
        });
        assert_eq!(seen, vec![vec![1], vec![2]]);
    }

    #[test]
    fn inject_queue_drops_beyond_its_limit_like_a_nic_would() {
        let mut queue = InjectQueue::default();
        for packet in 0..INJECT_LIMIT + 3 {
            queue.push(vec![packet as u8]);
        }
        assert_eq!(queue.frames.len(), INJECT_LIMIT);
        assert_eq!(queue.dropped, 3);
    }

    #[test]
    fn inject_queue_drops_only_the_packet_that_errors() {
        let mut queue = InjectQueue::default();
        queue.push(vec![9, 9]);
        queue.push(vec![1]);
        let mut seen = Vec::new();
        queue.deliver(|packet| {
            if packet.first() == Some(&9) {
                Err(io::Error::other("interface went away"))
            } else {
                seen.push(packet.to_vec());
                Ok(())
            }
        });
        assert_eq!(seen, vec![vec![1]]);
        assert_eq!(queue.dropped, 1);
        assert!(queue.frames.is_empty());
        assert!(!queue.busy);
    }

    #[test]
    fn pings_are_answered_while_a_session_is_relaying() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let relaying = AtomicBool::new(true);
        let (tx, _rx) = mpsc::channel();
        std::thread::spawn(move || handle_connection(server, &relaying, &tx));

        client.write_all(&frame(KIND_PING, &[])).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buffer = [0u8; 64];
        let length = client.read(&mut buffer).unwrap();
        assert_eq!(&buffer[..length], frame(KIND_OK, &[]).as_slice());
    }

    #[test]
    fn a_second_start_is_refused_while_relaying() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let relaying = AtomicBool::new(true);
        let (tx, _rx) = mpsc::channel();
        std::thread::spawn(move || handle_connection(server, &relaying, &tx));

        client.write_all(&frame(KIND_START, &[0; 17])).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buffer = [0u8; 256];
        let length = client.read(&mut buffer).unwrap();
        let mut reader = FrameReader::default();
        reader.extend(&buffer[..length]);
        let Some((kind, body)) = reader.next() else {
            panic!("expected a reply to the refused start");
        };
        assert_eq!(kind, KIND_ERROR);
        let message = crate::helper::decode_error(&body);
        assert!(message.contains("already relaying"), "{message}");
    }

    #[test]
    fn a_start_is_queued_when_no_session_is_running() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let relaying = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || handle_connection(server, &relaying, &tx));

        client.write_all(&frame(KIND_START, &[7, 7, 7])).unwrap();
        let (_stream, body) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(body, vec![7, 7, 7]);
    }
}
