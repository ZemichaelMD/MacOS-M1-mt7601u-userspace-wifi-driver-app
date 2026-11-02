//! A thread that keeps one bulk IN transfer armed while a link is up.
//!
//! The MT7601U's USB receive engine does not tolerate a starved or cancelled
//! receive path: the reference drivers never cancel receive transfers — the
//! kernel driver keeps several URBs queued at all times, and the vendor driver
//! does the same — and a host that stops feeding the device receive buffers
//! while it pushes a long transmit batch can leave the device's USB DMA engine
//! permanently busy. Once that happens no transfer completes again and the
//! link is dead until the device is re-initialised.
//!
//! A single relay thread cannot honour that constraint: it must alternately
//! read, parse, transmit and write to the tunnel, and every read has to carry
//! a timeout so the other directions get a turn. This module moves the reads
//! to a thread of their own, which re-arms the next transfer the moment the
//! previous one completes and holds whole buffers for the relay to collect.
//! That mirrors the reference drivers: no cancellation while the link is
//! live, and no window in which the device has nothing to fill.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::enumerate::UsbError;
use super::transport::Transport;

/// How long one receive read waits before it is re-armed.
///
/// A read that runs out its timeout is cancelled by `libusb`, which is what
/// this module exists to avoid, so the value is chosen to never elapse on a
/// live link: beacons alone arrive roughly every 100 ms, hence one second of
/// silence means the link has genuinely stopped receiving. Only then does a
/// cancelled read make sense — re-arming (rather than dying) is still the
/// right response for a device that has merely gone quiet.
const READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Receive buffers held for the consumer before the reader pauses.
///
/// Sized so the reader never has to pause for a relay iteration that is
/// delayed by a transmit timeout or a slow tunnel write; 1024 × 16 KiB is
/// far more than any iteration can consume.
const QUEUE_DEPTH: usize = 1024;

/// How long the reader waits between attempts to hand a buffer over when the
/// queue is full, before checking the stop flag again.
const FULL_PAUSE: Duration = Duration::from_millis(2);

/// Keeps a bulk IN transfer armed on a transport's receive endpoint.
pub struct RxPump {
    receiver: Receiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    failure: Arc<Mutex<Option<String>>>,
    /// Whether a failure has already been handed to the consumer.
    reported: AtomicBool,
}

impl RxPump {
    /// Start reading `endpoint` from `transport`, in whole-buffer transfers of
    /// `buffer_len` bytes.
    pub fn start<T: Transport + Send + 'static>(
        transport: T,
        endpoint: u8,
        buffer_len: usize,
    ) -> Self {
        let (sender, receiver) = sync_channel(QUEUE_DEPTH);
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let thread = {
            let stop = Arc::clone(&stop);
            let failure = Arc::clone(&failure);
            thread::Builder::new()
                .name("mt7601u-rx".to_string())
                .spawn(move || {
                    let mut buffer = vec![0u8; buffer_len];
                    while !stop.load(Ordering::Relaxed) {
                        match transport.bulk_in(endpoint, &mut buffer, READ_TIMEOUT) {
                            // One frame or more. Hand the buffer over whole —
                            // it may carry several aggregated frames.
                            Ok(len) if len >= 2 => {
                                let mut pending = Some(buffer[..len].to_vec());
                                while let Some(data) = pending.take() {
                                    if stop.load(Ordering::Relaxed) {
                                        return;
                                    }
                                    match sender.try_send(data) {
                                        Ok(()) => {}
                                        Err(TrySendError::Full(data)) => {
                                            pending = Some(data);
                                            thread::sleep(FULL_PAUSE);
                                        }
                                        // The consumer is gone.
                                        Err(TrySendError::Disconnected(_)) => return,
                                    }
                                }
                            }
                            // A zero-length transfer is the device's packet
                            // terminator; there is simply nothing to hand over.
                            Ok(_) => {}
                            // An idle link, not an error: keep the transfer armed.
                            Err(UsbError::Libusb(rusb::Error::Timeout)) => {}
                            // The endpoint itself failed (the device was
                            // unplugged, say). Report it and stop.
                            Err(error) => {
                                *failure.lock().expect("rx pump failure lock") =
                                    Some(error.to_string());
                                return;
                            }
                        }
                    }
                })
                .expect("spawn the receive reader")
        };

        Self {
            receiver,
            stop,
            thread: Some(thread),
            failure,
            reported: AtomicBool::new(false),
        }
    }

    /// Buffers received since the last call, oldest first, at most `max`.
    ///
    /// Never blocks: the relay calls it once per iteration and picks the next
    /// batch up on the following one.
    pub fn drain(&self, max: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < max {
            match self.receiver.try_recv() {
                Ok(buffer) => out.push(buffer),
                Err(_) => break,
            }
        }
        out
    }

    /// Why the reader stopped on its own, if it did.
    ///
    /// Reported once: a hard transfer error, or the thread ending for any
    /// other reason (`None` while it is running normally).
    pub fn take_failure(&self) -> Option<String> {
        if self.reported.load(Ordering::Relaxed) {
            return None;
        }
        if let Some(message) = self.failure.lock().expect("rx pump failure lock").take() {
            self.reported.store(true, Ordering::Relaxed);
            return Some(message);
        }
        if self
            .thread
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
        {
            self.reported.store(true, Ordering::Relaxed);
            return Some("the receive reader stopped unexpectedly".to_string());
        }
        None
    }

    /// Ask the reader to stop and wait for it to finish.
    ///
    /// This is the one place a receive transfer may be cancelled: the link is
    /// about to be torn down, and the device re-initialised (or released)
    /// right after, so nothing can be left armed on it anyway.
    pub fn stop(&mut self) {
        if let Some(handle) = self.thread.take() {
            self.stop.store(true, Ordering::Relaxed);
            let _ = handle.join();
        }
    }
}

impl Drop for RxPump {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{MockTransport, RX_ENDPOINT};

    /// Collect at least `count` buffers, or give up after five seconds.
    fn drain_until(pump: &RxPump, count: usize) -> Vec<Vec<u8>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut out = Vec::new();
        while out.len() < count && std::time::Instant::now() < deadline {
            out.extend(pump.drain(8));
            if out.len() < count {
                thread::sleep(Duration::from_millis(2));
            }
        }
        out
    }

    #[test]
    fn hands_over_queued_buffers_in_order() {
        let transport = MockTransport::default();
        transport.time_out_empty_bulk_in();
        transport.push_rx_frame(vec![1, 2, 3, 4]);
        // A zero-length terminator must be skipped, not handed over.
        transport.push_rx_frame(Vec::new());
        transport.push_rx_frame(vec![9, 8]);

        let pump = RxPump::start(transport, RX_ENDPOINT, 64);
        let buffers = drain_until(&pump, 2);

        assert_eq!(buffers, vec![vec![1, 2, 3, 4], vec![9, 8]]);
        assert!(pump.take_failure().is_none());
    }

    #[test]
    fn idle_timeouts_do_not_stop_the_reader() {
        let transport = MockTransport::default();
        transport.time_out_empty_bulk_in();
        transport.push_rx_frame(vec![7, 7, 7]);

        let pump = RxPump::start(transport, RX_ENDPOINT, 64);
        assert_eq!(drain_until(&pump, 1), vec![vec![7, 7, 7]]);

        // The reader is now cycling through timed-out reads; none may be
        // reported as a failure, and the pump must still be usable.
        thread::sleep(Duration::from_millis(30));
        assert!(pump.take_failure().is_none());
        assert!(pump.drain(8).is_empty());
    }

    #[test]
    fn a_hard_read_error_is_reported_once() {
        let transport = MockTransport::default();
        transport.push_rx_frame(vec![5, 6]);

        // With no timeout behaviour configured, an empty read is a hard error,
        // as a disconnected device would produce.
        let pump = RxPump::start(transport, RX_ENDPOINT, 64);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let failure = loop {
            if let Some(failure) = pump.take_failure() {
                break failure;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no failure reported within five seconds"
            );
            thread::sleep(Duration::from_millis(2));
        };
        assert!(failure.contains("bulk-in"), "unexpected message: {failure}");

        // The buffer read before the error is still handed over.
        assert_eq!(pump.drain(8), vec![vec![5, 6]]);
        assert!(pump.take_failure().is_none());
    }

    #[test]
    fn stop_joins_and_is_safe_to_repeat() {
        let transport = MockTransport::default();
        transport.time_out_empty_bulk_in();
        let mut pump = RxPump::start(transport, RX_ENDPOINT, 64);
        pump.stop();
        pump.stop();
        assert!(pump.drain(8).is_empty());
    }
}
