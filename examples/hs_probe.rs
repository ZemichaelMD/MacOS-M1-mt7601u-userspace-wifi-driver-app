//! Handshake + data-path probe: associate with a WPA2 AP, confirm the AP
//! accepted message 4/4, then exercise the link (raw dump, ARP, DHCP).
//!
//! ```text
//! MT7601U_PSK=… cargo run --example hs_probe [ssid] [channel] [bssid]
//! ```

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use mt7601u_macos::mt7601u::{
    self,
    data::{StaLink, StaLinkInfo},
    rx, scan, station, Mt7601u,
};
use mt7601u_macos::net::{arp, dhcp};
use mt7601u_macos::paths;
use mt7601u_macos::usb::{enumerate, RusbTransport, Transport};

// `MT_RXINFO_*` (mac.h) — decoded here so the probe does not depend on the
// driver's own accessors.
const RXINFO_MULTICAST: u32 = 1 << 5;
const RXINFO_BROADCAST: u32 = 1 << 6;
const RXINFO_CRCERR: u32 = 1 << 8;
const RXINFO_ICVERR: u32 = 1 << 9;
const RXINFO_MICERR: u32 = 1 << 10;
const RXINFO_AMSDU: u32 = 1 << 11;
const RXINFO_L2PAD: u32 = 1 << 14;
const RXINFO_DECRYPT: u32 = 1 << 16;

fn open_chip() -> Result<Mt7601u<RusbTransport>, String> {
    let info = enumerate::find_mt7601u()
        .map_err(|error| format!("USB enumeration failed: {error}"))?
        .ok_or_else(|| {
            format!(
                "MT7601U ({:04x}:{:04x}) not detected",
                mt7601u::VENDOR_ID,
                mt7601u::PRODUCT_ID
            )
        })?;

    let mut transport =
        RusbTransport::open(&info).map_err(|error| format!("open failed: {error}"))?;
    transport
        .claim_interface(mt7601u::DEFAULT_INTERFACE)
        .map_err(|error| format!("claim interface 0 failed: {error}"))?;

    Ok(Mt7601u::new(transport, info))
}

fn mac(text: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (slot, part) in out.iter_mut().zip(text.split(':')) {
        *slot = u8::from_str_radix(part, 16).expect("bad MAC");
    }
    out
}

fn mac_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Dump every received segment for `seconds`, including management frames, with
/// the RXWI flags decoded. This is what shows a deauthentication, a beacon, or
/// a reply the client's own parser would have discarded.
fn dump_raw(chip: &Mt7601u<RusbTransport>, label: &str, seconds: f32) -> usize {
    let Ok(endpoint) = chip.rx_endpoint() else {
        return 0;
    };
    let mut buffer = vec![0u8; 16384];
    let deadline = Instant::now() + Duration::from_secs_f32(seconds);
    let mut seen = 0;

    while Instant::now() < deadline {
        let Ok(len) = chip
            .transport()
            .bulk_in(endpoint, &mut buffer, Duration::from_millis(100))
        else {
            continue;
        };
        for segment in rx::parse_segments(&buffer[..len]) {
            let frame = segment.payload;
            if frame.len() < 2 {
                continue;
            }
            let info = segment.rxwi.rxinfo;
            let fc = u16::from_le_bytes([frame[0], frame[1]]);
            if (fc >> 2) & 0x3 == 0 {
                // Beacon: mention it once per dump, then skip the detail.
                seen += 1;
                continue;
            }
            seen += 1;
            println!(
                "  [{label}] fc={fc:#06x} type={} sub={} len={} rxinfo={info:#010x} \
                 crc={} icv={} mic={} amsdu={} l2pad={} dec={} mc={} bc={} \
                 ctl={:#010x} a1={} a2={} a3={}",
                (fc >> 2) & 0x3,
                (fc >> 4) & 0xf,
                frame.len(),
                info & RXINFO_CRCERR != 0,
                info & RXINFO_ICVERR != 0,
                info & RXINFO_MICERR != 0,
                info & RXINFO_AMSDU != 0,
                info & RXINFO_L2PAD != 0,
                info & RXINFO_DECRYPT != 0,
                info & RXINFO_MULTICAST != 0,
                info & RXINFO_BROADCAST != 0,
                segment.rxwi.ctl,
                mac_str(&frame[4..10]),
                mac_str(&frame[10..16]),
                mac_str(&frame[16..22]),
            );
        }
    }
    println!("  [{label}] {seen} frame(s) in {seconds}s");
    seen
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .without_time()
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1);
    let ssid = args.next().unwrap_or_else(|| "HaLePo".to_string());
    let channel: u8 = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(11);
    let bssid = mac(&args
        .next()
        .unwrap_or_else(|| "98:25:4a:a7:53:8a".to_string()));

    let Some(psk) = std::env::var("MT7601U_PSK").ok() else {
        eprintln!("set MT7601U_PSK to the passphrase");
        return std::process::ExitCode::FAILURE;
    };

    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let firmware = paths::find_firmware();
    let (eeprom, mut state) = match scan::bringup(&chip, firmware.as_deref()) {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("bring-up failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    println!("MAC {}", eeprom.mac_string());

    for (label, result) in [
        (
            "set channel",
            chip.phy_set_channel(&eeprom, &mut state, channel),
        ),
        ("mac start", chip.mac_start()),
        ("agc reset", chip.agc_reset(eeprom.lna_gain)),
    ] {
        if let Err(error) = result {
            eprintln!("{label}: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }

    let target =
        station::BssTarget::infrastructure(ssid.clone(), bssid, channel, station::CAPABILITY_ESS);
    let snonce = match station::random_bytes::<32>() {
        Ok(nonce) => nonce,
        Err(error) => {
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let started = Instant::now();
    let association = match station::associate_wpa2(&chip, &eeprom, &target, psk.as_bytes(), snonce)
    {
        Ok(association) => association,
        Err(error) => {
            eprintln!("association failed after {:?}: {error}", started.elapsed());
            return std::process::ExitCode::FAILURE;
        }
    };
    println!(
        "associate_wpa2 took {:?}: AID {} handshake_confirmed={}",
        started.elapsed(),
        association.aid,
        association.handshake_confirmed
    );

    // Everything below runs on the encrypted link.
    let info = StaLinkInfo::new(eeprom.mac_addr, bssid, false).encrypted();

    println!("\n--- raw dump right after the handshake ---");
    dump_raw(&chip, "post-hs", 4.0);

    // Reachability: an ARP reply is unicast and pairwise-encrypted, so it also
    // proves the RX decryption path works at all.
    println!("\n--- ARP for candidate gateways ---");
    for target_ip in [
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 4, 1),
        Ipv4Addr::new(10, 0, 0, 1),
    ] {
        let request = arp::request(&eeprom.mac_addr, Ipv4Addr::new(192, 168, 0, 250), target_ip);
        if let Err(error) = chip.tx_payload_to(&info, &[0xff; 6], arp::ETHERTYPE_ARP, &request) {
            println!("  send ARP for {target_ip}: {error}");
            continue;
        }
        let reply = chip.recv_payload(&info, Duration::from_millis(1200), arp::ETHERTYPE_ARP);
        match reply.and_then(|payload| arp::parse(&payload.payload)) {
            Some(reply) => println!(
                "  ARP reply from {target_ip}: {} is at {} <-- LINK IS UP",
                reply.sender_ip,
                mac_str(&reply.sender_mac)
            ),
            None => println!("  no ARP reply from {target_ip}"),
        }
    }

    println!("\n--- DHCP over the link ---");
    let link = StaLink::new(&chip, info);
    chip.start_frame_trace();
    let lease = dhcp::obtain(&link, &eeprom.mac_addr, 0x7a11_5eed);
    chip.stop_frame_trace();

    match &lease {
        Ok(lease) => println!(
            "LEASE {} mask {} router {} dns {:?} server {} lease {}s",
            lease.address,
            lease.subnet_mask,
            lease.router,
            lease.dns,
            lease.server,
            lease.lease_secs
        ),
        Err(error) => println!("DHCP failed: {error}"),
    }

    let trace = chip.frame_trace();
    println!("\nframes seen during the DHCP exchange ({}):", trace.len());
    for frame in trace.iter().take(24) {
        println!("  {}", frame.line());
    }

    // End-to-end IP: with a lease in hand, ping through the AP. Everything is
    // addressed to the AP as the next hop, and the router ARPs for our new
    // address first, so the probe answers that too.
    if let Ok(lease) = &lease {
        println!("\n--- ICMP through the lease ---");
        for target in [Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(8, 8, 8, 8)] {
            let mut echo = vec![8u8, 0, 0, 0, 0, 1, 0, 1];
            echo.extend_from_slice(b"mt7601u-echo");
            let sum = mt7601u_macos::net::ipv4::checksum(&echo);
            echo[2..4].copy_from_slice(&sum.to_be_bytes());
            let packet = mt7601u_macos::net::ipv4::build(
                lease.address,
                target,
                0x1234,
                1, // ICMP
                &echo,
            );
            chip.tx_payload_to(&info, &bssid, 0x0800, &packet)
                .expect("ICMP echo");

            let started = Instant::now();
            let mut replied = false;
            while started.elapsed() < Duration::from_secs(4) && !replied {
                let Some(payload) = chip.recv_frame(&info, Duration::from_millis(300)) else {
                    continue;
                };
                if payload.ethertype == 0x0806 {
                    if let Some(request) = arp::parse(&payload.payload) {
                        if request.operation == arp::OP_REQUEST
                            && request.target_ip == lease.address
                        {
                            let reply = arp::reply(
                                &eeprom.mac_addr,
                                lease.address,
                                &request.sender_mac,
                                request.sender_ip,
                            );
                            println!(
                                "  ARP request for {} from {} — replying",
                                lease.address, request.sender_ip
                            );
                            let _ = chip.tx_payload_to(&info, &request.sender_mac, 0x0806, &reply);
                        }
                    }
                } else if payload.ethertype == 0x0800 {
                    if let Some(ip) = mt7601u_macos::net::ipv4::parse(&payload.payload) {
                        if ip.source == target && !ip.payload.is_empty() && ip.payload[0] == 0 {
                            println!("  ICMP echo reply from {}", ip.source);
                            replied = true;
                        }
                    }
                }
            }
            println!(
                "  ping {target}: {}",
                if replied { "REPLIED" } else { "no reply" }
            );
        }
    }

    // A last look at the link, so a deauthentication or a late reply shows up.
    println!("\n--- raw dump after the DHCP attempt ---");
    dump_raw(&chip, "post-dhcp", 4.0);

    if lease.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
