//! Minimal DHCPv4 client (RFC 2131), used to obtain an address from the AP
//! once the station is associated.
//!
//! The packet codec is pure; the exchange ([`obtain`]) runs over any
//! [`IpLink`], so it can be unit-tested with an in-memory link.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::ipv4::{self, PROTO_UDP};
use super::IpLink;

/// DHCP server port.
pub const SERVER_PORT: u16 = 67;
/// DHCP client port.
pub const CLIENT_PORT: u16 = 68;

/// Hostname advertised to the DHCP server (RFC 2132 option 12), so the AP's
/// client list shows a name instead of an unidentified MAC address.
pub const HOSTNAME: &str = "MT7601U-Dongle";

/// Minimum DHCP message length (RFC 2131 §2). Clients pad to at least this
/// size; a shorter DISCOVER is ignored outright by some servers.
const MIN_MESSAGE_LEN: usize = 300;

/// How many times to retransmit DISCOVER/REQUEST before giving up.
const DISCOVER_ATTEMPTS: u32 = 3;
/// How long to wait for each OFFER/ACK.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// DHCPDISCOVER message type.
pub const DISCOVER: u8 = 1;
/// DHCPOFFER message type.
pub const OFFER: u8 = 2;
/// DHCPREQUEST message type.
pub const REQUEST: u8 = 3;
/// DHCPACK message type.
pub const ACK: u8 = 5;

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const OP_BOOTREQUEST: u8 = 1;
const OP_BOOTREPLY: u8 = 2;
/// `htype` = Ethernet.
const HTYPE_ETHERNET: u8 = 1;
const BOOTP_LEN: usize = 236;
const FLAG_BROADCAST: u16 = 0x8000;

const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQUEST: u8 = 55;
const OPT_END: u8 = 255;

/// A lease obtained from the AP's DHCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub server: Ipv4Addr,
    pub lease_secs: u32,
}

/// A decoded DHCP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub xid: u32,
    pub message_type: u8,
    pub your_address: Ipv4Addr,
    pub server: Ipv4Addr,
    pub subnet_mask: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_secs: Option<u32>,
    pub client_mac: [u8; 6],
}

fn bootp(xid: u32, mac: &[u8; 6]) -> Vec<u8> {
    let mut message = vec![0u8; BOOTP_LEN];
    message[0] = OP_BOOTREQUEST;
    message[1] = HTYPE_ETHERNET;
    message[2] = 6; // hlen
    message[4..8].copy_from_slice(&xid.to_be_bytes());
    message[10..12].copy_from_slice(&FLAG_BROADCAST.to_be_bytes());
    message[28..34].copy_from_slice(mac); // chaddr
    message.extend_from_slice(&MAGIC_COOKIE);
    message
}

fn push_option(message: &mut Vec<u8>, code: u8, body: &[u8]) {
    message.push(code);
    message.push(body.len() as u8);
    message.extend_from_slice(body);
}

/// Pad a DHCP message to the RFC 2131 minimum length. The padding (option 0)
/// follows the END option, so parsers ignore it, but the on-wire message is
/// the length a server expects.
fn pad_to_minimum(message: &mut Vec<u8>) {
    if message.len() < MIN_MESSAGE_LEN {
        message.resize(MIN_MESSAGE_LEN, 0);
    }
}

/// Build a DHCPDISCOVER payload.
pub fn build_discover(xid: u32, mac: &[u8; 6]) -> Vec<u8> {
    let mut message = bootp(xid, mac);
    push_option(&mut message, OPT_MSG_TYPE, &[DISCOVER]);
    push_option(&mut message, OPT_HOSTNAME, HOSTNAME.as_bytes());
    push_option(
        &mut message,
        OPT_PARAM_REQUEST,
        &[OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS],
    );
    message.push(OPT_END);
    pad_to_minimum(&mut message);
    message
}

/// Build a DHCPREQUEST payload selecting `requested` from `server`.
pub fn build_request(xid: u32, mac: &[u8; 6], requested: Ipv4Addr, server: Ipv4Addr) -> Vec<u8> {
    let mut message = bootp(xid, mac);
    push_option(&mut message, OPT_MSG_TYPE, &[REQUEST]);
    push_option(&mut message, OPT_HOSTNAME, HOSTNAME.as_bytes());
    push_option(&mut message, OPT_REQUESTED_IP, &requested.octets());
    push_option(&mut message, OPT_SERVER_ID, &server.octets());
    push_option(
        &mut message,
        OPT_PARAM_REQUEST,
        &[OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS],
    );
    message.push(OPT_END);
    pad_to_minimum(&mut message);
    message
}

fn read_ipv4(body: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(body[0], body[1], body[2], body[3])
}

/// Parse a BOOTREPLY payload (a DHCP OFFER/ACK/NAK).
pub fn parse_reply(packet: &[u8]) -> Option<Reply> {
    if packet.len() < BOOTP_LEN + 4 || packet[0] != OP_BOOTREPLY {
        return None;
    }
    if packet[BOOTP_LEN..BOOTP_LEN + 4] != MAGIC_COOKIE {
        return None;
    }

    let mut client_mac = [0u8; 6];
    client_mac.copy_from_slice(&packet[28..34]);

    let mut reply = Reply {
        xid: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        message_type: 0,
        your_address: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        server: Ipv4Addr::UNSPECIFIED,
        subnet_mask: None,
        router: None,
        dns: Vec::new(),
        lease_secs: None,
        client_mac,
    };

    let mut cursor = BOOTP_LEN + 4;
    while cursor < packet.len() {
        let code = packet[cursor];
        if code == OPT_END {
            break;
        }
        if code == 0 {
            cursor += 1; // padding
            continue;
        }
        let length = usize::from(*packet.get(cursor + 1)?);
        let start = cursor + 2;
        let end = start + length;
        if end > packet.len() {
            break;
        }
        let body = &packet[start..end];
        match code {
            OPT_MSG_TYPE => reply.message_type = *body.first()?,
            OPT_SUBNET_MASK if body.len() >= 4 => reply.subnet_mask = Some(read_ipv4(body)),
            OPT_ROUTER if body.len() >= 4 => reply.router = Some(read_ipv4(body)),
            OPT_DNS => {
                reply.dns = body
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|chunk| read_ipv4(chunk.as_slice()))
                    .collect();
            }
            OPT_LEASE_TIME if body.len() >= 4 => {
                reply.lease_secs = Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
            }
            OPT_SERVER_ID if body.len() >= 4 => reply.server = read_ipv4(body),
            _ => {}
        }
        cursor = end;
    }

    (reply.message_type != 0).then_some(reply)
}

/// Wrap a DHCP payload as UDP to/from the broadcast address.
pub fn to_broadcast(payload: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    let udp = ipv4::build_udp(
        Ipv4Addr::UNSPECIFIED,
        source_port,
        Ipv4Addr::BROADCAST,
        destination_port,
        payload,
    );
    ipv4::build(
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        0,
        PROTO_UDP,
        &udp,
    )
}

/// Unwrap an inbound UDP packet addressed to the DHCP client port.
pub fn from_packet(packet: &[u8]) -> Option<Reply> {
    let ip = ipv4::parse(packet)?;
    if ip.protocol != PROTO_UDP {
        return None;
    }
    let (_, destination_port, payload) = ipv4::parse_udp(ip.payload)?;
    if destination_port != CLIENT_PORT {
        return None;
    }
    parse_reply(payload)
}

/// Run the DISCOVER → OFFER → REQUEST → ACK exchange over `link`.
///
/// Like a real client, the DISCOVER is retransmitted a few times: on a busy
/// link the first one can be lost, and association has only just completed.
pub fn obtain(link: &dyn IpLink, mac: &[u8; 6], xid: u32) -> Result<Lease, String> {
    let discover = to_broadcast(&build_discover(xid, mac), CLIENT_PORT, SERVER_PORT);
    let mut offer = None;
    for _ in 0..DISCOVER_ATTEMPTS {
        link.send_ipv4(&discover)?;
        if let Some(reply) = await_reply(link, xid, OFFER, REPLY_TIMEOUT) {
            offer = Some(reply);
            break;
        }
    }
    let offer = offer.ok_or_else(|| {
        format!(
            "no DHCP response (message type {}); the AP did not answer a DISCOVER after {} tries",
            OFFER, DISCOVER_ATTEMPTS
        )
    })?;

    let server = if offer.server.is_unspecified() {
        return Err("DHCP OFFER did not carry a server identifier".to_string());
    } else {
        offer.server
    };

    let request = to_broadcast(
        &build_request(xid, mac, offer.your_address, server),
        CLIENT_PORT,
        SERVER_PORT,
    );
    let mut ack = None;
    for _ in 0..DISCOVER_ATTEMPTS {
        link.send_ipv4(&request)?;
        if let Some(reply) = await_reply(link, xid, ACK, REPLY_TIMEOUT) {
            ack = Some(reply);
            break;
        }
    }
    let ack = ack.ok_or_else(|| {
        format!(
            "no DHCP ACK (message type {}) after {} tries",
            ACK, DISCOVER_ATTEMPTS
        )
    })?;

    let address = if ack.your_address.is_unspecified() {
        offer.your_address
    } else {
        ack.your_address
    };

    Ok(Lease {
        address,
        subnet_mask: ack.subnet_mask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
        router: ack.router.or(offer.router).unwrap_or(server),
        dns: if ack.dns.is_empty() {
            offer.dns
        } else {
            ack.dns
        },
        server,
        lease_secs: ack.lease_secs.or(offer.lease_secs).unwrap_or(3600),
    })
}

/// Wait for a reply of `message_type` matching `xid`, ignoring others.
fn await_reply(link: &dyn IpLink, xid: u32, message_type: u8, timeout: Duration) -> Option<Reply> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let Some(packet) = link.recv_ipv4(Duration::from_millis(200)) else {
            continue;
        };
        if let Some(reply) = from_packet(&packet) {
            if reply.xid == xid && reply.message_type == message_type {
                return Some(reply);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x88, 0x82, 0x79, 0x24, 0x0e, 0xc0];

    fn reply(message_type: u8, xid: u32, your: Ipv4Addr, server: Ipv4Addr) -> Vec<u8> {
        let mut message = vec![0u8; BOOTP_LEN];
        message[0] = OP_BOOTREPLY;
        message[1] = HTYPE_ETHERNET;
        message[2] = 6;
        message[4..8].copy_from_slice(&xid.to_be_bytes());
        message[16..20].copy_from_slice(&your.octets());
        message[28..34].copy_from_slice(&MAC);
        message.extend_from_slice(&MAGIC_COOKIE);
        push_option(&mut message, OPT_MSG_TYPE, &[message_type]);
        push_option(&mut message, OPT_SERVER_ID, &server.octets());
        push_option(&mut message, OPT_SUBNET_MASK, &[255, 255, 255, 0]);
        push_option(&mut message, OPT_ROUTER, &[192, 168, 1, 1]);
        push_option(&mut message, OPT_DNS, &[8, 8, 8, 8]);
        push_option(&mut message, OPT_LEASE_TIME, &3600u32.to_be_bytes());
        message.push(OPT_END);
        message
    }

    /// The body of DHCP option `code` in a message, if present.
    fn option(message: &[u8], code: u8) -> Option<&[u8]> {
        let mut cursor = BOOTP_LEN + 4;
        while cursor + 1 < message.len() {
            let current = message[cursor];
            if current == OPT_END {
                return None;
            }
            if current == 0 {
                cursor += 1;
                continue;
            }
            let length = usize::from(message[cursor + 1]);
            let start = cursor + 2;
            let end = start + length;
            if end > message.len() {
                return None;
            }
            if current == code {
                return Some(&message[start..end]);
            }
            cursor = end;
        }
        None
    }

    #[test]
    fn discover_carries_mac_and_message_type() {
        let payload = build_discover(0x11223344, &MAC);
        assert_eq!(payload[0], OP_BOOTREQUEST);
        assert_eq!(&payload[28..34], &MAC);
        assert_eq!(&payload[BOOTP_LEN..BOOTP_LEN + 4], &MAGIC_COOKIE);
        assert_eq!(option(&payload, OPT_MSG_TYPE), Some(&[DISCOVER][..]));
        // The hostname makes the AP's client list show a name, not a bare MAC.
        assert_eq!(option(&payload, OPT_HOSTNAME), Some(HOSTNAME.as_bytes()));
        // Padded to the RFC 2131 minimum, or some servers ignore the DISCOVER.
        assert!(payload.len() >= MIN_MESSAGE_LEN);
    }

    #[test]
    fn request_carries_the_hostname_and_the_selection() {
        let payload = build_request(
            7,
            &MAC,
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        assert_eq!(option(&payload, OPT_MSG_TYPE), Some(&[REQUEST][..]));
        assert_eq!(option(&payload, OPT_HOSTNAME), Some(HOSTNAME.as_bytes()));
        assert_eq!(
            option(&payload, OPT_REQUESTED_IP),
            Some(&[192, 168, 1, 50][..])
        );
        assert_eq!(option(&payload, OPT_SERVER_ID), Some(&[192, 168, 1, 1][..]));
    }

    #[test]
    fn parses_a_full_offer() {
        let packet = reply(
            OFFER,
            0xdead,
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        let parsed = parse_reply(&packet).unwrap();
        assert_eq!(parsed.message_type, OFFER);
        assert_eq!(parsed.xid, 0xdead);
        assert_eq!(parsed.your_address, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(parsed.server, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(parsed.router, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parsed.dns, vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn rejects_non_replies() {
        assert!(parse_reply(&[0u8; 10]).is_none());
        let mut request = build_discover(1, &MAC);
        request[0] = OP_BOOTREQUEST;
        assert!(parse_reply(&request).is_none());
    }

    #[test]
    fn broadcast_round_trips_through_the_packet_codec() {
        let payload = reply(
            ACK,
            7,
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        // The server sends to the broadcast address; we unwrap by destination port.
        let packet = ipv4::build(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            0,
            PROTO_UDP,
            &ipv4::build_udp(
                Ipv4Addr::new(10, 0, 0, 1),
                SERVER_PORT,
                Ipv4Addr::BROADCAST,
                CLIENT_PORT,
                &payload,
            ),
        );
        let decoded = from_packet(&packet).unwrap();
        assert_eq!(decoded.xid, 7);
        assert_eq!(decoded.message_type, ACK);
    }

    #[test]
    fn obtain_runs_the_full_exchange() {
        // A link that yields an OFFER then an ACK.
        struct ScriptLink {
            replies: std::cell::RefCell<std::collections::VecDeque<Vec<u8>>>,
            sent: std::cell::RefCell<Vec<Vec<u8>>>,
        }
        impl IpLink for ScriptLink {
            fn send_ipv4(&self, packet: &[u8]) -> Result<(), String> {
                self.sent.borrow_mut().push(packet.to_vec());
                Ok(())
            }
            fn recv_ipv4(&self, _timeout: Duration) -> Option<Vec<u8>> {
                let payload = self.replies.borrow_mut().pop_front()?;
                Some(ipv4::build(
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                    0,
                    PROTO_UDP,
                    &ipv4::build_udp(
                        Ipv4Addr::UNSPECIFIED,
                        SERVER_PORT,
                        Ipv4Addr::BROADCAST,
                        CLIENT_PORT,
                        &payload,
                    ),
                ))
            }
        }

        let link = ScriptLink {
            replies: std::cell::RefCell::new(
                vec![
                    reply(
                        OFFER,
                        42,
                        Ipv4Addr::new(192, 168, 1, 50),
                        Ipv4Addr::new(192, 168, 1, 1),
                    ),
                    reply(
                        ACK,
                        42,
                        Ipv4Addr::new(192, 168, 1, 50),
                        Ipv4Addr::new(192, 168, 1, 1),
                    ),
                ]
                .into(),
            ),
            sent: std::cell::RefCell::new(Vec::new()),
        };

        let lease = obtain(&link, &MAC, 42).unwrap();
        assert_eq!(lease.address, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(lease.router, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(lease.dns, vec![Ipv4Addr::new(8, 8, 8, 8)]);
        // DISCOVER then REQUEST were both sent.
        assert_eq!(link.sent.borrow().len(), 2);
    }

    #[test]
    fn obtain_retransmits_when_the_first_discover_is_lost() {
        // A link that ignores the first DISCOVER's whole wait window and only
        // answers once the retransmission has gone out.
        struct LossyLink {
            phase: std::cell::Cell<u8>,
            sent: std::cell::RefCell<Vec<Vec<u8>>>,
        }
        impl IpLink for LossyLink {
            fn send_ipv4(&self, packet: &[u8]) -> Result<(), String> {
                self.sent.borrow_mut().push(packet.to_vec());
                Ok(())
            }
            fn recv_ipv4(&self, _timeout: Duration) -> Option<Vec<u8>> {
                // Before the second DISCOVER (2 sends), stay silent.
                if self.sent.borrow().len() < 2 {
                    return None;
                }
                let payload = if self.phase.get() == 0 {
                    self.phase.set(1);
                    reply(
                        OFFER,
                        7,
                        Ipv4Addr::new(10, 0, 0, 5),
                        Ipv4Addr::new(10, 0, 0, 1),
                    )
                } else {
                    reply(
                        ACK,
                        7,
                        Ipv4Addr::new(10, 0, 0, 5),
                        Ipv4Addr::new(10, 0, 0, 1),
                    )
                };
                Some(ipv4::build(
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                    0,
                    PROTO_UDP,
                    &ipv4::build_udp(
                        Ipv4Addr::UNSPECIFIED,
                        SERVER_PORT,
                        Ipv4Addr::BROADCAST,
                        CLIENT_PORT,
                        &payload,
                    ),
                ))
            }
        }

        let link = LossyLink {
            phase: std::cell::Cell::new(0),
            sent: std::cell::RefCell::new(Vec::new()),
        };
        let lease = obtain(&link, &MAC, 7).unwrap();
        assert_eq!(lease.address, Ipv4Addr::new(10, 0, 0, 5));
        // Two DISCOVERs plus one REQUEST.
        assert_eq!(link.sent.borrow().len(), 3);
    }
}
