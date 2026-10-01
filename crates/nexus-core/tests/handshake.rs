//! Integration tests for the NexusMesh core: handshake round-trips, transport
//! encryption, replay protection, punch/STUN codecs, and key persistence.

use nexus_core::crypto::*;
use nexus_core::noise::*;
use nexus_core::packet;
use nexus_core::stun;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn handshake_roundtrip_derives_matching_keys() {
    let alice = StaticKeyPair::generate();
    let bob = StaticKeyPair::generate();
    let bob_pub = bob.public();

    let (init_msg, pending) = create_initiation(&alice, &bob_pub, 0xAAAA, None).unwrap();
    assert_eq!(init_msg.len(), INITIATION_LEN);

    let src: SocketAddr = "203.0.113.10:51820".parse().unwrap();
    let dec = decode_initiation(&init_msg, &bob, src, false).unwrap();
    assert_eq!(dec.peer_static, alice.public());
    assert_eq!(dec.initiator_index, 0xAAAA);

    let (resp_msg, bob_keys) = build_response(&dec, 0xBBBB).unwrap();
    assert_eq!(resp_msg.len(), RESPONSE_LEN);

    let alice_keys = consume_response(&resp_msg, &pending, &alice).unwrap();
    // Initiator send == responder receive, and vice versa.
    assert_eq!(alice_keys.send_key, bob_keys.recv_key);
    assert_eq!(alice_keys.recv_key, bob_keys.send_key);
    assert_eq!(alice_keys.their_index, 0xBBBB);
    assert_eq!(bob_keys.their_index, 0xAAAA);
}

#[test]
fn tampered_initiation_fails_mac1() {
    let alice = StaticKeyPair::generate();
    let bob = StaticKeyPair::generate();
    let (mut msg, _) = create_initiation(&alice, &bob.public(), 1, None).unwrap();
    msg[20] ^= 0xFF; // flip a bit in the ephemeral key
    let src: SocketAddr = "198.51.100.2:9999".parse().unwrap();
    assert!(decode_initiation(&msg, &bob, src, false).is_err());
}

#[test]
fn cookie_validation_roundtrip() {
    let alice = StaticKeyPair::generate();
    let bob = StaticKeyPair::generate();
    let src: SocketAddr = "192.0.2.55:40000".parse().unwrap();

    // Without a cookie, a rate-limited responder must reject.
    let (msg_nocookie, _) = create_initiation(&alice, &bob.public(), 7, None).unwrap();
    assert!(decode_initiation(&msg_nocookie, &bob, src, true).is_err());

    // Responder hands out a cookie; initiator retries carrying it in mac2.
    let ck = cookie_key(&bob.public());
    let cookie = cookie_for_addr(&ck, &src);
    let (msg_cookie, _) = create_initiation(&alice, &bob.public(), 7, Some(&cookie)).unwrap();
    let dec = decode_initiation(&msg_cookie, &bob, src, true).unwrap();
    assert_eq!(dec.peer_static, alice.public());
}

#[test]
fn cookie_reply_roundtrip() {
    let alice = StaticKeyPair::generate();
    let bob = StaticKeyPair::generate();
    let src: SocketAddr = "192.0.2.99:1234".parse().unwrap();

    let (init_msg, _) = create_initiation(&alice, &bob.public(), 42, None).unwrap();
    let trigger_mac1 = &init_msg[116..132];
    let reply = create_cookie_reply(&bob, 42, trigger_mac1, src).unwrap();
    assert_eq!(reply.len(), COOKIE_REPLY_LEN);

    let cookie = consume_cookie_reply(&reply, &bob.public(), 42, trigger_mac1).unwrap();
    // Cookie must match what the responder would derive statelessly.
    let ck = cookie_key(&bob.public());
    assert_eq!(cookie, cookie_for_addr(&ck, &src));
}

#[test]
fn transport_roundtrip_and_replay() {
    let alice = StaticKeyPair::generate();
    let bob = StaticKeyPair::generate();
    let (init_msg, pending) = create_initiation(&alice, &bob.public(), 1, None).unwrap();
    let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let dec = decode_initiation(&init_msg, &bob, src, false).unwrap();
    let (resp, bob_keys) = build_response(&dec, 2).unwrap();
    let alice_keys = consume_response(&resp, &pending, &alice).unwrap();

    let payload = b"\x45\x00fake-ipv4-packet-for-test";
    let sealed = seal_transport(&alice_keys.send_key, alice_keys.their_index, 0, payload).unwrap();
    let view = parse_transport(&sealed).unwrap();
    assert_eq!(view.receiver_index, bob_keys.our_index);
    assert_eq!(view.counter, 0);

    let mut window = ReplayWindow::new();
    assert!(window.check_and_update(view.counter));
    let opened = open_transport(&bob_keys.recv_key, &view).unwrap();
    assert_eq!(opened, payload);

    // Replay of counter 0 must be rejected.
    assert!(!window.check_and_update(0));
    // Far-ahead counters accepted once.
    assert!(window.check_and_update(5000));
    assert!(!window.check_and_update(5000));
    // Old counters outside window rejected.
    assert!(!window.check_and_update(1));
}

#[test]
fn aead_roundtrip() {
    let key = [0x42u8; KEY_LEN];
    let ct = aead_encrypt(&key, 9, b"hello mesh", b"aad").unwrap();
    assert_eq!(ct.len(), 10 + TAG_LEN);
    let pt = aead_decrypt(&key, 9, &ct, b"aad").unwrap();
    assert_eq!(pt, b"hello mesh");
    // Wrong counter fails authentication.
    assert!(aead_decrypt(&key, 10, &ct, b"aad").is_err());
}

#[test]
fn identity_sign_verify() {
    let id = IdentityKey::generate();
    let wg = StaticKeyPair::generate();
    let sig = id.sign(&wg.public());
    assert!(verify_identity(&id.public_bytes(), &wg.public(), &sig).is_ok());
    // Signature over a different message fails.
    assert!(verify_identity(&id.public_bytes(), b"other", &sig).is_err());
}

#[test]
fn punch_datagram_roundtrip() {
    let kp = StaticKeyPair::generate();
    let msg = packet::build_punch(&kp.public(), 0xDEADBEEF);
    assert_eq!(packet::parse_punch(&msg), Some(kp.public()));
    assert_eq!(packet::parse_punch(&[0u8; 48]), None);
}

#[test]
fn stun_binding_roundtrip_v4() {
    let (req, txid) = stun::build_binding_request();
    assert!(stun::is_stun_message(&req));
    let parsed_txid = stun::parse_binding_request(&req).unwrap();
    assert_eq!(parsed_txid, txid);

    let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51342);
    let resp = stun::build_binding_response(&txid, observed);
    let back = stun::parse_binding_response(&resp, &txid).unwrap();
    assert_eq!(back, observed);
}

#[test]
fn stun_binding_roundtrip_v6() {
    let txid = [9u8; 12];
    let observed: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
    let resp = stun::build_binding_response(&txid, observed);
    let back = stun::parse_binding_response(&resp, &txid).unwrap();
    assert_eq!(back, observed);
}

#[test]
fn icmpv4_echo_roundtrip() {
    let pkt = packet::icmpv4_echo_request(
        Ipv4Addr::new(100, 64, 0, 2),
        Ipv4Addr::new(100, 64, 0, 3),
        0x1234,
        7,
        &[0u8; 16],
    )
    .unwrap();
    // Craft a reply by hand: same packet, type 0, swapped addresses.
    let mut reply = pkt.clone();
    reply[20] = 0; // echo reply
    reply[22] = 0;
    reply[23] = 0; // recompute checksum? parse ignores checksums — fine
    assert_eq!(
        packet::parse_icmpv4_echo_reply(&reply, 0x1234),
        Some((7, Some(0)))
    );
    assert_eq!(packet::parse_icmpv4_echo_reply(&reply, 0x9999), None);
}
