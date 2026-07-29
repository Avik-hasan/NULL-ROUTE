use vpn_core::crypto::{generate_static_keypair, build_handshake, Session, Role};
use vpn_core::protocol::PacketKind;

fn create_test_session() -> Session {
    let initiator_kp = generate_static_keypair().unwrap();
    let responder_kp = generate_static_keypair().unwrap();
    let psk = [0u8; 32];

    let mut initiator = build_handshake(Role::Initiator, &initiator_kp.private, Some(&responder_kp.public), &psk).unwrap();
    let mut responder = build_handshake(Role::Responder, &responder_kp.private, None, &psk).unwrap();

    let mut msg1 = vec![0u8; 128];
    let n1 = initiator.write_message(&[], &mut msg1).unwrap();

    let mut scratch = vec![0u8; 128];
    responder.read_message(&msg1[..n1], &mut scratch).unwrap();

    let mut msg2 = vec![0u8; 128];
    let n2 = responder.write_message(&[], &mut msg2).unwrap();
    
    initiator.read_message(&msg2[..n2], &mut scratch).unwrap();

    Session::from_handshake(1, initiator).unwrap()
}

#[test]
fn test_data_packet_seal_open() {
    let session = create_test_session();
    let payload = b"hello vpn world";
    
    let sealed = session.seal(PacketKind::Data, payload).unwrap();
    assert!(sealed.len() > payload.len());
    
    let (kind, opened) = session.open(&sealed).unwrap();
    assert_eq!(kind, PacketKind::Data);
    assert_eq!(opened, payload);
}

#[test]
fn test_anti_replay_window() {
    let session = create_test_session();
    let payload = b"test payload";
    
    let sealed1 = session.seal(PacketKind::Data, payload).unwrap();
    let sealed2 = session.seal(PacketKind::Data, payload).unwrap();
    
    // First receive of packet 1 succeeds
    let _ = session.open(&sealed1).unwrap();
    
    // Replay of packet 1 should fail
    let res = session.open(&sealed1);
    assert!(res.is_err(), "Replayed packet should be rejected");
    
    // First receive of packet 2 succeeds
    let _ = session.open(&sealed2).unwrap();
}
