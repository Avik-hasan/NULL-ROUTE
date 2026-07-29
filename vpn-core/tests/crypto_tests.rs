use vpn_core::crypto::{generate_static_keypair, build_handshake, Session, Role};

#[test]
fn test_generate_keypair() {
    let kp = generate_static_keypair().unwrap();
    assert_eq!(kp.public.len(), 32);
    assert_eq!(kp.private.len(), 32);
}

#[test]
fn test_noise_handshake_roundtrip() {
    let initiator_kp = generate_static_keypair().unwrap();
    let responder_kp = generate_static_keypair().unwrap();
    let psk = [0u8; 32];

    let mut initiator = build_handshake(
        Role::Initiator,
        &initiator_kp.private,
        Some(&responder_kp.public),
        &psk,
    ).unwrap();

    let mut responder = build_handshake(
        Role::Responder,
        &responder_kp.private,
        None,
        &psk,
    ).unwrap();

    let mut msg1 = vec![0u8; 128];
    let n1 = initiator.write_message(&[], &mut msg1).unwrap();

    let mut scratch = vec![0u8; 128];
    responder.read_message(&msg1[..n1], &mut scratch).unwrap();

    let mut msg2 = vec![0u8; 128];
    let n2 = responder.write_message(&[], &mut msg2).unwrap();
    
    initiator.read_message(&msg2[..n2], &mut scratch).unwrap();

    let session_i = Session::from_handshake(1, initiator).unwrap();
    let session_r = Session::from_handshake(1, responder).unwrap();

    assert!(session_i.is_initiator());
    assert!(!session_r.is_initiator());
}
