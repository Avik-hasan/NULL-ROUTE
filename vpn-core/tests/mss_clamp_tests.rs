use vpn_core::mss_clamp;

#[test]
fn test_mss_clamping_ipv4_tcp() {
    // A synthetic IPv4 TCP SYN packet
    // IP header: 20 bytes, TCP header: 24 bytes (with MSS option)
    let mut packet = vec![
        0x45, 0x00, 0x00, 0x2c, // Version=4, IHL=5, TOS=0, Total Length=44
        0x00, 0x00, 0x40, 0x00, // ID=0, Flags/Frag=DF
        0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=6 (TCP), Checksum (dummy)
        0x0a, 0x00, 0x00, 0x01, // Source IP: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // Dest IP: 10.0.0.2
        0x12, 0x34, 0x00, 0x50, // Source Port: 4660, Dest Port: 80
        0x00, 0x00, 0x00, 0x01, // Seq Number
        0x00, 0x00, 0x00, 0x00, // Ack Number
        0x60, 0x02, 0x20, 0x00, // Data Offset=6 (24 bytes), Flags=SYN, Window
        0x00, 0x00, 0x00, 0x00, // Checksum (dummy), Urgent Pointer
        0x02, 0x04, 0x05, 0xb4, // MSS Option: Kind=2, Length=4, Value=1460 (0x05b4)
    ];

    // MSS inside the packet is 1460. Clamping to tunnel should reduce it.
    mss_clamp::clamp_to_tunnel(&mut packet);

    // Verify the MSS option was rewritten to a smaller value (e.g. 1360)
    assert_eq!(packet[42], 0x05); // High byte (e.g. 1360 is 0x0550)
    assert_eq!(packet[43], 0x50); // Low byte
}

#[test]
fn test_mss_clamping_ignores_udp() {
    let mut packet = vec![
        0x45, 0x00, 0x00, 0x1c, // Total Length=28
        0x00, 0x00, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, // Protocol=17 (UDP)
        0x0a, 0x00, 0x00, 0x01, 
        0x0a, 0x00, 0x00, 0x02, 
        0x12, 0x34, 0x00, 0x50, // UDP ports
        0x00, 0x08, 0x00, 0x00, // UDP Length, Checksum
    ];
    let original = packet.clone();
    mss_clamp::clamp_to_tunnel(&mut packet);
    assert_eq!(packet, original, "UDP packet should remain unchanged");
}
