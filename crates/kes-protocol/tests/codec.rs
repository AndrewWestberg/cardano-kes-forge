use kes_core::cbor::{Encoder, Error as CborError, Value, visit_without};
use kes_protocol::{
    Envelope, EnvelopeKind as K, Error, MAX_FRAME_BYTES, Receiver, ReceiverState, decode_frame,
    encode_frame,
};
use sha2::{Digest, Sha256};

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let mut h = [0; 9];
    let len = kes_core::cbor::encode_head(major, n, &mut h);
    out.extend_from_slice(&h[..len]);
}
fn u(n: u64) -> Vec<u8> {
    let mut b = vec![];
    head(0, n, &mut b);
    b
}
fn b(bytes: &[u8]) -> Vec<u8> {
    let mut b = vec![];
    head(2, bytes.len() as u64, &mut b);
    b.extend_from_slice(bytes);
    b
}
fn t(s: &str) -> Vec<u8> {
    let mut b = vec![];
    head(3, s.len() as u64, &mut b);
    b.extend_from_slice(s.as_bytes());
    b
}
fn map(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut fields: Vec<_> = fields.into_iter().map(|(k, v)| (t(k), v)).collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = vec![];
    head(5, fields.len() as u64, &mut out);
    for (k, v) in fields {
        out.extend(k);
        out.extend(v);
    }
    out
}
fn array(values: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = vec![];
    head(4, values.len() as u64, &mut out);
    for value in values {
        out.extend(value);
    }
    out
}
fn network() -> Vec<u8> {
    map(vec![
        ("network_magic", u(42)),
        ("shelley_genesis_digest", b(&[0; 32])),
        ("slots_per_kes_period", u(1)),
        ("max_kes_evolutions", u(64)),
    ])
}
fn request(op: &str, payload: Vec<u8>, pool: bool) -> Vec<u8> {
    map(vec![
        ("version", u(1)),
        ("op", t(op)),
        ("device", b(&[0; 16])),
        ("pool", if pool { b(&[0; 28]) } else { vec![0xf6] }),
        ("incarnation", if pool { b(&[0; 16]) } else { vec![0xf6] }),
        ("session", b(&[0; 16])),
        ("seq", u(u64::MAX)),
        ("request", b(&[0; 16])),
        ("budget_ms", u(500)),
        ("payload", payload),
        ("mac", b(&[0; 32])),
    ])
}
fn sign_payload(message: &[u8]) -> Vec<u8> {
    map(vec![
        ("generation", b(&[0; 16])),
        ("certificate_digest", b(&[0; 32])),
        ("absolute_period", u(u64::MAX)),
        ("network", network()),
        ("message", b(message)),
    ])
}
fn certificate() -> Vec<u8> {
    let mut c = vec![0x82, 0x84];
    c.extend(b(&[0; 32]));
    c.extend(u(u64::MAX));
    c.extend(u(u64::MAX));
    c.extend(b(&[0; 64]));
    c.extend(b(&[0; 32]));
    c
}

#[test]
fn gate_sensitivity_detects_parser_scope_bypass() {
    let Ok(mode) = std::env::var("KES_GATE_MODE") else {
        return;
    };
    let valid = request("SIGN", sign_payload(b"public sensitivity message"), true);
    assert!(Envelope::parse(&valid, K::DeviceRequest).is_ok());
    let invalid = request("SIGN", sign_payload(b"public sensitivity message"), false);
    assert!(matches!(
        Envelope::parse(&invalid, K::DeviceRequest),
        Err(Error::InvalidValue)
    ));
    match mode.as_str() {
        "clean" => println!(
            "KES_GATE_SUMMARY {{\"version\":1,\"cases\":2,\"scenarios\":{{\"frame\":2}},\"measurements\":{{\"violations\":0}}}}"
        ),
        "coverage" => {
            let build = std::env::var("KES_GATE_BUILD").expect("coverage build missing");
            assert!(
                build
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
            );
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":2,\"scenarios\":{{\"frame\":2}},\"measurements\":{{\"violations\":0,\"build\":\"{build}\",\"changed_branches\":{{\"frame-boundary\":1,\"scope-validation\":1,\"malformed-rejection\":1}}}}}}"
            );
        }
        "seeded-semantic-authentication-bypass" => {
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"frame\":1}},\"measurements\":{{\"violations\":1,\"counterexample\":{{\"mode\":\"seeded-semantic-authentication-bypass\",\"path\":\"kes-protocol.Envelope::parse\",\"observation\":\"a pool-scoped SIGN frame with null pool and incarnation was rejected\",\"disclosure\":\"public\"}}}}}}"
            );
            panic!("seeded frame scope bypass detected");
        }
        _ => panic!("unsupported frame gate mode: {mode}"),
    }
}

#[test]
fn signing_boundaries_and_borrowed_exact_bytes() {
    for n in [0, 1, 4096] {
        let message = vec![0x7b; n];
        let wire = request("SIGN", sign_payload(&message), true);
        let parsed = Envelope::parse(&wire, K::DeviceRequest).unwrap();
        assert_eq!(parsed.message().unwrap(), message);
        let body = parsed.message().unwrap();
        assert!(body.as_ptr() >= wire.as_ptr());
        assert!((body.as_ptr() as usize) + body.len() <= wire.as_ptr() as usize + wire.len());
        let mut framed = [0; 8196];
        let len = encode_frame(Value::parse(&wire).unwrap(), &mut framed).unwrap();
        assert_eq!(decode_frame(&framed[..len]).unwrap().encoded(), wire);
    }
    let wire = request("SIGN", sign_payload(&vec![0; 4097]), true);
    assert!(matches!(
        Envelope::parse(&wire, K::DeviceRequest),
        Err(Error::InvalidLength)
    ));
}

#[test]
fn exact_operation_fields_scope_and_network_bounds() {
    let wire = request("SIGN", sign_payload(b"public Cardano content"), false);
    assert!(Envelope::parse(&wire, K::DeviceRequest).is_err());
    let wire = request(
        "GENERATE",
        map(vec![
            ("next_generation_number", u(u64::MAX)),
            ("expected_revision", u(u64::MAX)),
        ]),
        true,
    );
    assert!(Envelope::parse(&wire, K::DeviceRequest).is_ok());
    for payload in [
        map(vec![("next_generation_number", u(1))]),
        map(vec![
            ("next_generation_number", u(1)),
            ("expected_revision", u(0)),
            ("extra", u(0)),
        ]),
    ] {
        assert!(Envelope::parse(&request("GENERATE", payload, true), K::DeviceRequest).is_err());
    }
    let valid = certificate();
    let wire = request(
        "CERTIFY",
        map(vec![
            ("generation", b(&[0; 16])),
            ("certificate", b(&valid)),
            ("network", network()),
            ("expected_revision", u(0)),
        ]),
        true,
    );
    assert!(Envelope::parse(&wire, K::DeviceRequest).is_ok());
    for n in [0, 1024, 1025] {
        let wire = request(
            "CERTIFY",
            map(vec![
                ("generation", b(&[0; 16])),
                ("certificate", b(&vec![0; n])),
                ("network", network()),
                ("expected_revision", u(0)),
            ]),
            true,
        );
        assert!(Envelope::parse(&wire, K::DeviceRequest).is_err());
    }
    let wire = request(
        "UPDATE_CHUNK",
        map(vec![
            ("manifest_digest", b(&[0; 32])),
            ("offset", u(0)),
            ("bytes", b(b"public firmware")),
            ("expected_revision", u(0)),
        ]),
        false,
    );
    assert!(Envelope::parse(&wire, K::DeviceRequest).is_ok());
    assert!(
        Envelope::parse(
            &request(
                "UPDATE_BEGIN",
                map(vec![
                    ("manifest_digest", b(&[0; 32])),
                    ("expected_revision", u(0))
                ]),
                true
            ),
            K::DeviceRequest
        )
        .is_err()
    );
}

#[test]
fn strict_cbor_rejections() {
    for bytes in [
        &[0x18, 0x17][..],
        &[0x58, 0x00],
        &[0x9f, 0xff],
        &[0xc0, 0],
        &[0xf9, 0, 0],
        &[0x20],
        &[0x61, 0xff],
        &[0xa2, 0x61, b'a', 0, 0x61, b'a', 1],
        &[0xa2, 0x61, b'b', 0, 0x61, b'a', 1],
        &[0xa0, 0],
        &[0x81, 0x81, 0x81, 0x81, 0x81, 0],
    ] {
        assert!(Value::parse(bytes).is_err(), "{bytes:?}");
    }
    assert!(Value::parse(&[0x81, 0x81, 0x81, 0x81, 0]).is_ok());
    assert_eq!(decode_frame(&[0, 0, 32, 1]).err(), Some(Error::Oversize));
    assert_eq!(
        decode_frame(&[0, 0, 0, 1, 0xa0, 0]).err(),
        Some(Error::TrailingBytes)
    );
}

#[test]
fn receiver_original_deadline_and_terminal_errors() {
    let mut storage = [0; MAX_FRAME_BYTES];
    let mut rx = Receiver::new(&mut storage);
    assert_eq!(rx.push(&[0], 100), Ok(1));
    assert_eq!(rx.push(&[0], 1099), Ok(1));
    assert_eq!(rx.push(&[0], 2099), Ok(1));
    assert_eq!(rx.push(&[1, 0xa0], 2100), Err(Error::Timeout));
    rx.reset();
    assert_eq!(rx.push(&[0, 0, 32, 1], 0), Err(Error::Oversize));
    assert!(rx.complete().is_none());
    rx.reset();
    assert_eq!(rx.push(&[0, 0, 0, 1, 0xa0, 0xff], 10), Ok(5));
    assert_eq!(rx.complete(), Some(&[0xa0][..]));
    assert_eq!(rx.check_timeout(10000), Ok(()));
    rx.reset();
    rx.push(&[0], 10).unwrap();
    assert_eq!(rx.check_timeout(9), Err(Error::ClockRegressed));
}

#[test]
fn receiver_state_uses_caller_owned_storage_without_a_self_borrow() {
    let mut storage = [0; MAX_FRAME_BYTES];
    let mut rx = ReceiverState::new();
    assert_eq!(rx.push(&mut storage, &[0, 0, 0], 7), Ok(3));
    assert_eq!(rx.push(&mut storage, &[2, 0xa1, 0], 8), Ok(3));
    assert_eq!(rx.complete(&storage), Some(&[0xa1, 0][..]));
    assert_eq!(rx.push(&mut storage, &[0xff], 9), Ok(0));
    rx.reset();
    assert!(rx.complete(&storage).is_none());
}

#[test]
fn transcript_omission_changes_map_header_without_changing_body() {
    let wire = request("SIGN", sign_payload(b"public"), true);
    let parsed = Envelope::parse(&wire, K::DeviceRequest).unwrap();
    let mut transcript = vec![];
    visit_without(parsed.map(), "mac", |chunk| {
        transcript.extend_from_slice(chunk)
    })
    .unwrap();
    let value = Value::parse(&transcript).unwrap();
    let map = value.map().unwrap();
    assert_eq!(map.len(), 10);
    assert!(map.get("mac").unwrap().is_none());
    assert_eq!(
        map.required("payload").unwrap().encoded(),
        parsed.payload().encoded()
    );
}

#[test]
fn bounded_writer_checks_canonical_order() {
    let mut out = [0; 64];
    let mut e = Encoder::new(&mut out);
    e.map(2).unwrap();
    e.text("b").unwrap();
    e.uint(0).unwrap();
    e.text("a").unwrap();
    e.uint(0).unwrap();
    assert_eq!(e.finish().err(), Some(CborError::DuplicateOrUnsortedKey));
}

#[test]
fn all_pool_request_schemas_are_closed() {
    let generation = ("generation", b(&[0; 16]));
    let revision = ("expected_revision", u(0));
    let digest = ("certificate_digest", b(&[0; 32]));
    let cases = vec![
        ("STATUS", map(vec![])),
        ("STATUS", map(vec![generation.clone()])),
        (
            "GENERATE",
            map(vec![("next_generation_number", u(1)), revision.clone()]),
        ),
        (
            "OP_STATUS",
            map(vec![("request", b(&[0; 16])), ("generation_number", u(1))]),
        ),
        ("GET_BACKUP", map(vec![generation.clone()])),
        (
            "CERTIFY",
            map(vec![
                generation.clone(),
                revision.clone(),
                ("certificate", b(&certificate())),
                ("network", network()),
            ]),
        ),
        (
            "ACTIVATE",
            map(vec![
                generation.clone(),
                revision.clone(),
                digest.clone(),
                ("current_absolute_period", u(1)),
                ("expected_active_generation", vec![0xf6]),
            ]),
        ),
        (
            "SCHEDULE",
            map(vec![
                generation.clone(),
                revision.clone(),
                digest.clone(),
                ("activation_absolute_period", u(1)),
                ("expected_active_generation", vec![0xf6]),
            ]),
        ),
        (
            "EVOLVE",
            map(vec![
                generation.clone(),
                revision.clone(),
                digest.clone(),
                ("target_absolute_period", u(1)),
                ("network", network()),
            ]),
        ),
        ("SIGN", sign_payload(b"public")),
        (
            "OBSERVE_PERIOD",
            map(vec![
                revision.clone(),
                ("absolute_period", u(1)),
                ("network", network()),
            ]),
        ),
        (
            "DEV_INSPECT",
            map(vec![generation, ("protected_output", vec![0xf5])]),
        ),
    ];
    for (op, payload) in cases {
        assert!(
            Envelope::parse(&request(op, payload.clone(), true), K::DeviceRequest).is_ok(),
            "{op}"
        );
        let value = Value::parse(&payload).unwrap();
        let mut fields: Vec<_> = value
            .map()
            .unwrap()
            .map(|e| {
                let (k, v) = e.unwrap();
                (k, v.encoded().to_vec())
            })
            .collect();
        fields.push(("unknown", u(1)));
        assert!(
            Envelope::parse(&request(op, map(fields), true), K::DeviceRequest).is_err(),
            "{op}"
        );
    }
}

#[test]
fn handshakes_local_scope_and_signed_management_bytes() {
    use kes_protocol::operations::{
        visit_management_tuple, visit_open_signature, visit_session_info,
    };
    let info = map(vec![
        ("version", u(1)),
        ("op", t("INFO")),
        ("request", b(&[0; 16])),
        ("payload", map(vec![("challenge", b(&[0; 32]))])),
    ]);
    assert!(Envelope::parse(&info, K::InfoRequest).is_ok());
    assert!(Envelope::parse(&info, K::DeviceRequest).is_err());
    assert_eq!(
        Envelope::parse_device_ingress(&info).unwrap().kind,
        K::InfoRequest
    );
    let open = map(vec![
        ("version", u(1)),
        ("op", t("OPEN")),
        ("device", b(&[0; 16])),
        ("pool", vec![0xf6]),
        ("incarnation", vec![0xf6]),
        ("request", b(&[0; 16])),
        (
            "payload",
            map(vec![
                ("boot_nonce", b(&[0; 32])),
                ("credential_epoch", u(0)),
                ("open_counter", u(0)),
                ("encapsulation", b(&[0; 32])),
                ("ciphertext", b(&[0; 48])),
                ("signature", b(&[0; 64])),
            ]),
        ),
    ]);
    let parsed = Envelope::parse(&open, K::OpenRequest).unwrap();
    assert_eq!(
        Envelope::parse_device_ingress(&open).unwrap().kind,
        K::OpenRequest
    );
    let sign = request("SIGN", sign_payload(b"exact"), true);
    assert_eq!(
        Envelope::parse_device_ingress(&sign).unwrap().kind,
        K::DeviceRequest
    );
    let mut info_tuple = vec![];
    visit_session_info(parsed, |b| info_tuple.extend_from_slice(b)).unwrap();
    assert_eq!(
        Value::parse(&info_tuple).unwrap().array().unwrap().count(),
        8
    );
    let mut signed_tuple = vec![];
    visit_open_signature(parsed, |b| signed_tuple.extend_from_slice(b)).unwrap();
    assert_eq!(
        Value::parse(&signed_tuple)
            .unwrap()
            .array()
            .unwrap()
            .count(),
        10
    );
    let canonical = map(vec![]);
    let payload = map(vec![
        ("device", b(&[0; 16])),
        ("pool", vec![0xf6]),
        ("incarnation", vec![0xf6]),
        ("management_sequence", u(1)),
        ("request", b(&[0; 16])),
        ("expected_revision", u(0)),
        ("action", t("DEVICE_RETIRE")),
        ("canonical_payload", b(&canonical)),
        ("signature", b(&[0; 64])),
    ]);
    let wire = request("MANAGE", payload, false);
    let parsed = Envelope::parse(&wire, K::DeviceRequest).unwrap();
    let mut tuple = vec![];
    visit_management_tuple(parsed, |b| tuple.extend_from_slice(b)).unwrap();
    let last = Value::parse(&tuple)
        .unwrap()
        .array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(last.encoded(), canonical);
    for op in ["STATUS", "SIGN", "DEV_INSPECT"] {
        let payload = if op == "SIGN" {
            sign_payload(b"public")
        } else if op == "DEV_INSPECT" {
            map(vec![
                ("generation", b(&[0; 16])),
                ("protected_output", vec![0xf5]),
            ])
        } else {
            map(vec![])
        };
        let local = map(vec![
            ("version", u(1)),
            ("connection", t("pool-1")),
            ("request", b(&[0; 16])),
            ("budget_ms", u(500)),
            ("op", t(op)),
            ("payload", payload),
        ]);
        assert_eq!(
            Envelope::parse(&local, K::LocalRequest).is_ok(),
            op != "DEV_INSPECT"
        );
    }
}

fn response(op: &str, status: &str, payload: Vec<u8>) -> Vec<u8> {
    map(vec![
        ("version", u(1)),
        ("op", t(op)),
        ("device", b(&[0; 16])),
        ("pool", b(&[0; 28])),
        ("incarnation", b(&[0; 16])),
        ("session", b(&[0; 16])),
        ("seq", u(1)),
        ("request_seq", u(0)),
        ("request", b(&[0; 16])),
        ("status", t(status)),
        ("payload", payload),
        ("mac", b(&[0; 32])),
    ])
}
fn signing_context(period: u64) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("revision", u(1)),
        ("generation", b(&[0; 16])),
        ("certificate_digest", b(&[0; 32])),
        ("relative_period", u(period)),
        ("lifecycle", t("active")),
        ("health", t("healthy")),
    ]
}
#[test]
fn response_metadata_signature_limits_and_stable_statuses() {
    for status in kes_protocol::Status::ALL {
        assert_eq!(kes_protocol::Status::parse(status.as_str()), Ok(*status));
    }
    for (signature_len, period, accepted) in [
        (448, 63, true),
        (447, 63, false),
        (449, 63, false),
        (448, 64, false),
    ] {
        let mut fields = signing_context(period);
        fields.extend([
            ("signature", b(&vec![0; signature_len])),
            ("message_digest", b(&[0; 32])),
        ]);
        let wire = response("SIGN", "OK", map(fields));
        assert_eq!(Envelope::parse(&wire, K::DeviceResponse).is_ok(), accepted);
    }
    assert!(
        Envelope::parse(
            &response("EVOLVE", "EXPIRED", map(signing_context(63))),
            K::DeviceResponse
        )
        .is_ok()
    );
    for (scope, diagnostic, accepted) in [
        ("device", "public reason", true),
        ("pool", "public reason", true),
        ("other", "public reason", false),
    ] {
        let wire = response(
            "SIGN",
            "BUSY",
            map(vec![("scope", t(scope)), ("diagnostic", t(diagnostic))]),
        );
        assert_eq!(Envelope::parse(&wire, K::DeviceResponse).is_ok(), accepted);
    }
    assert!(
        Envelope::parse(
            &response(
                "SIGN",
                "BUSY",
                map(vec![
                    ("scope", t("pool")),
                    ("diagnostic", t(&"x".repeat(257)))
                ])
            ),
            K::DeviceResponse
        )
        .is_err()
    );
    for status in [
        "IN_PROGRESS",
        "UNKNOWN",
        "NOT_COMMITTED",
        "RESULT_RECLAIMED",
    ] {
        let wire = response(
            "OP_STATUS",
            status,
            map(vec![("request", b(&[0; 16])), ("generation_number", u(1))]),
        );
        assert!(Envelope::parse(&wire, K::DeviceResponse).is_ok());
    }
}

#[test]
fn backup_schema_preserves_immutable_public_ciphertext_and_rejects_extra_fields() {
    use kes_protocol::backup::BackupArtifact;
    let fields = vec![
        ("version", u(1)),
        ("kem", u(32)),
        ("kdf", u(1)),
        ("aead", u(3)),
        ("device", b(&[0; 16])),
        ("incarnation", b(&[0; 16])),
        ("generation", b(&[0; 16])),
        ("pool", b(&[0; 28])),
        ("generation_number", u(1)),
        ("verification_key", b(&[0; 32])),
        ("recipient_public_key", b(&[0; 32])),
        ("recipient_id", b(&Sha256::digest([0; 32]))),
        ("period", u(0)),
        ("encapsulation", b(&[0; 32])),
        ("ciphertext", b(&[0; 624])),
        ("device_signature", b(&[0; 64])),
    ];
    let artifact = [b"KESBKP01".as_slice(), &map(fields.clone())].concat();
    let parsed = BackupArtifact::parse(&artifact).unwrap();
    assert_eq!(parsed.encoded(), artifact);
    assert_eq!(
        parsed
            .map()
            .required("ciphertext")
            .unwrap()
            .bytes()
            .unwrap()
            .len(),
        624
    );
    let wire = response(
        "GET_BACKUP",
        "OK",
        map(vec![
            ("generation", b(&[0; 16])),
            ("backup", b(&artifact)),
            ("artifact_digest", b(&[0; 32])),
        ]),
    );
    assert!(Envelope::parse(&wire, K::DeviceResponse).is_ok());
    for (key, value) in [
        ("period", u(1)),
        ("kem", u(0)),
        ("ciphertext", b(&[0; 623])),
        ("device", b(&[0; 15])),
    ] {
        let changed = fields
            .iter()
            .map(|(k, v)| (*k, if *k == key { value.clone() } else { v.clone() }))
            .collect();
        let artifact = [b"KESBKP01".as_slice(), &map(changed)].concat();
        assert!(BackupArtifact::parse(&artifact).is_err());
    }
    assert_eq!(
        BackupArtifact::parse(&vec![0; 2049]).err(),
        Some(Error::Oversize)
    );
}

#[test]
fn maximum_frame_and_offset_overflow_are_bounded() {
    let raw = map(vec![("x", b(&vec![0; 8186]))]);
    assert_eq!(raw.len(), 8192);
    assert!(Value::parse(&raw).is_ok());
    let mut too_large = raw.clone();
    too_large.push(0);
    assert_eq!(Value::parse(&too_large).err(), Some(CborError::Oversize));
    let wire = request(
        "UPDATE_CHUNK",
        map(vec![
            ("manifest_digest", b(&[0; 32])),
            ("offset", u(u64::MAX)),
            ("bytes", b(&[1])),
            ("expected_revision", u(0)),
        ]),
        false,
    );
    assert!(matches!(
        Envelope::parse(&wire, K::DeviceRequest),
        Err(Error::InvalidValue)
    ));
    let mut storage = [0; MAX_FRAME_BYTES];
    let mut rx = Receiver::new(&mut storage);
    assert_eq!(rx.push(&[0, 0, 32, 0], 0), Ok(4));
    assert_eq!(rx.push(&raw, 1999), Ok(8192));
    assert_eq!(rx.complete(), Some(raw.as_slice()));
}

#[test]
fn management_action_payloads_and_update_requests_are_closed() {
    let manifest = map(vec![
        ("version", u(1)),
        ("firmware_digest", b(&[0; 32])),
        ("partition_manifest_digest", b(&[0; 32])),
        ("storage_schema", u(1)),
        ("image_length", u(1)),
        ("security_version", u(1)),
        ("hardware_policy_digest", b(&[0; 32])),
        ("signature", b(&[0; 64])),
    ]);
    let enrollment = map(vec![
        ("version", u(1)),
        ("device", b(&[0; 16])),
        ("pool", b(&[0; 28])),
        ("incarnation", b(&[0; 16])),
        ("cold_verification_key", b(&[0; 32])),
        ("network", network()),
        ("machine_public_key", b(&[0; 32])),
        ("credential_epoch", u(0)),
        ("recipient_public_key", b(&[0; 32])),
        ("recipient_id", b(&[0; 32])),
    ]);
    for (action, pool, canonical) in [
        ("ENROLL", true, enrollment),
        (
            "CREDENTIAL_REPLACE",
            true,
            map(vec![
                ("machine_public_key", b(&[0; 32])),
                ("credential_epoch", u(1)),
            ]),
        ),
        (
            "CREDENTIAL_REVOKE",
            false,
            map(vec![("credential_epoch", u(1))]),
        ),
        (
            "RECIPIENT_REPLACE",
            true,
            map(vec![
                ("recipient_public_key", b(&[0; 32])),
                ("recipient_id", b(&[0; 32])),
            ]),
        ),
        (
            "STAGED_DISCARD",
            true,
            map(vec![("generation", b(&[0; 16]))]),
        ),
        ("POOL_DELETE", true, map(vec![])),
        ("DEVICE_RETIRE", false, map(vec![])),
        ("FIRMWARE_AUTHORIZE", false, manifest),
    ] {
        let mut fields = vec![
            ("device", b(&[0; 16])),
            ("pool", if pool { b(&[0; 28]) } else { vec![0xf6] }),
            ("incarnation", if pool { b(&[0; 16]) } else { vec![0xf6] }),
            ("management_sequence", u(1)),
            ("request", b(&[0; 16])),
            ("expected_revision", u(0)),
            ("action", t(action)),
            ("canonical_payload", b(&canonical)),
            ("signature", b(&[0; 64])),
        ];
        assert!(
            Envelope::parse(
                &request("MANAGE", map(fields.clone()), false),
                K::DeviceRequest
            )
            .is_ok(),
            "{action}"
        );
        fields.push(("unknown", u(0)));
        assert!(Envelope::parse(&request("MANAGE", map(fields), false), K::DeviceRequest).is_err());
    }
    for (op, fields) in [
        (
            "UPDATE_BEGIN",
            vec![
                ("manifest_digest", b(&[0; 32])),
                ("expected_revision", u(0)),
            ],
        ),
        (
            "UPDATE_FINALIZE",
            vec![
                ("manifest_digest", b(&[0; 32])),
                ("final_digest", b(&[0; 32])),
                ("expected_revision", u(0)),
            ],
        ),
    ] {
        assert!(Envelope::parse(&request(op, map(fields), false), K::DeviceRequest).is_ok());
    }
}

#[test]
fn core_session_crypto_matches_exact_wire_transcripts() {
    use ed25519_dalek::{Signature, SigningKey};
    use kes_core::{
        session::{
            DeviceHpkeKey, DeviceIdentityKey, INFO_TRANSCRIPT_BYTES, OpenContext, OpenResponse,
            Scope, SessionTable, accept_open, begin_open, verify_info,
        },
        types::{CredentialEpoch, DeviceId, IncarnationId, PoolId, RequestId},
    };
    use kes_protocol::operations::{visit_open_signature, visit_session_info};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use zeroize::Zeroizing;

    let device = DeviceId::from_bytes([1; 16]);
    let request_id = RequestId::from_bytes([2; 16]);
    let pool = PoolId::from_bytes([3; 28]);
    let incarnation = IncarnationId::from_bytes([4; 16]);
    let boot_nonce = [5; 32];
    let challenge = [6; 32];
    let identity = DeviceIdentityKey::from_seed(Zeroizing::new([7; 32]));
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new([8; 32]));
    let machine = SigningKey::from_bytes(&[9; 32]);

    let make_info = |signature: [u8; 64]| {
        map(vec![
            ("version", u(1)),
            ("op", t("INFO")),
            ("request", b(request_id.as_bytes())),
            ("device", b(device.as_bytes())),
            ("status", t("OK")),
            (
                "payload",
                map(vec![
                    ("challenge", b(&challenge)),
                    ("identity_public_key", b(&identity.verification_key())),
                    ("hpke_public_key", b(&hpke.public_key())),
                    ("boot_nonce", b(&boot_nonce)),
                    (
                        "open_counters",
                        array(vec![map(vec![
                            ("pool", vec![0xf6]),
                            ("incarnation", vec![0xf6]),
                            ("open_counter", u(0)),
                        ])]),
                    ),
                    ("firmware_digest", b(&[10; 32])),
                    ("security_version", u(1)),
                    ("hardware_policy_digest", b(&[11; 32])),
                    ("security_mode", t("development")),
                    ("capability_evidence", b(b"public")),
                    (
                        "limits",
                        map(vec![
                            ("frame_bytes", u(8192)),
                            ("message_bytes", u(4096)),
                            ("certificate_bytes", u(1024)),
                            ("backup_bytes", u(2048)),
                            ("pools", u(32)),
                            ("sessions", u(33)),
                        ]),
                    ),
                ]),
            ),
            ("signature", b(&signature)),
        ])
    };
    let unsigned_info = make_info([0; 64]);
    let parsed_info = Envelope::parse(&unsigned_info, K::InfoResponse).unwrap();
    let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
    let info_signature = identity
        .sign_info(
            parsed_info.map(),
            device,
            request_id,
            &challenge,
            &mut scratch,
        )
        .unwrap();
    let signed_info = make_info(info_signature);
    let parsed_info = Envelope::parse(&signed_info, K::InfoResponse).unwrap();
    let info = verify_info(
        parsed_info.map(),
        device,
        request_id,
        &challenge,
        &identity.verification_key(),
        &mut scratch,
    )
    .unwrap();
    assert_eq!(info.boot_nonce, boot_nonce);
    assert_eq!(info.hpke_public_key, hpke.public_key());

    let context = OpenContext::new(
        device,
        boot_nonce,
        Scope::Pool { pool, incarnation },
        CredentialEpoch::new(12),
        13,
        request_id,
    );
    let mut host_rng = ChaCha20Rng::from_seed([14; 32]);
    let (open, pending) = begin_open(context, &hpke.public_key(), &machine, &mut host_rng).unwrap();
    let encoded_open = map(vec![
        ("version", u(1)),
        ("op", t("OPEN")),
        ("device", b(device.as_bytes())),
        ("pool", b(pool.as_bytes())),
        ("incarnation", b(incarnation.as_bytes())),
        ("request", b(request_id.as_bytes())),
        (
            "payload",
            map(vec![
                ("boot_nonce", b(&boot_nonce)),
                ("credential_epoch", u(12)),
                ("open_counter", u(13)),
                ("encapsulation", b(&open.encapsulation)),
                ("ciphertext", b(&open.ciphertext)),
                ("signature", b(&open.signature)),
            ]),
        ),
    ]);
    let parsed_open = Envelope::parse(&encoded_open, K::OpenRequest).unwrap();
    let mut info_tuple = Vec::new();
    visit_session_info(parsed_open, |chunk| info_tuple.extend_from_slice(chunk)).unwrap();
    assert_eq!(
        Value::parse(&info_tuple).unwrap().array().unwrap().count(),
        8
    );
    let mut signature_tuple = Vec::new();
    visit_open_signature(parsed_open, |chunk| {
        signature_tuple.extend_from_slice(chunk)
    })
    .unwrap();
    machine
        .verifying_key()
        .verify_strict(&signature_tuple, &Signature::from_bytes(&open.signature))
        .unwrap();
    let mut device_rng = ChaCha20Rng::from_seed([15; 32]);
    let accepted = accept_open(
        context,
        &open,
        &hpke,
        &machine.verifying_key().to_bytes(),
        &mut device_rng,
    )
    .unwrap();
    let make_open_response = |response: OpenResponse| {
        map(vec![
            ("version", u(1)),
            ("op", t("OPEN")),
            ("device", b(device.as_bytes())),
            ("pool", b(pool.as_bytes())),
            ("incarnation", b(incarnation.as_bytes())),
            ("request", b(request_id.as_bytes())),
            ("status", t("OK")),
            (
                "payload",
                map(vec![
                    ("session", b(&response.session_id)),
                    (
                        "challenge_acknowledgement",
                        b(&response.challenge_acknowledgement),
                    ),
                ]),
            ),
            ("mac", b(&response.mac)),
        ])
    };
    let fields = accepted.response_fields();
    let unsigned_response = make_open_response(fields);
    let parsed_response = Envelope::parse(&unsigned_response, K::OpenResponse).unwrap();
    let mut sessions = SessionTable::new();
    let mut counter = 13;
    let response = accepted
        .commit(&mut counter, &mut sessions, parsed_response.map())
        .unwrap();
    assert_eq!(counter, 14);
    let signed_response = make_open_response(response);
    let parsed_response = Envelope::parse(&signed_response, K::OpenResponse).unwrap();
    let host = pending.complete(parsed_response.map()).unwrap();
    assert_eq!(host.session_id(), &response.session_id);
}
