use ai_trust::*;

#[test]
fn test_pdu_received_before_trust_valid() {
    let mut val = SlidingWindowValidator::new(1, 10);

    // 1. Data PDU arrives first
    let res_pdu = val.receive_pdu(&DataPdu { epoch: 1, seq: 10, protected_field: 0xABCD });
    assert_eq!(res_pdu, ImmediatePduResult::BufferedWaitingForTrust);

    // 2. Trust descriptor arrives later and authenticates
    let digest = compute_digest(0xABCD);
    let res_trust = val.receive_trust(&TrustDescriptor { epoch: 1, seq: 10, expected_digest: digest });
    assert_eq!(res_trust, ImmediateTrustResult::CorrelatedValid);

    // 3. Eviction reports clean validation
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 10 });
}

#[test]
fn test_pdu_received_before_trust_tampered() {
    let mut val = SlidingWindowValidator::new(1, 20);

    // 1. Attacker-modified PDU arrives first
    let res_pdu = val.receive_pdu(&DataPdu { epoch: 1, seq: 20, protected_field: 0x9999 });
    assert_eq!(res_pdu, ImmediatePduResult::BufferedWaitingForTrust);

    // 2. Machine A's legitimate trust arrives expecting 0x8888
    let expected = compute_digest(0x8888);
    let res_trust = val.receive_trust(&TrustDescriptor { epoch: 1, seq: 20, expected_digest: expected });
    assert_eq!(res_trust, ImmediateTrustResult::CorrelatedTampered);

    // 3. Eviction reports residual tampered slot
    assert_eq!(val.advance_one_slot(), EvictionReport::TamperedResidual { seq: 20 });
}

#[test]
fn test_trust_received_before_pdu_valid() {
    let mut val = SlidingWindowValidator::new(1, 30);

    // 1. Trust arrives first
    let digest = compute_digest(0x1234);
    let res_trust = val.receive_trust(&TrustDescriptor { epoch: 1, seq: 30, expected_digest: digest });
    assert_eq!(res_trust, ImmediateTrustResult::BufferedWaitingForPdu);

    // 2. Data PDU arrives later
    let res_pdu = val.receive_pdu(&DataPdu { epoch: 1, seq: 30, protected_field: 0x1234 });
    assert_eq!(res_pdu, ImmediatePduResult::CorrelatedValid);

    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 30 });
}

#[test]
fn test_duplicated_replay_protection() {
    let mut val = SlidingWindowValidator::new(1, 40);

    // PDU arrives once
    assert_eq!(val.receive_pdu(&DataPdu { epoch: 1, seq: 40, protected_field: 1 }), ImmediatePduResult::BufferedWaitingForTrust);

    // Replay arrival of the same PDU
    let res_replay = val.receive_pdu(&DataPdu { epoch: 1, seq: 40, protected_field: 1 });
    assert_eq!(res_replay, ImmediatePduResult::Duplicated);

    // Advance window past seq 40
    val.advance_one_slot();

    // Replay arrival behind window base (circular past)
    let res_stale = val.receive_pdu(&DataPdu { epoch: 1, seq: 40, protected_field: 1 });
    assert_eq!(res_stale, ImmediatePduResult::Duplicated);
}

#[test]
fn test_added_injected_pdu_detection() {
    let mut val = SlidingWindowValidator::new(1, 50);

    // Attacker injects a rogue PDU at seq 50 (Machine A NEVER emits a trust descriptor for 50)
    let res_pdu = val.receive_pdu(&DataPdu { epoch: 1, seq: 50, protected_field: 0xBADC0DE });
    assert_eq!(res_pdu, ImmediatePduResult::BufferedWaitingForTrust);

    // Window advances past seq 50 without ever getting trust -> Detected as Added/Injected!
    let report = val.advance_one_slot();
    assert_eq!(report, EvictionReport::AddedPdu { seq: 50 });
}

#[test]
fn test_dropped_lost_pdu_detection() {
    let mut val = SlidingWindowValidator::new(1, 60);

    // Machine A emits trust descriptor for seq 60, but the PDU is lost on the network
    let digest = compute_digest(0xCAFE);
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 60, expected_digest: digest }),
        ImmediateTrustResult::BufferedWaitingForPdu
    );

    // Window advances past seq 60 without the PDU arriving -> Detected as Dropped/Lost!
    let report = val.advance_one_slot();
    assert_eq!(report, EvictionReport::DroppedPdu { seq: 60 });
}

#[test]
fn test_udp_out_of_order_jitter_and_asynchrony() {
    let mut val = SlidingWindowValidator::new(1, 100);

    assert_eq!(val.receive_pdu(&DataPdu { epoch: 1, seq: 102, protected_field: 200 }), ImmediatePduResult::BufferedWaitingForTrust);
    assert_eq!(val.receive_trust(&TrustDescriptor { epoch: 1, seq: 100, expected_digest: compute_digest(100) }), ImmediateTrustResult::BufferedWaitingForPdu);
    assert_eq!(val.receive_pdu(&DataPdu { epoch: 1, seq: 100, protected_field: 100 }), ImmediatePduResult::CorrelatedValid);
    assert_eq!(val.receive_trust(&TrustDescriptor { epoch: 1, seq: 102, expected_digest: compute_digest(200) }), ImmediateTrustResult::CorrelatedValid);
    assert_eq!(val.receive_pdu(&DataPdu { epoch: 1, seq: 101, protected_field: 150 }), ImmediatePduResult::BufferedWaitingForTrust);
    assert_eq!(val.receive_trust(&TrustDescriptor { epoch: 1, seq: 101, expected_digest: compute_digest(150) }), ImmediateTrustResult::CorrelatedValid);

    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 100 });
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 101 });
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 102 });
}

#[test]
fn test_circular_arithmetic_wraparound_at_max() {
    let max_seq = u64::MAX;
    let mut val = SlidingWindowValidator::new(1, max_seq);

    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: max_seq, protected_field: 42 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: 0, protected_field: 43 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: max_seq, expected_digest: compute_digest(42) }),
        ImmediateTrustResult::CorrelatedValid
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 0, expected_digest: compute_digest(43) }),
        ImmediateTrustResult::CorrelatedValid
    );

    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: max_seq });
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 0 });
}

#[test]
fn test_overflow_boundary_frontiers() {
    let base = 1000u64;
    let mut val = SlidingWindowValidator::new(1, base);

    let seq_past = base.wrapping_sub(1);
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: seq_past, protected_field: 0 }),
        ImmediatePduResult::Duplicated
    );

    let seq_just_out = base.wrapping_add(WINDOW_CAPACITY as u64);
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: seq_just_out, protected_field: 0 }),
        ImmediatePduResult::OutOfWindow
    );

    let seq_last = base.wrapping_add(WINDOW_LAST_INDEX as u64);
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: seq_last, protected_field: 99 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );
}

#[test]
fn test_jitter_across_wraparound_boundary() {
    let base = u64::MAX - 2;
    let mut val = SlidingWindowValidator::new(1, base);

    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: 1, protected_field: 10 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: u64::MAX - 1, protected_field: 20 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: 0, protected_field: 30 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: u64::MAX - 2, protected_field: 40 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );

    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: u64::MAX - 2, expected_digest: compute_digest(40) }),
        ImmediateTrustResult::CorrelatedValid
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: u64::MAX - 1, expected_digest: compute_digest(20) }),
        ImmediateTrustResult::CorrelatedValid
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 0, expected_digest: compute_digest(30) }),
        ImmediateTrustResult::CorrelatedValid
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 1, expected_digest: compute_digest(10) }),
        ImmediateTrustResult::CorrelatedValid
    );

    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: u64::MAX - 2 });
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: u64::MAX - 1 });
    assert_eq!(val.advance_one_slot(), EvictionReport::None);
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 0 });
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 1 });
}

#[test]
fn test_chaotic_out_of_order_full_permutation() {
    let mut val = SlidingWindowValidator::new(1, 500);

    let n = 20u64;
    let pdu_order: [u64; 20] = [
        13, 7, 19, 2, 0, 11, 4, 16, 9, 1, 18, 5, 14, 8, 3, 17, 10, 15, 6, 12,
    ];
    let trust_order: [u64; 20] = [
        8, 15, 3, 19, 0, 12, 6, 18, 1, 14, 10, 4, 17, 9, 2, 16, 5, 11, 7, 13,
    ];

    let mut pdu_ptr = 0;
    let mut trust_ptr = 0;

    while pdu_ptr < 20 || trust_ptr < 20 {
        if pdu_ptr < 20 && (pdu_ptr <= trust_ptr || trust_ptr == 20) {
            let offset = pdu_order[pdu_ptr];
            let seq = 500 + offset;
            val.receive_pdu(&DataPdu { epoch: 1, seq, protected_field: offset * 10 });
            pdu_ptr += 1;
        } else if trust_ptr < 20 {
            let offset = trust_order[trust_ptr];
            let seq = 500 + offset;
            val.receive_trust(&TrustDescriptor { epoch: 1, seq, expected_digest: compute_digest(offset * 10) });
            trust_ptr += 1;
        }
    }

    for offset in 0..n {
        let seq = 500 + offset;
        assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq });
    }
}

#[test]
fn test_chaotic_disorder_with_interleaved_anomalies() {
    let mut val = SlidingWindowValidator::new(1, 1000);

    val.receive_trust(&TrustDescriptor { epoch: 1, seq: 1001, expected_digest: compute_digest(101) });
    val.receive_pdu(&DataPdu { epoch: 1, seq: 1002, protected_field: 0xBAD });
    val.receive_pdu(&DataPdu { epoch: 1, seq: 1000, protected_field: 100 });
    val.receive_pdu(&DataPdu { epoch: 1, seq: 1005, protected_field: 999 });
    val.receive_trust(&TrustDescriptor { epoch: 1, seq: 1004, expected_digest: compute_digest(104) });

    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: 1001, protected_field: 101 }),
        ImmediatePduResult::CorrelatedValid
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 1000, expected_digest: compute_digest(100) }),
        ImmediateTrustResult::CorrelatedValid
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 1002, expected_digest: compute_digest(0x9999) }),
        ImmediateTrustResult::CorrelatedTampered
    );
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: 1000, protected_field: 100 }),
        ImmediatePduResult::Duplicated
    );

    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 1000 });
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 1001 });
    assert_eq!(val.advance_one_slot(), EvictionReport::TamperedResidual { seq: 1002 });
    assert_eq!(val.advance_one_slot(), EvictionReport::None);
    assert_eq!(val.advance_one_slot(), EvictionReport::DroppedPdu { seq: 1004 });
    assert_eq!(val.advance_one_slot(), EvictionReport::AddedPdu { seq: 1005 });
}

#[test]
fn test_stress_continuous_circular_wraparound() {
    let mut val = SlidingWindowValidator::new(1, u64::MAX - 50);

    for offset in 0..300u64 {
        let cur_seq = (u64::MAX - 50).wrapping_add(offset);
        let digest = compute_digest(offset);

        assert_eq!(
            val.receive_pdu(&DataPdu { epoch: 1, seq: cur_seq, protected_field: offset }),
            ImmediatePduResult::BufferedWaitingForTrust
        );
        assert_eq!(
            val.receive_trust(&TrustDescriptor { epoch: 1, seq: cur_seq, expected_digest: digest }),
            ImmediateTrustResult::CorrelatedValid
        );
        assert_eq!(
            val.advance_one_slot(),
            EvictionReport::NormalValidated { seq: cur_seq }
        );
    }
}

#[test]
fn test_trust_received_before_pdu_tampered() {
    let mut val = SlidingWindowValidator::new(1, 200);

    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 200, expected_digest: compute_digest(0x1111) }),
        ImmediateTrustResult::BufferedWaitingForPdu
    );
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: 200, protected_field: 0x2222 }),
        ImmediatePduResult::CorrelatedTampered
    );
    assert_eq!(val.advance_one_slot(), EvictionReport::TamperedResidual { seq: 200 });
}

#[test]
fn test_trust_out_of_window_and_redundant() {
    let mut val = SlidingWindowValidator::new(1, 300);

    let out_seq = 300 + (WINDOW_CAPACITY as u64);
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: out_seq, expected_digest: 123 }),
        ImmediateTrustResult::OutOfWindow
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 300, expected_digest: compute_digest(1) }),
        ImmediateTrustResult::BufferedWaitingForPdu
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 300, expected_digest: compute_digest(1) }),
        ImmediateTrustResult::RedundantTrust
    );
}

#[test]
fn test_equipment_reboot_epoch_transition() {
    let mut val = SlidingWindowValidator::new(1, 100);

    // Session 1 : Machine A émet seq 100
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 1, seq: 100, protected_field: 0x1111 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 1, seq: 100, expected_digest: compute_digest(0x1111) }),
        ImmediateTrustResult::CorrelatedValid
    );
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 100 });

    // Machine A redémarre brutalement et initialise l'Epoch 2 en repartant de seq 0 !
    // Scénario asynchrone : la PDU de l'Epoch 2 arrive avant son descripteur de confiance
    assert_eq!(
        val.receive_pdu(&DataPdu { epoch: 2, seq: 0, protected_field: 0x2222 }),
        ImmediatePduResult::BufferedWaitingForTrust
    );

    // Le descripteur de confiance de l'Epoch 2 signé arrive : il confirme le nouvel Epoch et corrèle la PDU !
    assert_eq!(
        val.receive_trust(&TrustDescriptor { epoch: 2, seq: 0, expected_digest: compute_digest(0x2222) }),
        ImmediateTrustResult::CorrelatedValid
    );

    assert_eq!(val.current_epoch, 2);
    assert_eq!(val.window_base, 0);
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 0 });
}

#[test]
fn test_inter_epoch_replay_rejection() {
    let mut val = SlidingWindowValidator::new(2, 50);

    // Paquet rejoué d'une ère antérieure (Epoch 1 < 2)
    let stale_pdu = DataPdu { epoch: 1, seq: 50, protected_field: 0x9999 };
    assert_eq!(val.receive_pdu(&stale_pdu), ImmediatePduResult::StaleEpoch);

    // Descripteur rejoué d'une ère antérieure (Epoch 1 < 2)
    let stale_trust = TrustDescriptor { epoch: 1, seq: 50, expected_digest: compute_digest(0x9999) };
    assert_eq!(val.receive_trust(&stale_trust), ImmediateTrustResult::StaleEpoch);
}

#[test]
fn test_epoch_transition_edge_cases() {
    let mut val = SlidingWindowValidator::new(1, 0);

    // 1. PDU avec epoch très en avance (> current + 1)
    let pdu_far = DataPdu { epoch: 10, seq: 0, protected_field: 1 };
    assert_eq!(val.receive_pdu(&pdu_far), ImmediatePduResult::OutOfWindow);

    // 2. TrustDescriptor arrivant en premier pour un nouvel epoch (sans PDU en attente)
    let trust_new = TrustDescriptor { epoch: 2, seq: 10, expected_digest: compute_digest(42) };
    assert_eq!(val.receive_trust(&trust_new), ImmediateTrustResult::NewEpochInitialized);
    assert_eq!(val.current_epoch, 2);
    assert_eq!(val.window_base, 10);

    // 3. PDU de l'epoch 3 en avance mais corrompu par rapport au trust qui arrive ensuite
    let pdu_corrupt = DataPdu { epoch: 3, seq: 0, protected_field: 0xBAD };
    assert_eq!(val.receive_pdu(&pdu_corrupt), ImmediatePduResult::BufferedWaitingForTrust);

    let trust_correct = TrustDescriptor { epoch: 3, seq: 0, expected_digest: compute_digest(0x9999) };
    assert_eq!(val.receive_trust(&trust_correct), ImmediateTrustResult::CorrelatedTampered);
}

#[test]
fn test_cold_start_auto_acquisition() {
    // Cas 1 : Le descripteur de confiance arrive en premier au cold-start
    let mut val = SlidingWindowValidator::new_cold_start();
    assert!(!val.is_synchronized);

    let trust_first = TrustDescriptor {
        epoch: 5,
        seq: 100,
        expected_digest: compute_digest(0x42),
    };
    assert_eq!(val.receive_trust(&trust_first), ImmediateTrustResult::ColdStartSynchronized);
    assert!(val.is_synchronized);
    assert_eq!(val.current_epoch, 5);
    assert_eq!(val.window_base, 100);

    let pdu_ok = DataPdu { epoch: 5, seq: 100, protected_field: 0x42 };
    assert_eq!(val.receive_pdu(&pdu_ok), ImmediatePduResult::CorrelatedValid);
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 100 });

    // Cas 2 : Une PDU arrive avant le descripteur lors d'un cold-start (mise en tampon pré-synchronisation)
    let mut val2 = SlidingWindowValidator::new_cold_start();
    let pdu_early = DataPdu { epoch: 7, seq: 200, protected_field: 0x99 };
    assert_eq!(val2.receive_pdu(&pdu_early), ImmediatePduResult::BufferedWaitingForTrust);

    let trust_later = TrustDescriptor {
        epoch: 7,
        seq: 200,
        expected_digest: compute_digest(0x99),
    };
    assert_eq!(val2.receive_trust(&trust_later), ImmediateTrustResult::CorrelatedValid);
    assert!(val2.is_synchronized);
    assert_eq!(val2.current_epoch, 7);
    assert_eq!(val2.window_base, 200);
    assert_eq!(val2.advance_one_slot(), EvictionReport::NormalValidated { seq: 200 });

    // Cas 3 : PDU altérée reçue avant le descripteur lors d'un cold-start
    let mut val3 = SlidingWindowValidator::new_cold_start();
    let pdu_tampered = DataPdu { epoch: 8, seq: 300, protected_field: 0xBAD };
    assert_eq!(val3.receive_pdu(&pdu_tampered), ImmediatePduResult::BufferedWaitingForTrust);

    let trust_tampered = TrustDescriptor {
        epoch: 8,
        seq: 300,
        expected_digest: compute_digest(0x9999),
    };
    assert_eq!(val3.receive_trust(&trust_tampered), ImmediateTrustResult::CorrelatedTampered);

    // Cas 4 : Débordement du buffer de cold-start (> 16 PDUs)
    let mut val4 = SlidingWindowValidator::new_cold_start();
    for i in 0..16u64 {
        assert_eq!(val4.receive_pdu(&DataPdu { epoch: 9, seq: i, protected_field: i }), ImmediatePduResult::BufferedWaitingForTrust);
    }
    assert_eq!(val4.receive_pdu(&DataPdu { epoch: 9, seq: 16, protected_field: 16 }), ImmediatePduResult::OutOfWindow);
}

#[test]
fn test_multi_pdu_burst_next_epoch() {
    let mut val = SlidingWindowValidator::new(1, 0);

    // Envoi d'une salve de 5 PDUs de l'époque suivante (Epoch 2) avant le descripteur de confiance
    for i in 0..5u64 {
        let pdu = DataPdu {
            epoch: 2,
            seq: i,
            protected_field: 0x1000 + i,
        };
        assert_eq!(val.receive_pdu(&pdu), ImmediatePduResult::BufferedWaitingForTrust);
    }

    // Le premier descripteur de confiance de l'Epoch 2 arrive (seq 0)
    let trust_0 = TrustDescriptor {
        epoch: 2,
        seq: 0,
        expected_digest: compute_digest(0x1000),
    };
    assert_eq!(val.receive_trust(&trust_0), ImmediateTrustResult::CorrelatedValid);
    assert_eq!(val.current_epoch, 2);
    assert_eq!(val.window_base, 0);

    // Les descripteurs de confiance pour les 4 autres paquets de la salve arrivent
    for i in 1..5u64 {
        let trust = TrustDescriptor {
            epoch: 2,
            seq: i,
            expected_digest: compute_digest(0x1000 + i),
        };
        assert_eq!(val.receive_trust(&trust), ImmediateTrustResult::BufferedWaitingForPdu);
    }

    // Dépouillement des 5 slots
    assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: 0 });
    for i in 1..5u64 {
        let pdu = DataPdu {
            epoch: 2,
            seq: i,
            protected_field: 0x1000 + i,
        };
        assert_eq!(val.receive_pdu(&pdu), ImmediatePduResult::CorrelatedValid);
        assert_eq!(val.advance_one_slot(), EvictionReport::NormalValidated { seq: i });
    }
}

#[test]
fn test_pending_next_burst_overflow() {
    let mut val = SlidingWindowValidator::new(1, 0);

    // Remplir la capacité de 16 slots d'attente pour epoch + 1
    for i in 0..16u64 {
        let pdu = DataPdu {
            epoch: 2,
            seq: i,
            protected_field: i,
        };
        assert_eq!(val.receive_pdu(&pdu), ImmediatePduResult::BufferedWaitingForTrust);
    }

    // Le 17ème paquet dépasse la capacité du buffer de pré-époque -> OutOfWindow
    let pdu_overflow = DataPdu {
        epoch: 2,
        seq: 16,
        protected_field: 16,
    };
    assert_eq!(val.receive_pdu(&pdu_overflow), ImmediatePduResult::OutOfWindow);
}

#[test]
fn test_stream_telemetry_metrics_and_prometheus() {
    let mut telemetry = ai_trust::StreamTelemetry::new();

    // 1. Enregistrement d'événements PDU et Trust nominaux
    let res_pdu1 = ImmediatePduResult::BufferedWaitingForTrust;
    let res_trust1 = ImmediateTrustResult::CorrelatedValid;
    telemetry.record_pdu_outcome(&res_pdu1);
    telemetry.record_trust_outcome(&res_trust1);
    assert_eq!(telemetry.pdu_received, 1);
    assert_eq!(telemetry.trust_received, 1);
    assert_eq!(telemetry.validated_packets, 1);

    // 2. Altération (Tampering)
    telemetry.record_pdu_outcome(&ImmediatePduResult::CorrelatedTampered);
    telemetry.record_trust_outcome(&ImmediateTrustResult::CorrelatedTampered);
    assert_eq!(telemetry.tampered_packets, 2);

    // 3. Rejeux et Époque Obsolète
    telemetry.record_pdu_outcome(&ImmediatePduResult::Duplicated);
    telemetry.record_pdu_outcome(&ImmediatePduResult::StaleEpoch);
    telemetry.record_trust_outcome(&ImmediateTrustResult::StaleEpoch);
    telemetry.record_trust_outcome(&ImmediateTrustResult::RedundantTrust);
    assert_eq!(telemetry.replayed_packets, 3);

    // 4. Hors fenêtre (OutOfWindow) et Attente Trust
    telemetry.record_pdu_outcome(&ImmediatePduResult::OutOfWindow);
    telemetry.record_trust_outcome(&ImmediateTrustResult::OutOfWindow);
    telemetry.record_trust_outcome(&ImmediateTrustResult::BufferedWaitingForPdu);
    assert_eq!(telemetry.out_of_window_packets, 2);

    // 5. Éviction : PDU Perdue (Dropped), PDU Intruse (Added), Validated, TamperedResidual, None
    telemetry.record_eviction(&EvictionReport::DroppedPdu { seq: 42 });
    telemetry.record_eviction(&EvictionReport::AddedPdu { seq: 43 });
    telemetry.record_eviction(&EvictionReport::NormalValidated { seq: 44 });
    telemetry.record_eviction(&EvictionReport::TamperedResidual { seq: 45 });
    telemetry.record_eviction(&EvictionReport::None);
    assert_eq!(telemetry.dropped_packets, 1);
    assert_eq!(telemetry.injected_packets, 1);

    // 6. Transition d'époque et Cold-Start
    telemetry.record_trust_outcome(&ImmediateTrustResult::NewEpochInitialized);
    telemetry.record_trust_outcome(&ImmediateTrustResult::ColdStartSynchronized);
    assert_eq!(telemetry.epoch_transitions, 1);
    assert_eq!(telemetry.cold_start_syncs, 1);

    // 6. Vérification du format de sortie (summary & prometheus)
    let summary = telemetry.summary();
    assert!(summary.contains("Valid: 1"));
    assert!(summary.contains("Tampered: 2"));
    assert!(summary.contains("Replay: 3"));
    assert!(summary.contains("Drop: 1"));
    assert!(summary.contains("Inject: 1"));

    let prom = telemetry.prometheus_export();
    assert!(prom.contains("ai_trust_validated_total 1"));
    assert!(prom.contains("ai_trust_tampered_total 2"));
    assert!(prom.contains("ai_trust_replayed_total 3"));
    assert!(prom.contains("ai_trust_dropped_total 1"));
    assert!(prom.contains("ai_trust_injected_total 1"));
}


