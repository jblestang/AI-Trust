// ============================================================================
// Application Entrypoint: Network Stream Validator Demonstration & Simulation
// Scenario: Real-world Asynchronous UDP Network with Epoch Support
// ============================================================================

use ai_trust::*;

fn main() {
    println!("=== Machine B: Initialisation du Validateur Réseau Asynchrone UDP ===");
    let mut validator = SlidingWindowValidator::new(1, 100);

    println!(
        "Machine B: Fenêtre d'observation active: Epoch 1, Slots [{}, {}]",
        100u64,
        100u64 + (WINDOW_LAST_INDEX as u64)
    );

    // ------------------------------------------------------------------------
    // SCENARIO 1: Le PDU (seq 100) arrive EN PREMIER (Fast Path UDP)
    // ------------------------------------------------------------------------
    let pdu_100 = DataPdu { epoch: 1, seq: 100, protected_field: 0xCAFE_BABE };
    let res_pdu_100 = validator.receive_pdu(&pdu_100);
    println!("[UDP] PDU seq 100 reçu AVANT le trust -> {:?}", res_pdu_100);
    assert_eq!(res_pdu_100, ImmediatePduResult::BufferedWaitingForTrust);

    let trust_100 = TrustDescriptor { epoch: 1, seq: 100, expected_digest: compute_digest(0xCAFE_BABE) };
    let res_trust_100 = validator.receive_trust(&trust_100);
    println!("[TRUST] Descripteur seq 100 reçu plus tard -> Corrélation : {:?}", res_trust_100);
    assert_eq!(res_trust_100, ImmediateTrustResult::CorrelatedValid);

    // ------------------------------------------------------------------------
    // SCENARIO 2: PDU Altérée reçue avant son trust descriptor (seq 101)
    // ------------------------------------------------------------------------
    let pdu_tampered = DataPdu { epoch: 1, seq: 101, protected_field: 0xDEAD_0000 };
    let res_pdu_101 = validator.receive_pdu(&pdu_tampered);
    assert_eq!(res_pdu_101, ImmediatePduResult::BufferedWaitingForTrust);

    let trust_101 = TrustDescriptor { epoch: 1, seq: 101, expected_digest: compute_digest(0xDEAD_BEEF) };
    let res_trust_101 = validator.receive_trust(&trust_101);
    assert_eq!(res_trust_101, ImmediateTrustResult::CorrelatedTampered);

    // ------------------------------------------------------------------------
    // SCENARIO 3: PDU Dupliquée (Rejeu du seq 100)
    // ------------------------------------------------------------------------
    let pdu_replay = DataPdu { epoch: 1, seq: 100, protected_field: 0xCAFE_BABE };
    let res_replay = validator.receive_pdu(&pdu_replay);
    assert_eq!(res_replay, ImmediatePduResult::Duplicated);

    // ------------------------------------------------------------------------
    // SCENARIO 4: Rejeu d'un paquet d'une ancienne époque (Stale Epoch)
    // ------------------------------------------------------------------------
    let pdu_stale = DataPdu { epoch: 0, seq: 100, protected_field: 0xCAFE_BABE };
    let res_stale = validator.receive_pdu(&pdu_stale);
    println!("[UDP] Rejeu d'une session antérieure (Epoch 0 < 1) -> {:?}", res_stale);
    assert_eq!(res_stale, ImmediatePduResult::StaleEpoch);

    // ------------------------------------------------------------------------
    // SCENARIO 5: PDU Ajoutée / Injectée (seq 102 reçu, mais A ne l'a jamais émis)
    // ------------------------------------------------------------------------
    let pdu_injected = DataPdu { epoch: 1, seq: 102, protected_field: 0x9999_9999 };
    let res_injected = validator.receive_pdu(&pdu_injected);
    assert_eq!(res_injected, ImmediatePduResult::BufferedWaitingForTrust);

    // ------------------------------------------------------------------------
    // SCENARIO 6: PDU Supprimée (seq 103 émis par A dans le flux de confiance, mais PDU perdu)
    // ------------------------------------------------------------------------
    let trust_103 = TrustDescriptor { epoch: 1, seq: 103, expected_digest: compute_digest(0x5555_5555) };
    let res_trust_103 = validator.receive_trust(&trust_103);
    assert_eq!(res_trust_103, ImmediateTrustResult::BufferedWaitingForPdu);

    // ------------------------------------------------------------------------
    // AVANCEMENT DE FENÊTRE & DÉTECTIONS D'EXPIRATION
    // ------------------------------------------------------------------------
    println!("\n--- Avancement de la fenêtre glissante ---");
    let ev100 = validator.advance_one_slot();
    assert_eq!(ev100, EvictionReport::NormalValidated { seq: 100 });

    let ev101 = validator.advance_one_slot();
    assert_eq!(ev101, EvictionReport::TamperedResidual { seq: 101 });

    let ev102 = validator.advance_one_slot();
    assert_eq!(ev102, EvictionReport::AddedPdu { seq: 102 });

    let ev103 = validator.advance_one_slot();
    assert_eq!(ev103, EvictionReport::DroppedPdu { seq: 103 });

    println!("\n=== Toutes les anomalies asynchrones UDP sont formellement détectées ===");
}
