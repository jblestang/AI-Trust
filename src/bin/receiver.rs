// ============================================================================
// Machine B: Récepteur et Validateur Formel de Flux Réseau UDP (avec Epoch)
//
// Rôle :
//   - Écoute sur le port UDP 9001 (Canal de Données non sécurisé)
//   - Écoute sur le port UDP 9002 (Canal de Confiance intègre)
//   - Gère le suivi d'époque (Epoch / Boot Counter) pour s'adapter
//     instantanément au redémarrage de Machine A sans état persistant
//   - Détecte le rejeu de sessions antérieures (`StaleEpoch`)
// ============================================================================

use ai_trust::*;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

/// Adresse d'écoute pour le canal de données (PDU)
const DATA_BIND_ADDR: &str = "127.0.0.1:9001";
/// Adresse d'écoute pour le canal de confiance (Trust Descriptors)
const TRUST_BIND_ADDR: &str = "127.0.0.1:9002";

/// Désérialise un DataPdu depuis un buffer de 24 octets
fn parse_data_pdu(buf: &[u8]) -> Option<DataPdu> {
    if buf.len() < 24 {
        return None;
    }
    let epoch = u64::from_be_bytes(buf[0..8].try_into().ok()?);
    let seq = u64::from_be_bytes(buf[8..16].try_into().ok()?);
    let protected_field = u64::from_be_bytes(buf[16..24].try_into().ok()?);
    Some(DataPdu { epoch, seq, protected_field })
}

/// Désérialise un TrustDescriptor depuis un buffer de 24 octets
fn parse_trust_descriptor(buf: &[u8]) -> Option<TrustDescriptor> {
    if buf.len() < 24 {
        return None;
    }
    let epoch = u64::from_be_bytes(buf[0..8].try_into().ok()?);
    let seq = u64::from_be_bytes(buf[8..16].try_into().ok()?);
    let expected_digest = u64::from_be_bytes(buf[16..24].try_into().ok()?);
    Some(TrustDescriptor { epoch, seq, expected_digest })
}

fn main() -> std::io::Result<()> {
    println!("============================================================");
    println!("  MACHINE B : DÉMARRAGE DU VALIDATEUR AVEC GESTION D'EPOCH ");
    println!("============================================================");

    let data_socket = UdpSocket::bind(DATA_BIND_ADDR)?;
    let trust_socket = UdpSocket::bind(TRUST_BIND_ADDR)?;

    data_socket.set_nonblocking(true)?;
    trust_socket.set_nonblocking(true)?;

    println!("[RÉSEAU] Écoute Flux Données    : {}", DATA_BIND_ADDR);
    println!("[RÉSEAU] Écoute Flux Confiance : {}", TRUST_BIND_ADDR);

    let mut validator = SlidingWindowValidator::new_cold_start();
    println!(
        "[ÉTAT] Fenêtre glissante active en mode COLD-START (en attente d'auto-acquisition, capacité: {} slots)\n",
        WINDOW_CAPACITY
    );

    let mut buf = [0u8; 64];
    let mut stream_active = false;
    let mut last_activity = Instant::now();
    let mut last_advance = Instant::now();
    let advance_interval = Duration::from_millis(800);

    while !stream_active || last_activity.elapsed() < Duration::from_secs(3) {
        // 1. Dépouillement des paquets de données (Data PDUs)
        match data_socket.recv_from(&mut buf) {
            Ok((len, _src)) => {
                if let Some(pdu) = parse_data_pdu(&buf[..len]) {
                    if !stream_active {
                        stream_active = true;
                        last_advance = Instant::now();
                    }
                    last_activity = Instant::now();
                    let outcome = validator.receive_pdu(&pdu);
                    match outcome {
                        ImmediatePduResult::BufferedWaitingForTrust => {
                            println!(
                                "  [PDU REÇU]   Epoch: {} | Seq: {:<4} -> En attente de certification A",
                                pdu.epoch, pdu.seq
                            );
                        }
                        ImmediatePduResult::CorrelatedValid => {
                            println!(
                                "  [✓ VALIDE]   Epoch: {} | Seq: {:<4} -> Authentifié avec succès !",
                                pdu.epoch, pdu.seq
                            );
                        }
                        ImmediatePduResult::CorrelatedTampered => {
                            println!(
                                "  [⚠ ALTÉRÉ]   Epoch: {} | Seq: {:<4} | ALERTE : Empreinte divergente !",
                                pdu.epoch, pdu.seq
                            );
                        }
                        ImmediatePduResult::Duplicated => {
                            println!(
                                "  [⚠ REJEU]    Epoch: {} | Seq: {:<4} | ALERTE : PDU dupliquée !",
                                pdu.epoch, pdu.seq
                            );
                        }
                        ImmediatePduResult::StaleEpoch => {
                            println!(
                                "  [🔥 ÉPOQUE OBSOLÈTE] Epoch: {} < {} | ALERTE : Rejeu d'une session antérieure rejeté !",
                                pdu.epoch, validator.current_epoch
                            );
                        }
                        ImmediatePduResult::OutOfWindow => {
                            println!(
                                "  [PDU HORS]   Epoch: {} | Seq: {:<4} | Hors fenêtre glissante",
                                pdu.epoch, pdu.seq
                            );
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        // 2. Dépouillement des descripteurs de confiance (Trust Descriptors)
        match trust_socket.recv_from(&mut buf) {
            Ok((len, _src)) => {
                if let Some(trust) = parse_trust_descriptor(&buf[..len]) {
                    if !stream_active {
                        stream_active = true;
                        last_advance = Instant::now();
                    }
                    last_activity = Instant::now();
                    let outcome = validator.receive_trust(&trust);
                    match outcome {
                        ImmediateTrustResult::ColdStartSynchronized => {
                            println!(
                                "  [❄ COLD-START ACQUIS] Synchronisation initiale réussie sur Epoch {} | Seq: {:<4}",
                                trust.epoch, trust.seq
                            );
                        }
                        ImmediateTrustResult::BufferedWaitingForPdu => {
                            println!(
                                "  [TRUST REÇU] Epoch: {} | Seq: {:<4} -> En attente du PDU",
                                trust.epoch, trust.seq
                            );
                        }
                        ImmediateTrustResult::CorrelatedValid => {
                            println!(
                                "  [✓ CORRÉLÉ]  Epoch: {} | Seq: {:<4} | Certification validée !",
                                trust.epoch, trust.seq
                            );
                        }
                        ImmediateTrustResult::CorrelatedTampered => {
                            println!(
                                "  [⚠ ALTÉRÉ]   Epoch: {} | Seq: {:<4} | ALERTE : Tampering !",
                                trust.epoch, trust.seq
                            );
                        }
                        ImmediateTrustResult::NewEpochInitialized => {
                            println!(
                                "  [🔄 NOUVEL ÉPOQUE] Passage authentifié à l'Epoch {} (Redémarrage de A détecté)",
                                trust.epoch
                            );
                        }
                        ImmediateTrustResult::RedundantTrust => {
                            println!(
                                "  [TRUST DUP]  Epoch: {} | Seq: {:<4} | Descripteur redondant",
                                trust.epoch, trust.seq
                            );
                        }
                        ImmediateTrustResult::StaleEpoch => {
                            println!(
                                "  [TRUST OBS]  Epoch: {} < {} | Descripteur d'une époque antérieure ignoré",
                                trust.epoch, validator.current_epoch
                            );
                        }
                        ImmediateTrustResult::OutOfWindow => {
                            println!(
                                "  [TRUST HORS] Epoch: {} | Seq: {:<4} | Descripteur hors fenêtre",
                                trust.epoch, trust.seq
                            );
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        // 3. Avancement temporisé de la fenêtre
        if stream_active && last_advance.elapsed() >= advance_interval {
            let report = validator.advance_one_slot();
            match report {
                EvictionReport::DroppedPdu { seq } => {
                    println!("  [🔥 SUPPRIMÉ] Seq: {:<4} | ALERTE : PDU perdue !", seq);
                }
                EvictionReport::AddedPdu { seq } => {
                    println!("  [🔥 AJOUTÉ]   Seq: {:<4} | ALERTE : PDU injectée sans certification !", seq);
                }
                EvictionReport::NormalValidated { seq } => {
                    println!("  [CLÔTURE OK]  Seq: {:<4} | Clôturé avec succès", seq);
                }
                EvictionReport::TamperedResidual { seq } => {
                    println!("  [CLÔTURE ALT] Seq: {:<4} | PDU altéré évincé", seq);
                }
                EvictionReport::None => {}
            }
            last_advance = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(5));
    }

    println!("\n============================================================");
    println!("  MACHINE B : FIN DE SESSION DE SURVEILLANCE");
    println!("============================================================");
    Ok(())
}
