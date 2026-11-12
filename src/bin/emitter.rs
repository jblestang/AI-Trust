// ============================================================================
// Machine A: Émetteur de Flux Réseau & Générateur de Flux de Confiance
//
// Rôle :
//   - Gère le compteur d'époque persistant (Epoch / Boot Counter) incrémenté
//     à chaque redémarrage de l'équipement
//   - Émet des Data PDUs vers Machine B sur le port UDP 9001 (24 octets)
//   - Calcule, HISTORISE SUR DISQUE (WAL résilient aux crashs) et émet
//     des Trust Descriptors vers Machine B sur le port UDP 9002 (24 octets)
// ============================================================================

use ai_trust::{compute_digest, HardwareMonotonicCounter, TrustDescriptor, TrustJournal};
use std::net::UdpSocket;
use std::thread::sleep;
use std::time::Duration;

/// Cible du flux de données sur Machine B
const B_DATA_ADDR: &str = "127.0.0.1:9001";
/// Cible du flux de confiance sur Machine B
const B_TRUST_ADDR: &str = "127.0.0.1:9002";
/// Chemin du fichier journal persistant WAL (Write-Ahead Log sur disque amovible)
const JOURNAL_PATH: &str = "target/emitter_trust.wal";
/// Chemin du registre matériel non-volatile hors-disque (TPM 2.0 / NVRAM carte mère)
const NVRAM_COUNTER_PATH: &str = "target/nvram_epoch_counter.bin";

/// Sérialise un DataPdu sous forme de trame binaire de 24 octets
fn serialize_pdu(epoch: u64, seq: u64, protected_field: u64) -> [u8; 24] {
    let mut buf = [0u8; 24];
    buf[0..8].copy_from_slice(&epoch.to_be_bytes());
    buf[8..16].copy_from_slice(&seq.to_be_bytes());
    buf[16..24].copy_from_slice(&protected_field.to_be_bytes());
    buf
}

/// Sérialise un TrustDescriptor sous forme de trame binaire de 24 octets
fn serialize_trust(epoch: u64, seq: u64, expected_digest: u64) -> [u8; 24] {
    let mut buf = [0u8; 24];
    buf[0..8].copy_from_slice(&epoch.to_be_bytes());
    buf[8..16].copy_from_slice(&seq.to_be_bytes());
    buf[16..24].copy_from_slice(&expected_digest.to_be_bytes());
    buf
}

fn main() -> std::io::Result<()> {
    println!("============================================================");
    println!("  MACHINE A : ÉMETTEUR AVEC GESTION D'EPOCH (REDÉMARRAGE)   ");
    println!("============================================================");

    // Initialisation du journal persistant Write-Ahead Log
    let journal = TrustJournal::new(JOURNAL_PATH);
    let initial_records = journal.recover()?;

    // Lecture du compteur matériel hors-disque (TPM 2.0 / NVRAM carte mère)
    // Garanti strictement monotone MÊME EN CAS DE REMPLACEMENT DU DISQUE DUR
    let hw_counter = HardwareMonotonicCounter::new(NVRAM_COUNTER_PATH);
    let current_epoch = hw_counter.fetch_and_increment()?;

    println!(
        "[BOOT] Initialisation Session Machine A | Epoch matériel (TPM/NVRAM): {} ({} entrées disque antérieures)",
        current_epoch,
        initial_records.len()
    );

    // Socket local émetteur sur port éphémère
    let socket = UdpSocket::bind("127.0.0.1:0")?;

    println!("[INFO] Destination Données    : {}", B_DATA_ADDR);
    println!("[INFO] Destination Confiance : {}", B_TRUST_ADDR);
    println!("[INFO] Pause de 500ms avant le début de la séquence...\n");
    sleep(Duration::from_millis(500));

    // Helper d'émission de trust descriptor avec scellement préalable sur disque
    let emit_and_persist_trust = |epoch: u64, seq: u64, digest: u64| -> std::io::Result<()> {
        let desc = TrustDescriptor {
            epoch,
            seq,
            expected_digest: digest,
        };
        // 1. Scellement persistant avec fsync physique
        journal.append(&desc)?;
        println!(
            "  -> [DISK SYNC] TrustDescriptor (Epoch {}, Seq {}) scellé (digest: 0x{:08X})",
            epoch, seq, digest
        );
        // 2. Émission réseau UDP
        socket.send_to(&serialize_trust(epoch, seq, digest), B_TRUST_ADDR)?;
        Ok(())
    };

    // ------------------------------------------------------------------------
    // SCÉNARIO 1 : Transmission normale asynchrone (Seq 0)
    // ------------------------------------------------------------------------
    println!("--- [SCÉNARIO 1] Transmission normale : PDU émis AVANT son Trust ---");
    let seq_0 = 0u64;
    let field_0 = 0xAAAA_1111;
    let digest_0 = compute_digest(field_0);

    println!("  -> Émission PDU (Epoch {}, Seq {})", current_epoch, seq_0);
    socket.send_to(&serialize_pdu(current_epoch, seq_0, field_0), B_DATA_ADDR)?;

    sleep(Duration::from_millis(150));
    emit_and_persist_trust(current_epoch, seq_0, digest_0)?;
    sleep(Duration::from_millis(300));

    // ------------------------------------------------------------------------
    // SCÉNARIO 2 : Désordre UDP (Jitter) entre Seq 1 et Seq 2
    // ------------------------------------------------------------------------
    println!("\n--- [SCÉNARIO 2] Désordre UDP : Seq 2 arrive AVANT Seq 1 ---");
    let seq_1 = 1u64;
    let field_1 = 0xBBBB_2222;
    let digest_1 = compute_digest(field_1);

    let seq_2 = 2u64;
    let field_2 = 0xCCCC_3333;
    let digest_2 = compute_digest(field_2);

    println!("  -> Émission PDU (Epoch {}, Seq 2 en avance)", current_epoch);
    socket.send_to(&serialize_pdu(current_epoch, seq_2, field_2), B_DATA_ADDR)?;
    sleep(Duration::from_millis(50));

    println!("  -> Émission PDU (Epoch {}, Seq 1)", current_epoch);
    socket.send_to(&serialize_pdu(current_epoch, seq_1, field_1), B_DATA_ADDR)?;
    sleep(Duration::from_millis(150));

    emit_and_persist_trust(current_epoch, seq_1, digest_1)?;
    emit_and_persist_trust(current_epoch, seq_2, digest_2)?;
    sleep(Duration::from_millis(300));

    // ------------------------------------------------------------------------
    // SCÉNARIO 3 : Rejeu malveillant d'un paquet d'une ancienne époque (Stale Epoch)
    // ------------------------------------------------------------------------
    if current_epoch > 1 {
        println!("\n--- [SCÉNARIO 3] Attaque par rejeu inter-sessions (Stale Epoch) ---");
        let stale_epoch = current_epoch - 1;
        println!("  -> Attaquant réinjecte un paquet de l'époque précédente (Epoch {}, Seq 0)", stale_epoch);
        socket.send_to(&serialize_pdu(stale_epoch, 0, 0xAAAA_1111), B_DATA_ADDR)?;
        sleep(Duration::from_millis(300));
    }

    println!("\n[INFO] Tous les scénarios ont été émis. Attente de la fin de l'audit B...");
    sleep(Duration::from_secs(3));

    println!("============================================================");
    println!("  MACHINE A : FIN D'ÉMISSION & HISTORISATION RÉUSSIE");
    println!("============================================================");
    Ok(())
}
