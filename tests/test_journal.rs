use ai_trust::{compute_digest, DiskRecord, TrustDescriptor, TrustJournal};
use std::fs::OpenOptions;
use std::io::Write;

fn temp_journal_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("ai_trust_test_{}_{}.wal", name, nanos));
    p
}

#[test]
fn test_journal_normal_append_and_recovery() {
    let path = temp_journal_path("normal");
    let journal = TrustJournal::new(&path);

    let descriptors = vec![
        TrustDescriptor { epoch: 1, seq: 0, expected_digest: compute_digest(100) },
        TrustDescriptor { epoch: 1, seq: 1, expected_digest: compute_digest(200) },
        TrustDescriptor { epoch: 1, seq: 2, expected_digest: compute_digest(300) },
    ];

    for desc in &descriptors {
        assert!(journal.append(desc).is_ok());
    }

    let recovered = journal.recover_trust_descriptors().unwrap_or_default();
    assert_eq!(recovered.len(), 3);
    assert_eq!(recovered, descriptors);

    assert_eq!(journal.recover_and_truncate().unwrap_or_default().len(), 3);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_journal_crash_partial_trailing_write() {
    let path = temp_journal_path("partial_crash");
    let journal = TrustJournal::new(&path);

    for i in 0..3u64 {
        let desc = TrustDescriptor { epoch: 1, seq: i, expected_digest: compute_digest(i * 10) };
        assert!(journal.append(&desc).is_ok());
    }

    // Coupure de courant pendant l'écriture du 4e enregistrement (14 octets sur 40)
    if let Ok(mut file) = OpenOptions::new().append(true).open(&path) {
        let partial_bytes = [0x54, 0x52, 0x55, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB];
        assert!(file.write_all(&partial_bytes).is_ok());
        assert!(file.sync_data().is_ok());
    }

    let recovered = journal.recover_trust_descriptors().unwrap_or_default();
    assert_eq!(recovered.len(), 3);
    assert_eq!(recovered[0].seq, 0);
    assert_eq!(recovered[1].seq, 1);
    assert_eq!(recovered[2].seq, 2);

    let truncated_records = journal.recover_and_truncate().unwrap_or_default();
    assert_eq!(truncated_records.len(), 3);
    let final_file_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(final_file_len, 3 * 40);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_journal_crash_corrupted_checksum() {
    let path = temp_journal_path("corrupt_checksum");
    let journal = TrustJournal::new(&path);

    for i in 0..2u64 {
        let desc = TrustDescriptor { epoch: 1, seq: i, expected_digest: compute_digest(i + 1) };
        assert!(journal.append(&desc).is_ok());
    }

    // Corruption de bit dans le checksum (bloc 3)
    if let Ok(mut file) = OpenOptions::new().append(true).open(&path) {
        let mut corrupted_block = TrustJournal::encode_record(1, 2, compute_digest(3));
        corrupted_block[39] ^= 0xFF;
        assert!(file.write_all(&corrupted_block).is_ok());
        assert!(file.sync_data().is_ok());
    }

    let recovered = journal.recover().unwrap_or_default();
    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[0].seq, 0);
    assert_eq!(recovered[1].seq, 1);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_journal_invalid_magic_handling() {
    let path = temp_journal_path("bad_magic");
    let journal = TrustJournal::new(&path);

    let desc = TrustDescriptor { epoch: 1, seq: 0, expected_digest: 0x1234 };
    assert!(journal.append(&desc).is_ok());

    if let Ok(mut file) = OpenOptions::new().append(true).open(&path) {
        let mut bad_magic_block = TrustJournal::encode_record(1, 1, 0x5678);
        bad_magic_block[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        assert!(file.write_all(&bad_magic_block).is_ok());
    }

    let recovered = journal.recover().unwrap_or_default();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].seq, 0);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_journal_non_monotonic_sequence_breaks_prefix() {
    let path = temp_journal_path("non_monotonic");
    let journal = TrustJournal::new(&path);

    assert!(journal.append(&TrustDescriptor { epoch: 1, seq: 10, expected_digest: 1 }).is_ok());
    assert!(journal.append(&TrustDescriptor { epoch: 1, seq: 11, expected_digest: 2 }).is_ok());

    // Enregistrement non monotone (seq 5 < 11 sur même époque)
    let replayed_block = TrustJournal::encode_record(1, 5, 3);
    if let Ok(mut file) = OpenOptions::new().append(true).open(&path) {
        assert!(file.write_all(&replayed_block).is_ok());
    }

    let recovered = journal.recover().unwrap_or_default();
    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[0].seq, 10);
    assert_eq!(recovered[1].seq, 11);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_journal_idempotence_and_non_existent_file() {
    let path = temp_journal_path("idempotence");
    let journal = TrustJournal::new(&path);

    assert_eq!(journal.recover().unwrap_or(vec![DiskRecord { magic: 0, epoch: 0, seq: 0, expected_digest: 0, checksum: 0 }]).len(), 0);

    assert!(journal.append(&TrustDescriptor { epoch: 1, seq: 1, expected_digest: 100 }).is_ok());
    assert!(journal.append(&TrustDescriptor { epoch: 1, seq: 2, expected_digest: 200 }).is_ok());

    let rec1 = journal.recover_trust_descriptors().unwrap_or_default();
    let rec2 = journal.recover_trust_descriptors().unwrap_or_default();
    let rec3 = journal.recover_trust_descriptors().unwrap_or_default();

    assert_eq!(rec1, rec2);
    assert_eq!(rec2, rec3);
    assert_eq!(rec1.len(), 2);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_journal_edge_cases_buffer_len_and_truncate_non_existent() {
    let short_buf = [0u8; 25];
    assert!(TrustJournal::decode_record(&short_buf).is_none());

    let non_existent = temp_journal_path("truncate_non_existent");
    let journal = TrustJournal::new(&non_existent);
    assert_eq!(journal.recover_and_truncate().unwrap_or(vec![DiskRecord { magic: 0, epoch: 0, seq: 0, expected_digest: 0, checksum: 0 }]).len(), 0);
}

#[test]
fn test_hardware_monotonic_counter_persistence_and_increment() {
    let path = temp_journal_path("hw_nvram");
    let counter = ai_trust::HardwareMonotonicCounter::new(&path);

    // Registre inexistant -> lecture = 0
    assert_eq!(counter.read().unwrap_or(999), 0);

    // Incrémentations successives
    assert_eq!(counter.fetch_and_increment().unwrap_or(0), 1);
    assert_eq!(counter.read().unwrap_or(0), 1);
    assert_eq!(counter.fetch_and_increment().unwrap_or(0), 2);
    assert_eq!(counter.fetch_and_increment().unwrap_or(0), 3);
    assert_eq!(counter.read().unwrap_or(0), 3);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_hard_drive_replacement_survival() {
    let nvram_path = temp_journal_path("tpm_motherboard");
    let disk1_path = temp_journal_path("disk1_old");
    let disk2_path = temp_journal_path("disk2_new");

    let hw_counter = ai_trust::HardwareMonotonicCounter::new(&nvram_path);

    // 1. Session avec Disque 1
    let epoch1 = hw_counter.fetch_and_increment().unwrap_or(0);
    assert_eq!(epoch1, 1);
    let journal_disk1 = TrustJournal::new(&disk1_path);
    assert!(journal_disk1.append(&TrustDescriptor { epoch: epoch1, seq: 0, expected_digest: compute_digest(10) }).is_ok());
    assert!(journal_disk1.append(&TrustDescriptor { epoch: epoch1, seq: 1, expected_digest: compute_digest(20) }).is_ok());

    let mut receiver_b = ai_trust::SlidingWindowValidator::new(1, 0);
    assert_eq!(
        receiver_b.receive_trust(&TrustDescriptor { epoch: epoch1, seq: 0, expected_digest: compute_digest(10) }),
        ai_trust::ImmediateTrustResult::BufferedWaitingForPdu
    );

    // 2. SIMULATION DU REMPLACEMENT DU DISQUE DUR (Panne matérielle / Disque détruit)
    let _ = std::fs::remove_file(&disk1_path); // Disque 1 n'existe plus !

    // 3. Nouveau disque vierge (Disque 2)
    // Le composant TPM/NVRAM sur la carte mère a survécu :
    let epoch2 = hw_counter.fetch_and_increment().unwrap_or(0);
    assert_eq!(epoch2, 2); // Strictement supérieur à epoch1 !

    let journal_disk2 = TrustJournal::new(&disk2_path);
    assert!(journal_disk2.append(&TrustDescriptor { epoch: epoch2, seq: 0, expected_digest: compute_digest(100) }).is_ok());

    // 4. Machine B reçoit le nouveau descripteur émis avec le nouveau disque :
    // B valide la transition d'époque et n'est JAMAIS bloqué !
    let res = receiver_b.receive_trust(&TrustDescriptor { epoch: epoch2, seq: 0, expected_digest: compute_digest(100) });
    assert_eq!(res, ai_trust::ImmediateTrustResult::NewEpochInitialized);
    assert_eq!(receiver_b.current_epoch, 2);
    assert_eq!(receiver_b.window_base, 0);

    let _ = std::fs::remove_file(&nvram_path);
    let _ = std::fs::remove_file(&disk2_path);
}

#[test]
fn test_hardware_monotonic_counter_short_bytes() {
    let path = temp_journal_path("hw_short");
    if let Ok(mut file) = OpenOptions::new().create(true).write(true).truncate(true).open(&path) {
        assert!(file.write_all(&[1, 2, 3]).is_ok());
    }
    let counter = ai_trust::HardwareMonotonicCounter::new(&path);
    assert_eq!(counter.read().unwrap_or(999), 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_journal_group_commit_batch() {
    let path = temp_journal_path("batch_commit");
    let journal = TrustJournal::new(&path);

    // Test lot vide -> Ok(())
    assert!(journal.append_batch(&[]).is_ok());

    let batch = vec![
        TrustDescriptor { epoch: 1, seq: 10, expected_digest: compute_digest(10) },
        TrustDescriptor { epoch: 1, seq: 11, expected_digest: compute_digest(20) },
        TrustDescriptor { epoch: 1, seq: 12, expected_digest: compute_digest(30) },
        TrustDescriptor { epoch: 1, seq: 13, expected_digest: compute_digest(40) },
    ];

    assert!(journal.append_batch(&batch).is_ok());

    let recovered = journal.recover_trust_descriptors().unwrap_or_default();
    assert_eq!(recovered.len(), 4);
    assert_eq!(recovered, batch);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_journal_binary_serialization_roundtrip_and_layout() {
    let epoch = 42u64;
    let seq = 1337u64;
    let digest = compute_digest(0xCAFE);

    let bytes = TrustJournal::encode_record(epoch, seq, digest);
    assert_eq!(bytes.len(), 40);

    // Vérification de la disposition mémoire exacte conforme à la spec formelle SMT
    assert_eq!(&bytes[0..4], b"TRUS");
    assert_eq!(&bytes[4..8], &[0u8; 4]);
    assert_eq!(&bytes[8..16], &epoch.to_be_bytes());
    assert_eq!(&bytes[16..24], &seq.to_be_bytes());
    assert_eq!(&bytes[24..32], &digest.to_be_bytes());

    let expected_checksum = ai_trust::compute_record_checksum(ai_trust::JOURNAL_MAGIC, epoch, seq, digest);
    assert_eq!(&bytes[32..40], &expected_checksum.to_be_bytes());

    // Vérification du roundtrip decode_record(encode_record) == Some(rec)
    let decoded = TrustJournal::decode_record(&bytes);
    assert!(decoded.is_some());
    let rec = decoded.unwrap_or(DiskRecord { magic: 0, epoch: 0, seq: 0, expected_digest: 0, checksum: 0 });
    assert_eq!(rec.magic, ai_trust::JOURNAL_MAGIC);
    assert_eq!(rec.epoch, epoch);
    assert_eq!(rec.seq, seq);
    assert_eq!(rec.expected_digest, digest);
    assert_eq!(rec.checksum, expected_checksum);
}


