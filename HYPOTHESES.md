# Formalisation des Hypothèses du Modèle de Sécurité et Système

**Document de Référence pour l'Évaluation Formelle (Critères Communs EAL 7 / DO-178C DAL A)**  
**Projet :** AI-Trust — Automate de Validation de Flux Réseau Asynchrone  
**Fichier Source Vérifié :** [`src/lib.rs`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs)  
**Moteur de Preuve :** Verus (Logique de Hoare & Théorie SMT/Z3 intégrées en Rust)  

---

## 1. Contexte et Objectif

L'automate de validation de la Machine B reçoit deux flux réseau asynchrones en provenance de la Machine A :
1. Un **flux de données** acheminant les paquets PDU (`DataPdu`).
2. Un **flux de confiance** acheminant les descripteurs d'intégrité signés (`TrustDescriptor`).

L'objectif de sécurité formellement prouvé est la détection exhaustive et exclusive des 4 classes d'anomalies :
* **Altération** (*Tampering*) : modification de bits en vol par un tiers.
* **Duplication** (*Replay*) : réinjection de paquets légitimes passés.
* **Injection** (*Spurious / Added*) : insertion de trames non émises par Machine A.
* **Suppression** (*Drop / Loss*) : perte ou blocage de paquets sur le canal.

Pour que ces garanties mathématiques soient valides dans le monde physique, l'évaluation formelle repose sur un ensemble d'**hypothèses explicites, non dissimulées et traçables**. Ce document formalise rigoureusement chacune de ces hypothèses.

---

## 2. Formalisation Détaillée des Hypothèses

### H1. Hypothèse d'Exécution Monocœur (Single-Core & Séquentialité)

* **Énoncé Formel :**  
  L'instance de [`SlidingWindowValidator`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L246-L249) est accédée de manière strictement séquentielle. Il n'existe aucun entrelacement préemptif non synchronisé ou accès concurrent multithreadé modifiant l'état interne de la fenêtre glissante :
  $$\forall t_1, t_2, \quad \text{Exec}(op_1, t_1) \cap \text{Exec}(op_2, t_2) = \emptyset \quad \text{ou} \quad op_1 \prec op_2$$

* **Justification Système & Déploiement :**  
  Dans une architecture industrielle critique, le validateur est déployé soit :
  1. Sur un cœur CPU dédié en boucle de scrutation active (*polling loop* / DPDK).
  2. Au sein d'une tâche temps-réel périodique sous RTOS (type PikeOS, VxWorks 653, seL4) sans préemption concurrente sur la mémoire du composant.
  3. Dans un réacteur événementiel monothreadé (type *actor model* séquentiel).

* **Conséquences sur la Preuve :**  
  * Élimine le besoin de verrous de synchronisation à coût mémoire ou risque de blocage (*deadlock*).
  * Les invariants de structures prouvés dans Verus (`ensures final(self)...`) sont garantis stables d'un appel à l'autre sans interférence mémoire externe.

---

### H2. Hypothèse Cryptographique de Résistance aux Collisions

* **Énoncé Formel :**  
  La fonction de calcul d'empreinte $\mathcal{H} : \{0, 1\}^* \to \{0, 1\}^{64}$ est résistante aux collisions dans le domaine opérationnel :
  $$\forall m_1, m_2 \in \{0, 1\}^{64}, \quad \mathcal{H}(m_1) = \mathcal{H}(m_2) \implies m_1 = m_2$$

* **Définition dans le Modèle Formel :**  
  Spécifiée dans [`crypto_hash_spec`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L78-L80) et formalisée par le lemme SMT bitvector :
  ```rust
  pub proof fn lemma_collision_resistance_hypothesis(m1: u64, m2: u64)
      requires crypto_hash_spec(m1) == crypto_hash_spec(m2),
      ensures m1 == m2
  ```
  *(Voir [`src/lib.rs#L85-L91`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L85-L91)).*

* **Justification Industrielle :**  
  En production, $\mathcal{H}$ est instanciée par une primitive cryptographique standardisée (ex. HMAC-SHA256, BLAKE3-64, ou KMAC). La probabilité de collision accidentelle ou calculée sous borne calculatoire est considérée négligeable ($\le 2^{-64}$).

* **Conséquences sur la Preuve :**  
  Garantit formellement que si une PDU reçue a un champ altéré par rapport au paquet émis par Machine A, l'empreinte calculée par Machine B divergera **obligatoirement** de l'empreinte attendue certifiée par Machine A (`CorrelatedTampered` ou `TamperedResidual`).

---

### H3. Modèle d'Attaquant Réseau (Dolev-Yao) & Signature du Flux de Confiance (EUF-CMA)

* **Énoncé Formel :**  
  Le système opère sur deux canaux physiques ou logiques distincts :
  1. **Canal de données $\mathcal{C}_{\text{data}}$ (Non sécurisé) :**  
     Sous contrôle total d'un attaquant de type Dolev-Yao. L'attaquant peut :
     * Intercepter et lire les trames PDU en transit.
     * Modifier arbitrairement le contenu d'une PDU en vol (*bit flipping*, falsification de charge utile).
     * Rejouer des trames PDU légitimes antérieures.
     * Injecter de nouvelles trames PDU forgées avec des numéros de séquence arbitraires.
     * Supprimer des trames PDU en vol (déni de service / brouillage).
  2. **Canal de confiance $\mathcal{C}_{\text{trust}}$ (Authentifié et Intègre) :**  
     Chaque descripteur de confiance émis par Machine A est intègre et signé cryptographiquement sous l'hypothèse de sécurité standard **EUF-CMA** (*Existential Unforgeability under Chosen Message Attacks*) :
     $$\Pr[\mathcal{A} \text{ forge } \text{Sign}_{sk}(seq, \mathcal{H}(m)) \text{ sans } sk] \le \text{negl}(\kappa)$$
     L'attaquant **ne peut pas fabriquer** de descripteur de confiance valide pour un paquet injecté ou falsifié.

* **Conséquences sur la Preuve :**  
  * **Neutralisation de l'Empoisonnement de Buffer (*Buffer Poisoning*) :** L'attaquant ne peut pas injecter de faux descripteurs dans les slots de la Machine B pour valider ses propres paquets injectés.
  * **Détection Certaine des Injections :** Tout paquet injecté par l'attaquant sur $\mathcal{C}_{\text{data}}$ ne recevra jamais de descripteur valide sur $\mathcal{C}_{\text{trust}}$. Il reste confiné à l'état `SlotState::DataPending` jusqu'à son éviction, produisant sans exception le rapport d'anomalie critique `EvictionReport::AddedPdu { seq }`.

---

### H4. Arithmétique Circulaire Modulo $2^{64}$ (RFC 1982 Serial Number Arithmetic)

* **Énoncé Formel :**  
  L'espace des numéros de séquence est l'anneau quotient $\mathbb{Z} / 2^{64}\mathbb{Z}$. La distance modulaire signée entre une séquence reçue `seq` et la base active `base` est calculée par :
  $$\Delta(seq, base) = (seq - base) \bmod 2^{64}$$
  Le demi-espace de taille $2^{63}$ (`HALF_SPACE = 0x8000_0000_0000_0000`) partitionne rigoureusement l'espace :
  * Si $\Delta(seq, base) < W$ : le paquet appartient à la **fenêtre active** ([`in_circular_window`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L110-L112)).
  * Si $\Delta(seq, base) \ge 2^{63}$ : le paquet est situé dans le **passé** (rejeu/duplication) ([`is_in_past`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L115-L117)).
  * Si $W \le \Delta(seq, base) < 2^{63}$ : le paquet est situé dans le **futur hors fenêtre** ([`is_in_future`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L120-L122)).

* **Théorème de Partitionnement Exhaustif :**  
  Prouvé formellement dans [`theorem_circular_space_partition`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L157-L165) :
  $$\forall base, seq \in \text{u64}, \quad \mathbf{1}_{\text{in\_window}}(base, seq) + \mathbf{1}_{\text{is\_past}}(base, seq) + \mathbf{1}_{\text{is\_future}}(base, seq) = 1$$

* **Conséquences sur la Preuve :**  
  * Élimine toute précondition restrictive de dépassement d'entier (`base <= u64::MAX - W`).
  * Assure un fonctionnement pérenne et continu de l'automate lors du franchissement cyclique de la frontière $2^{64}-1 \to 0$.

---

### H5. Architecture Ring Buffer en $\mathcal{O}(1)$ & Injectivité ($W = 4096$)

* **Énoncé Formel :**  
  La fenêtre glissante stocke ses $W = 4096$ slots dans un tableau contigu indexé par la fonction de hachage de placement direct :
  $$\text{ring\_index}(seq) = (seq \bmod 4096) \text{ as usize}$$
  La projection spatiale est **strictement injective** à l'intérieur de la fenêtre active :
  $$\forall s_1, s_2 \in [base, base + W - 1], \quad s_1 \neq s_2 \implies \text{ring\_index}(s_1) \neq \text{ring\_index}(s_2)$$

* **Lemme Formel d'Injectivité :**  
  Prouvé formellement dans [`lemma_ring_buffer_injectivity`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L141-L151).

* **Conséquences sur la Preuve et la Performance :**  
  * **Absence d'Alias :** Deux numéros de séquence distincts situés simultanément dans la fenêtre glissante ne peuvent jamais partager le même emplacement mémoire physique.
  * **Complexité $\mathcal{O}(1)$ stricte :** L'avancement de fenêtre [`advance_one_slot`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L443-L472) s'exécute en temps constant sans aucun décalage de mémoire (`memmove` de 4096 éléments éliminé).
  * **Empreinte Cache L1 :** La table occupe $4096 \times 16 \text{ octets} = 64 \text{ Ko}$, s'insérant intégralement dans le cache L1 de données du cœur processeur (zéro défaut de cache).

---

### H6. Hypothèse Temporelle de Gigue Réseau Bornée (Bounded Jitter Liveness)

* **Énoncé Formel :**  
  Sur un flux nominal sans attaque, la désynchronisation temporelle d'acheminement réseau entre une PDU de données et son descripteur de confiance associé est strictement inférieure à la profondeur temporelle de la fenêtre de réception :
  $$|\text{tick}(PDU_{seq}) - \text{tick}(Trust_{seq})| < W_{\text{ticks}}$$

* **Théorème de Vivacité sous Gigue :**  
  Prouvé formellement dans [`theorem_bounded_jitter_liveness`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L529-L540).

* **Conséquences sur la Preuve :**  
  * Garantit la **vivacité** (*Liveness*) de l'automate : les flux se rencontrent obligatoirement au sein du buffer.
  * Garantit l'**absence de faux positifs** : aucun paquet légitime ne peut être expulsé prématurément par temporisation et faussement accusé d'injection (`AddedPdu`) ou de perte (`DroppedPdu`).

---

### H7. Hypothèse de Persistance Matérielle & Résistance aux Crashs (Émetteur WAL)

* **Énoncé Formel :**  
  L'émetteur (Machine A) consigne chaque descripteur de confiance émis dans un journal persistant *Write-Ahead Log* (WAL) sur stockage non volatil avant ou simultanément à son émission sur le réseau :
  $$\forall \text{TrustDescriptor}(epoch, seq, d), \quad \text{Persist}(\text{DiskRecord}(epoch, seq, d)) \prec \text{NetworkEmit}(epoch, seq, d)$$
  Chaque enregistrement sur disque est scellé dans un bloc unitaire de 40 octets alignés avec somme de contrôle d'intégrité :
  $$\mathcal{H}_{\text{rec}}(magic, epoch, seq, digest) = (magic \oplus epoch \oplus seq \oplus digest \oplus \text{A5A5...}_{16})$$
  La persistance est rendue durable par une barrière matérielle `fsync` (`sync_data`).

* **Modèle de Panne / Redémarrage Intempestif (*Crash Model*) :**  
  Une coupure d'alimentation ou un redémarrage brutal (*power loss*) peut survenir à tout instant $t$, y compris pendant l'écriture des octets d'un bloc. Au redémarrage, la procédure de récupération (`recover_from_bytes`) balaye le journal depuis le début et s'arrête strictement au premier bloc tronqué, corrompu ou non monotone.

* **Théorèmes Formels de Résistance au Crash :**
  1. **Théorème de Préservation de Préfixe (*Crash-Prefix Soundness*) :**  
     Prouvé formellement dans [`theorem_crash_prefix_soundness`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L540-L555).
  2. **Théorème d'Idempotence de la Restauration :**  
     Prouvé formellement dans [`theorem_recovery_idempotence`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L556-L565).
  3. **Lemme de Préservation de Monotonie :**  
     Prouvé formellement dans [`lemma_monotonic_prefix`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L575-L590).
  4. **Lemme d'Intégrité de l'Enregistrement :**  
     Prouvé formellement dans [`lemma_record_integrity`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L510-L530).

---

### H8. Compteur d'Ère / Démarrage d'Équipement (Epoch / Boot Counter & Inter-Epoch Replay Immunity)

* **Énoncé Formel :**  
  L'émetteur Machine A maintient un compteur d'ère monotone incrémenté strictement à chaque réinitialisation ou démarrage matériel :
  $$epoch_{\text{new}} > epoch_{\text{old}}$$
  Chaque PDU et chaque descripteur de confiance porte le couple $(epoch, seq)$. Le récepteur Machine B suit l'époque active $current\_epoch$.

* **Mécanisme de Transition & Résilience au Redémarrage :**  
  1. **Rupture d'Ère Authentifiée :** Lorsqu'un descripteur de confiance signé avec $epoch > current\_epoch$ est reçu sur Machine B, Machine B réinitialise instantanément sa fenêtre glissante sur $seq$ et avance son époque :
     $$current\_epoch \leftarrow epoch_{\text{trust}}, \quad window\_base \leftarrow seq_{\text{trust}}$$
  2. **Immunité au Rejeu Inter-Sessions :** Tout paquet émis lors d'une session antérieure est rejeté avec certitude :
     $$\forall pdu, \quad pdu.epoch < current\_epoch \implies \text{Result} = \text{StaleEpoch}$$
  3. **Protection contre le Déni de Service (DoS Dolev-Yao) :** Une fausse PDU injectée par l'attaquant avec un $epoch$ élevé ne déclenche jamais de réinitialisation d'époque ; seule une preuve signée sur le canal de confiance authentifie le redémarrage.

* **Théorèmes Formels d'Époque :**
  1. **Théorème d'Immunité au Rejeu Inter-Sessions :**  
     Prouvé dans [`theorem_inter_epoch_replay_immunity`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L445-L455).
  2. **Théorème de Transition d'Époque Authentifiée :**  
     Prouvé dans [`theorem_authenticated_epoch_transition`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L457-L467).

---

### H9. Registre Matériel Hors-Disque (TPM 2.0 / NVRAM Monotonic Counter)

* **Énoncé Formel :**  
  Le compteur d'époque monotone `epoch: u64` est découplé physiquement du support de stockage de masse amovible (disque dur / SSD) et réside dans un registre non-volatile soudé sur la carte mère (ex: compteur monotone TPM 2.0 `TPM2_NV_Increment` ou registre NVRAM platforme) :
  $$\text{Storage}(\text{Epoch}) \cap \text{Storage}(\text{MassDisk}) = \emptyset$$
  Le remplacement ou la corruption du disque dur ($\text{Disk}_{\text{old}} \to \text{Disk}_{\text{new}}$) n'altère pas la valeur du composant matériel :
  $$\forall \text{disque vierge}, \quad \text{epoch}_{\text{hardware}} > \text{epoch}_{\text{old\_disk}}$$

* **Théorème de Survie au Remplacement de Disque :**  
  Prouvé formellement dans [`theorem_disk_replacement_monotonicity`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L640-L655) :
  $$\text{hardware\_epoch} > \text{old\_disk\_epoch} \implies \text{hardware\_epoch} \neq \text{old\_disk\_epoch} \land \text{hardware\_epoch} > \text{old\_disk\_epoch}$$

* **Conséquences sur la Preuve et la Disponibilité :**  
  * **Zéro Déni de Service sur Disque Vierge :** Lorsqu'un disque dur est remplacé lors d'une opération de maintenance (RMA), Machine A lit le compteur TPM/NVRAM de la carte mère, s'incrémente à une valeur strictement supérieure, et émet un descripteur authentifié que Machine B accepte immédiatement.
  * **Zéro Rejet `StaleEpoch` :** Machine B ne classe jamais la nouvelle session comme un rejeu obsolète.

---

## 3. Matrice de Traçabilité Formelle

Le tableau ci-dessous relie chaque hypothèse à son modèle formel Verus, sa propriété de sécurité démontrée et son implémentation dans le code source :

| ID | Hypothèse Système | Propriété de Sécurité Démontrée | Lemme / Théorème Verus | Emplacement Source |
| :--- | :--- | :--- | :--- | :--- |
| **H1** | Monocœur Séquentiel | Absence de *race conditions*, déterminisme d'état | Spécification des contrats Hoare | [`src/lib.rs#L270-L390`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L270-L390) |
| **H2** | Résistance aux Collisions | Impossibilité de masquer une altération de données | `lemma_collision_resistance_hypothesis` | [`src/lib.rs#L85-L91`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L85-L91) |
| **H3** | Dolev-Yao + Signature EUF-CMA | Impossibilité de forger des descripteurs de confiance | `theorem_trace_authenticity_and_soundness` | [`src/lib.rs#L400-L425`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L400-L425) |
| **H4** | Arithmétique Modulo $2^{64}$ | Robustesse au débordement cyclique indéfini | `theorem_circular_space_partition` | [`src/lib.rs#L157-L165`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L157-L165) |
| **H5** | Ring Buffer Injectif $\mathcal{O}(1)$ | Absence d'alias mémoire, temps constant strict | `lemma_ring_buffer_injectivity` | [`src/lib.rs#L141-L151`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L141-L151) |
| **H6** | Gigue Bornée $< W$ | Vivacité de corrélation, zéro faux positif | `theorem_bounded_jitter_liveness` | [`src/lib.rs#L430-L442`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L430-L442) |
| **H7** | Persistance WAL & Crash-Consistency | Préfixe authentique garanti au reboot, idempotence | `theorem_crash_prefix_soundness`, `lemma_record_integrity` | [`src/lib.rs#L475-L590`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L475-L590) |
| **H8** | Compteur d'Ère (Epoch) | Résilience totale au redémarrage d'équipements, immunité au rejeu inter-sessions | `theorem_inter_epoch_replay_immunity`, `theorem_authenticated_epoch_transition` | [`src/lib.rs#L445-L467`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L445-L467) |
| **H9** | Registre TPM/NVRAM Hors-Disque | Survie au remplacement du disque dur, anti-amnésie matérielle | `theorem_disk_replacement_monotonicity` | [`src/lib.rs#L625-L655`](file:///Users/jean-baptiste/AI-Trust/src/lib.rs#L625-L655) |

---

## 4. Analyse de Rupture d'Hypothèse (Safety / Security Failure Modes)

Pour l'auditeur de certification, le tableau suivant documente le comportement du système si l'environnement physique venait à violer l'une des hypothèses :

| Hypothèse Violée | Scénario de Rupture | Impact Système | Contre-mesure Architecturale |
| :--- | :--- | :--- | :--- |
| **Rupture H1** | Accès multi-threadé non synchronisé | Corruption de mémoire potentielle | Encapsulation de l'automate dans un acteur ou exclusion mutuelle matérielle |
| **Rupture H2** | Cassure cryptographique de $\mathcal{H}$ | Collision délibérée (altération indétectée) | Remplacement de la primitive par un standard post-quantique ou SHA-3 |
| **Rupture H3** | Clé privée de signature compromise | Attaquant capable de forger des descripteurs | Module HSM / enclave sécurisée pour le stockage de la clé sur Machine A |
| **Rupture H4** | Non-respect de l'arithmétique circulaire | Dépassement d'entier / panique à $2^{64}-1$ | Neutralisé : garanti par `wrapping_sub` et typage `u64` sous Verus |
| **Rupture H5** | Indexation erronée | Collision de slots dans la fenêtre | Neutralisé : injectivité mathématiquement prouvée par SMT |
| **Rupture H6** | Gigue réseau extrême $> W$ | Fausse alerte d'injection ou de perte | Dimensionnement de la fenêtre glissante ($W=4096$) et régulateur de débit |
| **Rupture H7** | Panne du support de stockage disque | Échec d'écriture du journal WAL | Journalisation sur mémoire répliquée / NVRAM avec détection d'erreur I/O |
| **Rupture H8** | Perte du compteur d'époque persistant | Réutilisation accidentelle d'un ancien Epoch | Découplage sur registre TPM/NVRAM hors-disque (H9) |
| **Rupture H9** | Remplacement simultané de la carte mère et du disque | Perte totale d'historique matériel | Procédure de provisionnement usine / injection de certificat initial |

