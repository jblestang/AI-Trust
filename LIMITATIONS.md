# AI-Trust : Limitations Architecturales et Hypothèses de Déploiement

Ce document consigne de manière transparente et rigoureuse les limitations de l'état actuel de la bibliothèque formellement vérifiée `ai_trust`, conformément aux analyses critiques de robustesse et de sécurité.

---

## 1. Périmètre de la TCB Externe (Trusted Computing Base non prouvée)

### Description
La preuve formelle par SMT (Verus / Z3) garantit la correction mathématique intrinsèque de la logique métier Rust :
- Absence d'accès hors-limites (*out-of-bounds*).
- Absence de panique et de débordement arithmétique (*overflow*).
- Préservation de la cohérence et de l'intégrité de la fenêtre glissante circulaire $O(1)$.
- Invariance de préfixe valide du journal WAL et monotonicité de l'Epoch Counter.

### Limite opérationnelle
La garantie formelle s'arrête strictement aux frontières des appels système de l'OS (`std::fs::File`, `std::net::UdpSocket`). La chaîne de confiance physique repose sur des composants non formellement prouvés :
1. **Noyau du système d'exploitation** : Ordonnanceur, gestionnaire de mémoire virtuelle (VMM) et pile réseau de l'OS (Linux / macOS / RTOS).
2. **Pilotes matériels (NIC Drivers)** : Le firmware de la carte réseau (NIC) et ses buffers DMA peuvent réordonner, agréger (LRO/GRO) ou altérer des trames hors du contrôle du runtime Rust.
3. **Contrôleurs et micro-logiciels SSD / NVMe** : L'appel `sync_data()` (`fsync` / `fdatasync`) transmet une commande de flush au contrôleur matériel. Si le micrologiciel (firmware) du contrôleur SSD ou la puce mémoire ment sur la synchronisation physique (ex. cache volatile non secouru par condensateur de rétention d'énergie / PLP - *Power Loss Protection*), un crash physique simultané à une panne d'alimentation peut corrompre des secteurs sous-jacents.

### Recommandations pour la production
- Déploiement sur des systèmes d'exploitation certifiés ou durcis (SELinux, micro-noyaux de type seL4 pour les fonctions ultra-critiques).
- Utilisation de supports de stockage professionnels dotés de circuits de protection contre les coupures d'alimentation (Hardware PLP / Enterprise NVMe SSD).

---

## 2. Modélisation Cryptographique Abstraite (Digest XOR vs Primitives Réelles)

### Description
Dans le cadre de la vérification formelle actuelle (Hypothèse H2 dans `HYPOTHESES.md`), la fonction d'intégrité est modélisée par une réduction arithmétique abstraite :
$$\text{compute\_digest}(v) = v \oplus 0x5555\_AAAA\_5555\_AAAA$$

### Limite de sécurité cryptographique
Un tel hachage / condensat jouit de propriétés arithmétiques idéales pour la vérification automatique par solveur SMT (linéarité, coût de preuve instantané), mais :
1. **Linéarité et malléabilité** : Un attaquant actif capable de modifier le champ de données $v$ sans altérer le descripteur de confiance pourrait en théorie concevoir des collisions si la clé secrète était connue ou triviale.
2. **Absence de résistance aux collisions cryptographiques** : Ce modèle n'offre pas la sécurité d'une fonction de hachage cryptographique résistante aux pré-images et aux collisions ($2^{128}$ ou $2^{256}$).

### Recommandations pour la production
- Dans un déploiement réel opérationnel, remplacer l'implémentation de `compute_digest` et la signature du descripteur par des primitives cryptographiques conformes aux référentiels ANSSI / NIST :
  - **HMAC-SHA256**, **BLAKE3-keyed** ou **AES-GMAC** pour l'authentification des descripteurs de confiance.
  - **Ed25519** ou **ECDSA-P256** pour la signature asymétrique inter-équipements si le canal d'administration est partagé.
- Conserver la signature formelle de l'automate : la logique de la fenêtre glissante, de corrélation temporelle et d'éviction demeure strictement identique et indépendante du choix de la primitive de hachage.

---

## 3. Usure Matérielle du Registre Monotone (NVRAM / TPM Wear-Out)

### Description
L'architecture de résilience au remplacement de disque repose sur un compteur d'époques persistant matériellement hors du disque dur (NVRAM, registre TPM NV, ou EEPROM de la carte mère) :
- À chaque démarrage ou réinitialisation majeure, la Machine A effectue un `fetch_and_increment()` sur ce composant.

### Limite de durabilité matérielle
1. **Cycles d'écriture limités** : Les mémoires non-volatiles intégrées (EEPROM, mémoires flash de puce TPM 2.0) possèdent un nombre fini de cycles d'effacement/écriture (généralement entre $100\,000$ et $1\,000\,000$ de cycles par cellule).
2. **Scénario d'attaque par boucle de redémarrage (*Boot Looping / Flapping*)** :
   - Si un attaquant provoque des réinitialisations matérielles en boucle à haute fréquence (ex. coupure de relais toutes les 500 ms), le compteur monotone pourrait théoriquement atteindre sa limite d'endurance physique en quelques mois de sollicitation continue.
   - De surcroît, le TPM 2.0 applique un mécanisme de limitation de débit interne (*rate limiting / anti-hammering*) qui peut introduire des latences de plusieurs secondes si les écritures NV sont trop fréquentes.

### Recommandations pour la production
- **Mécanisme d'allocation par plages (Epoch Reservation Range)** :
  - Au démarrage, incrémenter le registre NVRAM d'un bloc de taille $K$ (ex. $K = 10\,000$).
  - La session courante utilise l'intervalle $[E, E + K - 1]$, écrivant les sous-époques sur le journal local rapide (WAL).
  - L'accès physique au TPM n'a lieu qu'une seule fois par cycle de réservation, divisant le taux d'usure de la cellule par un facteur $10^4$.
- **Circuit anti-flapping matériel** :
  - Temporisation minimale au redémarrage physique (délai de grâce de quelques secondes géré par le superviseur d'alimentation).

