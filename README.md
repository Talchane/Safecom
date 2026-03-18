# 🔒 Safecom

**Chat sécurisé post-quantique en ligne de commande.**

Safecom est une application de messagerie en temps réel qui protège vos communications grâce à une cryptographie hybride résistante aux ordinateurs quantiques.

---

## 🛡️ Technologies cryptographiques

| Fonction | Algorithme | Bibliothèque |
|---|---|---|
| Signature (identité) | **ML-DSA-65** (Dilithium3) | liboqs |
| Échange de clés | **ML-KEM-768** (Kyber768) | liboqs |
| Chiffrement symétrique | **XChaCha20-Poly1305** (AEAD) | libsodium |
| Entropie | `randombytes_buf()` (CSPRNG) | libsodium |

### Garanties

- **Perfect Forward Secrecy (PFS)** — Clés éphémères par session, compromission future impossible.
- **Effacement mémoire** — Toute clé sensible est nettoyée de la RAM (`sodium_memzero`).
- **Authentification** — Chaque message est signé (ML-DSA) et vérifié.
- **Intégrité** — Toute altération est détectée (AEAD + signature).
- **Anti MITM** — Empreinte de session commune à vérifier manuellement.

---

## 📁 Structure du projet

```
Safecom/
├── safecom.cpp          # Application principale (chat CLI)
├── CryptoEngine.hpp/cpp # Moteur cryptographique hybride
├── Network.hpp/cpp      # Couche réseau TCP (framing longueur-préfixé)
├── main_test.cpp        # Tests end-to-end du CryptoEngine
├── compiler             # Commandes de compilation
└── liboqs/              # Bibliothèque liboqs (post-quantique)
```

---

## ⚙️ Prérequis

- **Compilateur** : g++ avec support C++17
- **libsodium** : `sudo apt install libsodium-dev`
- **liboqs** : inclus dans le projet ou installé séparément
- **OpenSSL** (`libcrypto`)

---

## 🔨 Compilation

```bash
# Application principale
g++ -std=c++17 -O2 safecom.cpp CryptoEngine.cpp Network.cpp -o safecom -lsodium -loqs -lcrypto -w

# Tests
g++ -std=c++17 -O2 main_test.cpp CryptoEngine.cpp -o test -lsodium -loqs -lcrypto -w
```

---

## 🚀 Utilisation

### Mode interactif (menu)

```bash
./safecom
```

### Mode serveur

```bash
./safecom --listen 4444
```

### Mode client

```bash
./safecom --connect 127.0.0.1 4444
```

### Commandes en session

| Commande | Action |
|---|---|
| `/quit` | Quitter proprement |
| `exit` | Quitter proprement |

---

## 🔬 Tests

```bash
./test
```

Les tests vérifient :
- ✅ Round-trip complet (chiffrement → sérialisation → désérialisation → déchiffrement)
- ✅ Rejet de signature invalide (usurpation d'identité)
- ✅ Détection d'altération (bit-flip sur le ciphertext)
- ✅ Effacement de la clé KEM après décapsulation (PFS)

---

## 📡 Protocole

```
1. Connexion TCP
2. Handshake : échange des clés publiques ML-DSA + ML-KEM
3. Vérification manuelle de l'empreinte de session (anti-MITM)
4. Chat chiffré : ML-KEM encaps → XChaCha20-Poly1305 → ML-DSA sign
```

---

## 👤 Auteur

**Benoît Ferrandini**

---

## 📜 Licence

Projet personnel — Tous droits réservés.
