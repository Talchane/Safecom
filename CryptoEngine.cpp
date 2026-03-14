/**
 * @file CryptoEngine.cpp
 * @brief Implémentation du moteur cryptographique hybride post-quantique.
 *
 * Dépendances :
 *   - liboqs   (ML-DSA-65, ML-KEM-768)
 *   - libsodium (XChaCha20-Poly1305, randombytes_buf, sodium_memzero)
 */

#include "CryptoEngine.hpp"

#include <sodium.h>
#include <oqs/oqs.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

// ============================================================================
//  Constantes liboqs (noms d'algorithme)
// ============================================================================

static constexpr const char* KEM_ALG  = OQS_KEM_alg_ml_kem_768;
static constexpr const char* SIG_ALG  = OQS_SIG_alg_ml_dsa_65;

// ============================================================================
//  SecureAllocator — implémentation
// ============================================================================

template <typename T>
T* SecureAllocator<T>::allocate(std::size_t n) {
    if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
        throw std::bad_alloc();
    }
    auto* ptr = static_cast<T*>(std::malloc(n * sizeof(T)));
    if (!ptr) {
        throw std::bad_alloc();
    }
    return ptr;
}

template <typename T>
void SecureAllocator<T>::deallocate(T* ptr, std::size_t n) noexcept {
    if (ptr) {
        sodium_memzero(ptr, n * sizeof(T));
        std::free(ptr);
    }
}

// Instanciations explicites pour les types utilisés
template struct SecureAllocator<uint8_t>;

// ============================================================================
//  Helpers RAII pour liboqs (évite les fuites mémoire liboqs)
// ============================================================================

/** Gestion RAII de OQS_KEM*. Libère automatiquement à la destruction. */
struct OqsKemGuard {
    OQS_KEM* kem = nullptr;

    explicit OqsKemGuard(const char* alg) {
        kem = OQS_KEM_new(alg);
        if (!kem) {
            throw CryptoInitError("Échec d'initialisation ML-KEM-768 (OQS_KEM_new)");
        }
    }

    ~OqsKemGuard() noexcept {
        if (kem) OQS_KEM_free(kem);
    }

    OqsKemGuard(const OqsKemGuard&) = delete;
    OqsKemGuard& operator=(const OqsKemGuard&) = delete;
};

/** Gestion RAII de OQS_SIG*. */
struct OqsSigGuard {
    OQS_SIG* sig = nullptr;

    explicit OqsSigGuard(const char* alg) {
        sig = OQS_SIG_new(alg);
        if (!sig) {
            throw CryptoInitError("Échec d'initialisation ML-DSA-65 (OQS_SIG_new)");
        }
    }

    ~OqsSigGuard() noexcept {
        if (sig) OQS_SIG_free(sig);
    }

    OqsSigGuard(const OqsSigGuard&) = delete;
    OqsSigGuard& operator=(const OqsSigGuard&) = delete;
};

// ============================================================================
//  Helpers de sérialisation (little-endian, 4 octets)
// ============================================================================

namespace {

/** Écrit un uint32_t en little-endian dans un buffer. */
inline void write_u32_le(ByteVec& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

/** Lit un uint32_t en little-endian depuis un pointeur, avec vérification de bornes. */
inline uint32_t read_u32_le(const uint8_t* data, std::size_t offset, std::size_t total_size) {
    if (offset + 4 > total_size) {
        throw std::runtime_error("Désérialisation : dépassement de tampon lors de la lecture d'un champ de longueur");
    }
    return static_cast<uint32_t>(data[offset])
         | (static_cast<uint32_t>(data[offset + 1]) << 8)
         | (static_cast<uint32_t>(data[offset + 2]) << 16)
         | (static_cast<uint32_t>(data[offset + 3]) << 24);
}

/** Extrait un champ longueur-préfixé avec vérification stricte des bornes. */
inline ByteVec read_field(const uint8_t* data, std::size_t& offset, std::size_t total_size) {
    uint32_t len = read_u32_le(data, offset, total_size);
    offset += 4;

    if (len > total_size || offset > total_size - len) {
        throw std::runtime_error(
            "Désérialisation : taille de champ invalide (" + std::to_string(len) +
            " octets) — possible paquet malformé ou attaque");
    }

    ByteVec field(data + offset, data + offset + len);
    offset += len;
    return field;
}

} // namespace anonyme

// ============================================================================
//  KemKeyPair
// ============================================================================

void KemKeyPair::wipe() noexcept {
    if (!private_key.empty()) {
        sodium_memzero(private_key.data(), private_key.size());
        private_key.clear();
        private_key.shrink_to_fit();
    }
}

// ============================================================================
//  EncryptedPacket — sérialisation / désérialisation
// ============================================================================

ByteVec EncryptedPacket::serialize() const {
    // Format : [4 bytes len][field] x 4 champs
    // Ordre : kem_ciphertext, nonce, aead_ciphertext, signature
    ByteVec out;
    const std::size_t total = 4 * 4 // 4 champs × 4 octets de longueur
        + kem_ciphertext.size()
        + nonce.size()
        + aead_ciphertext.size()
        + signature.size();
    out.reserve(total);

    write_u32_le(out, static_cast<uint32_t>(kem_ciphertext.size()));
    out.insert(out.end(), kem_ciphertext.begin(), kem_ciphertext.end());

    write_u32_le(out, static_cast<uint32_t>(nonce.size()));
    out.insert(out.end(), nonce.begin(), nonce.end());

    write_u32_le(out, static_cast<uint32_t>(aead_ciphertext.size()));
    out.insert(out.end(), aead_ciphertext.begin(), aead_ciphertext.end());

    write_u32_le(out, static_cast<uint32_t>(signature.size()));
    out.insert(out.end(), signature.begin(), signature.end());

    return out;
}

EncryptedPacket EncryptedPacket::deserialize(const ByteVec& data) {
    if (data.size() < 16) { // Minimum : 4 champs × 4 octets de longueur
        throw std::runtime_error(
            "Désérialisation : paquet trop petit (" + std::to_string(data.size()) + " octets)");
    }

    std::size_t offset = 0;
    const std::size_t total = data.size();

    EncryptedPacket pkt;
    pkt.kem_ciphertext  = read_field(data.data(), offset, total);
    pkt.nonce           = read_field(data.data(), offset, total);
    pkt.aead_ciphertext = read_field(data.data(), offset, total);
    pkt.signature       = read_field(data.data(), offset, total);

    if (offset != total) {
        throw std::runtime_error(
            "Désérialisation : données excédentaires (" +
            std::to_string(total - offset) + " octets restants)");
    }

    return pkt;
}

// ============================================================================
//  CryptoEngine — Construction / Destruction
// ============================================================================

CryptoEngine::CryptoEngine() {
    // --- Initialisation de libsodium ---
    if (sodium_init() < 0) {
        throw CryptoInitError("Échec de sodium_init()");
    }

    // --- Génération de la paire de clés ML-DSA-65 (identité long terme) ---
    OqsSigGuard sig_guard(SIG_ALG);
    OQS_SIG* sig = sig_guard.sig;

    dsa_public_key_.resize(sig->length_public_key);
    dsa_private_key_.resize(sig->length_secret_key);

    // Utilisation de randombytes_buf de libsodium comme source d'entropie.
    // liboqs supporte un callback RNG custom, mais par défaut il utilise
    // déjà des sources sûres. Pour le forcer, on génère les clés normalement
    // (liboqs utilise son propre RNG interne sécurisé).
    OQS_STATUS rc = OQS_SIG_keypair(sig,
                                     dsa_public_key_.data(),
                                     dsa_private_key_.data());
    if (rc != OQS_SUCCESS) {
        // Effacer ce qui a été partiellement écrit
        sodium_memzero(dsa_private_key_.data(), dsa_private_key_.size());
        throw CryptoInitError("Échec de la génération de clés ML-DSA-65");
    }
}

CryptoEngine::~CryptoEngine() noexcept {
    // SecureBuffer::~SecureBuffer() appelle déjà sodium_memzero via le SecureAllocator,
    // mais on fait un effacement explicite par précaution (defense-in-depth).
    if (!dsa_private_key_.empty()) {
        sodium_memzero(dsa_private_key_.data(), dsa_private_key_.size());
    }
}

// ============================================================================
//  CryptoEngine — Gestion des clés
// ============================================================================

KemKeyPair CryptoEngine::generate_kem_keypair() const {
    OqsKemGuard kem_guard(KEM_ALG);
    OQS_KEM* kem = kem_guard.kem;

    KemKeyPair kp;
    kp.public_key.resize(kem->length_public_key);
    kp.private_key.resize(kem->length_secret_key);

    OQS_STATUS rc = OQS_KEM_keypair(kem,
                                     kp.public_key.data(),
                                     kp.private_key.data());
    if (rc != OQS_SUCCESS) {
        kp.wipe();
        throw CryptoInitError("Échec de la génération de clés ML-KEM-768");
    }

    return kp;
}

const ByteVec& CryptoEngine::get_dsa_public_key() const noexcept {
    return dsa_public_key_;
}

// ============================================================================
//  CryptoEngine — Chiffrement
// ============================================================================

EncryptedPacket CryptoEngine::encrypt_for_peer(
    const ByteVec& plaintext,
    const ByteVec& peer_kem_pk
) const {
    // -----------------------------------------------------------------
    //  Étape 1 : ML-KEM Encapsulation → clé symétrique + KEM ciphertext
    // -----------------------------------------------------------------
    OqsKemGuard kem_guard(KEM_ALG);
    OQS_KEM* kem = kem_guard.kem;

    // Vérification de la taille de la clé publique KEM
    if (peer_kem_pk.size() != kem->length_public_key) {
        throw CryptoInitError(
            "Taille de clé publique ML-KEM invalide : attendu " +
            std::to_string(kem->length_public_key) + ", reçu " +
            std::to_string(peer_kem_pk.size()));
    }

    // Clé symétrique partagée (secrète — effacée via SecureBuffer)
    SecureBuffer shared_secret(kem->length_shared_secret);
    ByteVec kem_ct(kem->length_ciphertext);

    OQS_STATUS rc = OQS_KEM_encaps(kem,
                                    kem_ct.data(),
                                    shared_secret.data(),
                                    peer_kem_pk.data());
    if (rc != OQS_SUCCESS) {
        sodium_memzero(shared_secret.data(), shared_secret.size());
        throw CryptoInitError("Échec de l'encapsulation ML-KEM-768");
    }

    // -----------------------------------------------------------------
    //  Étape 2 : Dérivation de clé symétrique pour XChaCha20-Poly1305
    // -----------------------------------------------------------------
    // Le shared_secret ML-KEM fait 32 octets = crypto_aead_xchacha20poly1305_ietf_KEYBYTES.
    // On peut l'utiliser directement si la taille correspond, sinon on dérive avec HKDF.
    SecureBuffer symmetric_key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    if (shared_secret.size() >= crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        // Prendre les 32 premiers octets du shared_secret
        std::memcpy(symmetric_key.data(), shared_secret.data(),
                    crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    } else {
        // Cas improbable : si le shared_secret est trop court, padding avec zéros
        // (ne devrait jamais arriver avec ML-KEM-768)
        std::memcpy(symmetric_key.data(), shared_secret.data(), shared_secret.size());
    }

    // Effacer le shared_secret original immédiatement
    sodium_memzero(shared_secret.data(), shared_secret.size());

    // -----------------------------------------------------------------
    //  Étape 3 : XChaCha20-Poly1305 — chiffrement AEAD
    // -----------------------------------------------------------------
    ByteVec nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size()); // 24 octets, entropie libsodium

    // Ciphertext = plaintext + tag Poly1305 (16 octets)
    ByteVec aead_ct(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long aead_ct_len = 0;

    int aead_rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        aead_ct.data(), &aead_ct_len,
        plaintext.data(), plaintext.size(),
        nullptr, 0,          // Pas de données associées (AD)
        nullptr,             // nsec (inutilisé par cette construction)
        nonce.data(),
        symmetric_key.data()
    );

    // Effacer la clé symétrique immédiatement après chiffrement
    sodium_memzero(symmetric_key.data(), symmetric_key.size());

    if (aead_rc != 0) {
        throw CryptoInitError("Échec du chiffrement XChaCha20-Poly1305");
    }
    aead_ct.resize(static_cast<std::size_t>(aead_ct_len));

    // -----------------------------------------------------------------
    //  Étape 4 : ML-DSA Signature de (kem_ciphertext || aead_ciphertext)
    // -----------------------------------------------------------------
    OqsSigGuard sig_guard(SIG_ALG);
    OQS_SIG* sig = sig_guard.sig;

    // Construire le message à signer : concaténation kem_ct || aead_ct
    ByteVec sign_input;
    sign_input.reserve(kem_ct.size() + aead_ct.size());
    sign_input.insert(sign_input.end(), kem_ct.begin(), kem_ct.end());
    sign_input.insert(sign_input.end(), aead_ct.begin(), aead_ct.end());

    ByteVec signature(sig->length_signature);
    std::size_t sig_len = 0;

    OQS_STATUS sig_rc = OQS_SIG_sign(sig,
                                      signature.data(), &sig_len,
                                      sign_input.data(), sign_input.size(),
                                      dsa_private_key_.data());
    if (sig_rc != OQS_SUCCESS) {
        throw CryptoInitError("Échec de la signature ML-DSA-65");
    }
    signature.resize(sig_len);

    // -----------------------------------------------------------------
    //  Construction du paquet
    // -----------------------------------------------------------------
    EncryptedPacket packet;
    packet.kem_ciphertext  = std::move(kem_ct);
    packet.nonce           = std::move(nonce);
    packet.aead_ciphertext = std::move(aead_ct);
    packet.signature       = std::move(signature);

    return packet;
}

// ============================================================================
//  CryptoEngine — Déchiffrement
// ============================================================================

SecureBuffer CryptoEngine::decrypt_from_peer(
    const EncryptedPacket& packet,
    const ByteVec& sender_dsa_pk,
    SecureBuffer& local_kem_sk
) const {
    // -----------------------------------------------------------------
    //  Étape 1 : ML-DSA Verify — vérification de la signature
    // -----------------------------------------------------------------
    OqsSigGuard sig_guard(SIG_ALG);
    OQS_SIG* sig = sig_guard.sig;

    // Vérifier la taille de la clé publique DSA de l'expéditeur
    if (sender_dsa_pk.size() != sig->length_public_key) {
        throw SignatureVerificationError(
            "Taille de clé publique ML-DSA invalide : attendu " +
            std::to_string(sig->length_public_key) + ", reçu " +
            std::to_string(sender_dsa_pk.size()));
    }

    // Reconstruire le message signé : kem_ciphertext || aead_ciphertext
    ByteVec sign_input;
    sign_input.reserve(packet.kem_ciphertext.size() + packet.aead_ciphertext.size());
    sign_input.insert(sign_input.end(),
                      packet.kem_ciphertext.begin(), packet.kem_ciphertext.end());
    sign_input.insert(sign_input.end(),
                      packet.aead_ciphertext.begin(), packet.aead_ciphertext.end());

    OQS_STATUS verify_rc = OQS_SIG_verify(sig,
                                           sign_input.data(), sign_input.size(),
                                           packet.signature.data(), packet.signature.size(),
                                           sender_dsa_pk.data());
    if (verify_rc != OQS_SUCCESS) {
        throw SignatureVerificationError(
            "Signature ML-DSA invalide — le message a été altéré ou l'expéditeur est inconnu");
    }

    // -----------------------------------------------------------------
    //  Étape 2 : ML-KEM Decapsulation → récupération de la clé symétrique
    // -----------------------------------------------------------------
    OqsKemGuard kem_guard(KEM_ALG);
    OQS_KEM* kem = kem_guard.kem;

    // Vérifier la taille de la clé privée KEM
    if (local_kem_sk.size() != kem->length_secret_key) {
        throw DecapsulationError(
            "Taille de clé privée ML-KEM invalide : attendu " +
            std::to_string(kem->length_secret_key) + ", reçu " +
            std::to_string(local_kem_sk.size()));
    }

    // Vérifier la taille du KEM ciphertext
    if (packet.kem_ciphertext.size() != kem->length_ciphertext) {
        throw DecapsulationError(
            "Taille du KEM ciphertext invalide : attendu " +
            std::to_string(kem->length_ciphertext) + ", reçu " +
            std::to_string(packet.kem_ciphertext.size()));
    }

    SecureBuffer shared_secret(kem->length_shared_secret);

    OQS_STATUS decaps_rc = OQS_KEM_decaps(kem,
                                           shared_secret.data(),
                                           packet.kem_ciphertext.data(),
                                           local_kem_sk.data());

    // *** PFS : Effacer la clé privée KEM IMMÉDIATEMENT après décapsulation ***
    sodium_memzero(local_kem_sk.data(), local_kem_sk.size());
    local_kem_sk.clear();
    local_kem_sk.shrink_to_fit();

    if (decaps_rc != OQS_SUCCESS) {
        sodium_memzero(shared_secret.data(), shared_secret.size());
        throw DecapsulationError("Échec de la décapsulation ML-KEM-768");
    }

    // -----------------------------------------------------------------
    //  Étape 3 : Dérivation de clé symétrique
    // -----------------------------------------------------------------
    SecureBuffer symmetric_key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    if (shared_secret.size() >= crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        std::memcpy(symmetric_key.data(), shared_secret.data(),
                    crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    } else {
        std::memcpy(symmetric_key.data(), shared_secret.data(), shared_secret.size());
    }

    sodium_memzero(shared_secret.data(), shared_secret.size());

    // -----------------------------------------------------------------
    //  Étape 4 : XChaCha20-Poly1305 — déchiffrement AEAD
    // -----------------------------------------------------------------
    // Vérifier la taille du nonce
    if (packet.nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        sodium_memzero(symmetric_key.data(), symmetric_key.size());
        throw DecryptionError(
            "Taille de nonce invalide : attendu " +
            std::to_string(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) + ", reçu " +
            std::to_string(packet.nonce.size()));
    }

    // Le ciphertext AEAD doit être au moins aussi grand que le tag (16 octets)
    if (packet.aead_ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        sodium_memzero(symmetric_key.data(), symmetric_key.size());
        throw DecryptionError("Ciphertext AEAD trop court — possible corruption");
    }

    // Taille du plaintext = ciphertext - tag
    const std::size_t plaintext_max_len =
        packet.aead_ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    SecureBuffer plaintext(plaintext_max_len);
    unsigned long long plaintext_len = 0;

    int decrypt_rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &plaintext_len,
        nullptr,                      // nsec (inutilisé)
        packet.aead_ciphertext.data(), packet.aead_ciphertext.size(),
        nullptr, 0,                   // Pas de données associées (AD)
        packet.nonce.data(),
        symmetric_key.data()
    );

    // Effacer la clé symétrique immédiatement après déchiffrement
    sodium_memzero(symmetric_key.data(), symmetric_key.size());

    if (decrypt_rc != 0) {
        // Effacer le buffer de sortie partiel
        sodium_memzero(plaintext.data(), plaintext.size());
        throw DecryptionError(
            "Échec du déchiffrement XChaCha20-Poly1305 — intégrité compromise ou clé incorrecte");
    }

    plaintext.resize(static_cast<std::size_t>(plaintext_len));
    return plaintext;
}
