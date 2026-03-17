/**
 * @file CryptoEngine.hpp
 * @author Benoît Ferrandini
 * @brief Coeur cryptographique hybride post-quantique pour messagerie sécurisée.
 *
 * Architecture :
 *   - Identité (long terme)    : ML-DSA-65  (Dilithium3) via liboqs    → Signature
 *   - Échange de clé (éphém.)  : ML-KEM-768 (Kyber768)   via liboqs    → Encapsulation / PFS
 *   - Chiffrement symétrique   : ChaCha20-Poly1305       via libsodium → AEAD
 *   - Entropie                 : randombytes_buf()        via libsodium → CSPRNG
 *
 * Garanties de sécurité :
 *   - Effacement mémoire systématique (sodium_memzero) de toute clé sensible.
 *   - Perfect Forward Secrecy via clés ML-KEM éphémères par session/message.
 *   - Classe non-copiable, non-déplaçable pour éviter les fuites accidentelles.
 */

#ifndef CRYPTO_ENGINE_HPP
#define CRYPTO_ENGINE_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// ============================================================================
//  Allocateur sécurisé — efface automatiquement la mémoire à la libération
// ============================================================================

/**
 * @brief Allocateur STL qui appelle sodium_memzero() à la désallocation.
 *
 * Tout std::vector<uint8_t, SecureAllocator<uint8_t>> sera effacé de la RAM
 * dès qu'il sort de portée ou qu'il est redimensionné.
 */
template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() noexcept = default;

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n);
    void deallocate(T* ptr, std::size_t n) noexcept;

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

// ============================================================================
//  Types sécurisés
// ============================================================================

/** Vecteur d'octets avec effacement mémoire automatique. */
using SecureBuffer = std::vector<uint8_t, SecureAllocator<uint8_t>>;

/** Vecteur d'octets standard (données non-sensibles : clés publiques, ciphertexts). */
using ByteVec = std::vector<uint8_t>;

// ============================================================================
//  Exceptions spécialisées
// ============================================================================

/** Erreur levée quand une signature ML-DSA est invalide. */
class SignatureVerificationError : public std::runtime_error {
public:
    explicit SignatureVerificationError(const std::string& msg)
        : std::runtime_error(msg) {}
};

/** Erreur levée quand la décapsulation ML-KEM échoue. */
class DecapsulationError : public std::runtime_error {
public:
    explicit DecapsulationError(const std::string& msg)
        : std::runtime_error(msg) {}
};

/** Erreur levée quand le déchiffrement AEAD échoue (intégrité ou clé incorrecte). */
class DecryptionError : public std::runtime_error {
public:
    explicit DecryptionError(const std::string& msg)
        : std::runtime_error(msg) {}
};

/** Erreur levée pour les problèmes d'initialisation (libsodium, liboqs). */
class CryptoInitError : public std::runtime_error {
public:
    explicit CryptoInitError(const std::string& msg)
        : std::runtime_error(msg) {}
};

// ============================================================================
//  Paire de clés ML-KEM éphémère
// ============================================================================

/**
 * @brief Paire de clés ML-KEM-768 éphémère pour une session.
 *
 * La clé publique est envoyée au pair ; la clé privée reste locale
 * et est effacée dès la décapsulation terminée.
 */
struct KemKeyPair {
    ByteVec      public_key;   ///< Clé publique ML-KEM (envoyée au pair)
    SecureBuffer private_key;  ///< Clé privée ML-KEM (usage unique, effacée après décaps.)

    /** Efface la clé privée immédiatement. */
    void wipe() noexcept;
};

// ============================================================================
//  Paquet chiffré (format de transport)
// ============================================================================

/**
 * @brief Structure représentant un message chiffré complet, prêt à envoyer.
 *
 * Contient toutes les données nécessaires au destinataire pour :
 *   1. Vérifier l'authenticité (signature ML-DSA)
 *   2. Récupérer la clé symétrique (KEM ciphertext)
 *   3. Déchiffrer le message (AEAD ciphertext + nonce)
 */
struct EncryptedPacket {
    ByteVec kem_ciphertext;    ///< Ciphertext ML-KEM (clé symétrique encapsulée)
    ByteVec nonce;             ///< Nonce ChaCha20-Poly1305 (24 octets, XChaCha20)
    ByteVec aead_ciphertext;   ///< Message chiffré + tag Poly1305
    ByteVec signature;         ///< Signature ML-DSA sur (kem_ciphertext || aead_ciphertext)

    /** Sérialise le paquet en un seul buffer (longueur-préfixé, little-endian). */
    [[nodiscard]] ByteVec serialize() const;

    /** Désérialise un buffer en EncryptedPacket. Lève std::runtime_error si invalide. */
    [[nodiscard]] static EncryptedPacket deserialize(const ByteVec& data);
};

// ============================================================================
//  Classe principale — CryptoEngine
// ============================================================================

/**
 * @brief Moteur cryptographique hybride post-quantique.
 *
 * Usage typique (côté expéditeur) :
 * @code
 *   CryptoEngine engine;
 *   auto kem_kp = engine.generate_kem_keypair();
 *   // Envoyer kem_kp.public_key au pair ...
 *
 *   auto packet = engine.encrypt_for_peer(
 *       plaintext,
 *       peer_kem_public_key
 *   );
 *   // Envoyer packet.serialize() sur le réseau ...
 * @endcode
 *
 * Usage typique (côté destinataire) :
 * @code
 *   CryptoEngine engine;
 *   auto plaintext = engine.decrypt_from_peer(
 *       packet,
 *       sender_dsa_public_key,
 *       local_kem_private_key
 *   );
 * @endcode
 */
class CryptoEngine {
public:
    // ---- Construction / Destruction ----------------------------------------

    /**
     * @brief Construit le moteur et génère la paire de clés ML-DSA (identité).
     * @throws CryptoInitError si libsodium ou liboqs échouent à s'initialiser.
     */
    CryptoEngine();

    /**
     * @brief Destructeur — efface toutes les clés sensibles de la RAM.
     */
    ~CryptoEngine() noexcept;

    // Non-copiable, non-déplaçable (protection mémoire)
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;
    CryptoEngine(CryptoEngine&&) = delete;
    CryptoEngine& operator=(CryptoEngine&&) = delete;

    // ---- Gestion des clés --------------------------------------------------

    /**
     * @brief Génère une paire de clés ML-KEM-768 éphémère.
     *
     * À appeler pour chaque nouvelle session ou message (PFS).
     * La clé publique doit être transmise au pair avant l'échange.
     *
     * @return KemKeyPair contenant clé publique + clé privée éphémère.
     * @throws CryptoInitError si la génération échoue.
     */
    [[nodiscard]] KemKeyPair generate_kem_keypair() const;

    /**
     * @brief Retourne la clé publique ML-DSA (identité long terme).
     *
     * Cette clé doit être partagée avec les pairs pour qu'ils puissent
     * vérifier les signatures des messages envoyés.
     */
    [[nodiscard]] const ByteVec& get_dsa_public_key() const noexcept;

    // ---- Chiffrement / Déchiffrement ---------------------------------------

    /**
     * @brief Chiffre un message pour un destinataire.
     *
     * Flux interne :
     *   1. ML-KEM Encaps → génère clé symétrique + KEM ciphertext
     *   2. XChaCha20-Poly1305 → chiffre le plaintext (nonce 24 octets)
     *   3. ML-DSA Sign → signe (kem_ciphertext || aead_ciphertext)
     *
     * @param plaintext         Message en clair à chiffrer.
     * @param peer_kem_pk       Clé publique ML-KEM éphémère du destinataire.
     * @return EncryptedPacket prêt à être sérialisé et envoyé.
     * @throws CryptoInitError si une opération crypto interne échoue.
     */
    [[nodiscard]] EncryptedPacket encrypt_for_peer(
        const ByteVec& plaintext,
        const ByteVec& peer_kem_pk
    ) const;

    /**
     * @brief Déchiffre un message reçu d'un pair.
     *
     * Flux interne :
     *   1. ML-DSA Verify → vérifie la signature de l'expéditeur
     *   2. ML-KEM Decaps → récupère la clé symétrique
     *   3. ChaCha20-Poly1305 → déchiffre le message
     *
     * @param packet            Paquet chiffré reçu.
     * @param sender_dsa_pk     Clé publique ML-DSA de l'expéditeur.
     * @param local_kem_sk      Clé privée ML-KEM locale (éphémère, sera effacée
     *                          en interne après décapsulation).
     * @return Le message en clair (SecureBuffer, effacé auto à la destruction).
     *
     * @throws SignatureVerificationError si la signature ML-DSA est invalide.
     * @throws DecapsulationError         si la décapsulation ML-KEM échoue.
     * @throws DecryptionError            si le déchiffrement AEAD échoue.
     */
    [[nodiscard]] SecureBuffer decrypt_from_peer(
        const EncryptedPacket& packet,
        const ByteVec& sender_dsa_pk,
        SecureBuffer& local_kem_sk
    ) const;

private:
    // ---- Clés d'identité ML-DSA (long terme) --------------------------------
    ByteVec      dsa_public_key_;   ///< Clé publique ML-DSA-65
    SecureBuffer dsa_private_key_;  ///< Clé privée ML-DSA-65 (effacée au ~CryptoEngine)
};

#endif // CRYPTO_ENGINE_HPP
