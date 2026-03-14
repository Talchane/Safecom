/**
 * @file safecom.cpp
 * @brief Application de chat sécurisé post-quantique en ligne de commande.
 *
 * Usage :
 *   ./safecom --listen PORT          # Mode serveur
 *   ./safecom --connect HOST PORT    # Mode client
 *
 * Protocole :
 *   1. Connexion TCP
 *   2. Handshake : échange clés publiques ML-DSA + ML-KEM
 *   3. Chat chiffré : ML-KEM encaps + XChaCha20-Poly1305 + ML-DSA signature
 *
 * Commandes :
 *   /quit   — quitter proprement
 */

#include "CryptoEngine.hpp"
#include "Network.hpp"

#include <sodium.h>

#include <atomic>
#include <csignal>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

// ============================================================================
//  Constantes du protocole
// ============================================================================

static constexpr uint8_t MSG_HANDSHAKE = 0x01;
static constexpr uint8_t MSG_CHAT      = 0x02;

// ============================================================================
//  État global pour arrêt propre
// ============================================================================

static std::atomic<bool> g_running{true};
static std::mutex g_print_mutex;

/** Affichage thread-safe sur la console. */
template <typename... Args>
void safe_print(Args&&... args) {
    std::lock_guard<std::mutex> lock(g_print_mutex);
    (std::cout << ... << std::forward<Args>(args)) << std::endl;
}

/** Gestionnaire SIGINT (Ctrl+C). */
void signal_handler(int) {
    g_running = false;
}

// ============================================================================
//  Handshake — échange de clés
// ============================================================================

/**
 * @brief Construit le message de handshake : [0x01][4B dsa_pk_len][dsa_pk][4B kem_pk_len][kem_pk]
 */
static ByteVec build_handshake(const ByteVec& dsa_pk, const ByteVec& kem_pk) {
    ByteVec msg;
    msg.reserve(1 + 4 + dsa_pk.size() + 4 + kem_pk.size());

    // Type
    msg.push_back(MSG_HANDSHAKE);

    // DSA public key (length-prefixed)
    auto dsa_len = static_cast<uint32_t>(dsa_pk.size());
    msg.push_back(static_cast<uint8_t>(dsa_len & 0xFF));
    msg.push_back(static_cast<uint8_t>((dsa_len >> 8) & 0xFF));
    msg.push_back(static_cast<uint8_t>((dsa_len >> 16) & 0xFF));
    msg.push_back(static_cast<uint8_t>((dsa_len >> 24) & 0xFF));
    msg.insert(msg.end(), dsa_pk.begin(), dsa_pk.end());

    // KEM public key (length-prefixed)
    auto kem_len = static_cast<uint32_t>(kem_pk.size());
    msg.push_back(static_cast<uint8_t>(kem_len & 0xFF));
    msg.push_back(static_cast<uint8_t>((kem_len >> 8) & 0xFF));
    msg.push_back(static_cast<uint8_t>((kem_len >> 16) & 0xFF));
    msg.push_back(static_cast<uint8_t>((kem_len >> 24) & 0xFF));
    msg.insert(msg.end(), kem_pk.begin(), kem_pk.end());

    return msg;
}

/** Lit un uint32 little-endian à offset donné avec vérification de bornes. */
static uint32_t read_u32(const ByteVec& data, size_t offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("Handshake : données tronquées");
    }
    return static_cast<uint32_t>(data[offset])
         | (static_cast<uint32_t>(data[offset + 1]) << 8)
         | (static_cast<uint32_t>(data[offset + 2]) << 16)
         | (static_cast<uint32_t>(data[offset + 3]) << 24);
}

/**
 * @brief Parse un message de handshake et extrait les clés publiques du pair.
 */
static void parse_handshake(const ByteVec& data, ByteVec& peer_dsa_pk, ByteVec& peer_kem_pk) {
    if (data.empty() || data[0] != MSG_HANDSHAKE) {
        throw std::runtime_error("Message de handshake invalide (type incorrect)");
    }

    size_t offset = 1;

    // DSA public key
    uint32_t dsa_len = read_u32(data, offset);
    offset += 4;
    if (offset + dsa_len > data.size()) {
        throw std::runtime_error("Handshake : clé DSA tronquée");
    }
    peer_dsa_pk.assign(data.begin() + offset, data.begin() + offset + dsa_len);
    offset += dsa_len;

    // KEM public key
    uint32_t kem_len = read_u32(data, offset);
    offset += 4;
    if (offset + kem_len > data.size()) {
        throw std::runtime_error("Handshake : clé KEM tronquée");
    }
    peer_kem_pk.assign(data.begin() + offset, data.begin() + offset + kem_len);
    offset += kem_len;

    if (offset != data.size()) {
        throw std::runtime_error("Handshake : données excédentaires");
    }
}

// ============================================================================
//  Thread de réception
// ============================================================================

/**
 * @brief Boucle de réception : lit les messages du pair, déchiffre, affiche.
 *
 * @param sock       Socket TCP connecté.
 * @param engine     CryptoEngine local (pour vérification de signature).
 * @param peer_dsa_pk Clé publique ML-DSA du pair.
 * @param kem_sk     Clé privée ML-KEM locale (copie faite à chaque décrypt).
 */
static void recv_loop(
    const TcpSocket& sock,
    const CryptoEngine& engine,
    const ByteVec& peer_dsa_pk,
    SecureBuffer& kem_sk
) {
    while (g_running) {
        try {
            ByteVec raw = sock.recv_framed();

            if (raw.empty() || raw[0] != MSG_CHAT) {
                safe_print("[!] Message de type inconnu reçu, ignoré.");
                continue;
            }

            // Extraire le paquet chiffré (après le type byte)
            ByteVec packet_data(raw.begin() + 1, raw.end());
            EncryptedPacket packet = EncryptedPacket::deserialize(packet_data);

            // Copier la clé KEM SK pour le déchiffrement
            // (decrypt_from_peer efface la copie, l'original reste pour la session)
            SecureBuffer kem_sk_copy(kem_sk.begin(), kem_sk.end());

            SecureBuffer plaintext = engine.decrypt_from_peer(
                packet, peer_dsa_pk, kem_sk_copy
            );

            std::string msg(plaintext.begin(), plaintext.end());

            // Effacer le plaintext du SecureBuffer automatiquement (RAII)
            {
                std::lock_guard<std::mutex> lock(g_print_mutex);
                std::cout << "\r\033[K"; // Effacer la ligne en cours
                std::cout << "\033[1;36m" << "Pair" << "\033[0m" << " > " << msg << std::endl;
                std::cout << "\033[1;32m" << "Vous" << "\033[0m" << " > " << std::flush;
            }

        } catch (const SignatureVerificationError& e) {
            safe_print("[⚠] Signature invalide : ", e.what());
        } catch (const DecapsulationError& e) {
            safe_print("[⚠] Décapsulation échouée : ", e.what());
        } catch (const DecryptionError& e) {
            safe_print("[⚠] Déchiffrement échoué : ", e.what());
        } catch (const std::runtime_error&) {
            // Connexion fermée ou erreur réseau
            if (g_running) {
                safe_print("\n[Safecom] Connexion fermée par le pair.");
                g_running = false;
            }
            break;
        }
    }
}

// ============================================================================
//  Envoi d'un message chiffré
// ============================================================================

static void send_encrypted(
    const TcpSocket& sock,
    const CryptoEngine& engine,
    const ByteVec& peer_kem_pk,
    const std::string& message
) {
    ByteVec plaintext(message.begin(), message.end());

    // Chiffrer avec la clé KEM publique du pair
    EncryptedPacket packet = engine.encrypt_for_peer(plaintext, peer_kem_pk);

    // Sérialiser le paquet
    ByteVec serialized = packet.serialize();

    // Construire le message réseau : [type][serialized_packet]
    ByteVec wire_msg;
    wire_msg.reserve(1 + serialized.size());
    wire_msg.push_back(MSG_CHAT);
    wire_msg.insert(wire_msg.end(), serialized.begin(), serialized.end());

    sock.send_framed(wire_msg);
}

// ============================================================================
//  Affichage
// ============================================================================

static void print_banner() {
    std::cout << "\033[1;35m"
              << R"(
  ╔══════════════════════════════════════════════════════╗
  ║            🔒 SAFECOM — Chat Post-Quantique         ║
  ║         ML-DSA-65 + ML-KEM-768 + XChaCha20          ║
  ╚══════════════════════════════════════════════════════╝
)" << "\033[0m" << std::endl;
}

static void print_usage(const char* prog) {
    std::cerr << "Usage :\n"
              << "  " << prog << " --listen PORT          # Mode serveur\n"
              << "  " << prog << " --connect HOST PORT    # Mode client\n";
}

// ============================================================================
//  Main
// ============================================================================

int main(int argc, char* argv[]) {
    print_banner();

    // ---- Parse arguments ----
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    bool is_server = (mode == "--listen");
    bool is_client = (mode == "--connect");

    if (!is_server && !is_client) {
        print_usage(argv[0]);
        return 1;
    }

    if (is_client && argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    // ---- Signal handler ----
    std::signal(SIGINT, signal_handler);

    try {
        // ---- Initialisation du moteur cryptographique ----
        std::cout << "[Safecom] Initialisation du moteur cryptographique..." << std::endl;
        CryptoEngine engine;
        std::cout << "[Safecom] ✓ Clés d'identité ML-DSA-65 générées." << std::endl;

        // Générer la paire KEM éphémère pour cette session
        KemKeyPair kem_kp = engine.generate_kem_keypair();
        std::cout << "[Safecom] ✓ Clés éphémères ML-KEM-768 générées." << std::endl;

        // ---- Connexion TCP ----
        TcpSocket sock;

        if (is_server) {
            uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
            std::cout << "[Safecom] Écoute sur le port " << port << "..." << std::endl;
            sock = TcpSocket::listen_and_accept(port);
            std::cout << "[Safecom] ✓ Client connecté !" << std::endl;
        } else {
            std::string host = argv[2];
            uint16_t port = static_cast<uint16_t>(std::stoi(argv[3]));
            std::cout << "[Safecom] Connexion à " << host << ":" << port << "..." << std::endl;
            sock = TcpSocket::connect_to(host, port);
            std::cout << "[Safecom] ✓ Connecté au serveur !" << std::endl;
        }

        // ---- Handshake : échange de clés ----
        std::cout << "[Safecom] Échange de clés en cours..." << std::endl;

        // Envoyer nos clés publiques
        ByteVec handshake_msg = build_handshake(
            engine.get_dsa_public_key(),
            kem_kp.public_key
        );
        sock.send_framed(handshake_msg);

        // Recevoir les clés publiques du pair
        ByteVec peer_handshake = sock.recv_framed();
        ByteVec peer_dsa_pk;
        ByteVec peer_kem_pk;
        parse_handshake(peer_handshake, peer_dsa_pk, peer_kem_pk);

        std::cout << "[Safecom] ✓ Clé d'identité du pair reçue (" 
                  << peer_dsa_pk.size() << " octets)" << std::endl;
        std::cout << "[Safecom] ✓ Clé éphémère du pair reçue (" 
                  << peer_kem_pk.size() << " octets)" << std::endl;

        // Afficher l'empreinte de la clé DSA du pair (premiers 16 octets en hex)
        {
            std::cout << "[Safecom] Empreinte du pair : ";
            for (size_t i = 0; i < 16 && i < peer_dsa_pk.size(); ++i) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02x", peer_dsa_pk[i]);
                std::cout << hex;
                if (i % 2 == 1) std::cout << " ";
            }
            std::cout << "..." << std::endl;
        }

        std::cout << "\n[Safecom] ✓ Session sécurisée établie !"
                  << "\n[Safecom] Tapez vos messages. /quit pour quitter.\n" << std::endl;

        // ---- Lancer le thread de réception ----
        std::thread recv_thread(recv_loop,
            std::cref(sock),
            std::cref(engine),
            std::cref(peer_dsa_pk),
            std::ref(kem_kp.private_key)
        );

        // ---- Boucle principale : lecture stdin → chiffrement → envoi ----
        std::string input;
        std::cout << "\033[1;32m" << "Vous" << "\033[0m" << " > " << std::flush;

        while (g_running && std::getline(std::cin, input)) {
            if (input.empty()) {
                std::cout << "\033[1;32m" << "Vous" << "\033[0m" << " > " << std::flush;
                continue;
            }

            if (input == "/quit") {
                g_running = false;
                break;
            }

            try {
                send_encrypted(sock, engine, peer_kem_pk, input);
            } catch (const std::exception& e) {
                safe_print("[!] Erreur d'envoi : ", e.what());
                g_running = false;
                break;
            }

            std::cout << "\033[1;32m" << "Vous" << "\033[0m" << " > " << std::flush;
        }

        // ---- Cleanup ----
        g_running = false;
        sock.close();

        if (recv_thread.joinable()) {
            recv_thread.join();
        }

        // Effacer les clés
        kem_kp.wipe();
        sodium_memzero(peer_dsa_pk.data(), peer_dsa_pk.size());
        sodium_memzero(peer_kem_pk.data(), peer_kem_pk.size());

        std::cout << "\n[Safecom] Déconnexion. Clés effacées. 🔒" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "\n[ERREUR FATALE] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
