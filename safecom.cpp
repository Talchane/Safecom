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
                g_running = false;
                std::cout << "\n\033[1;33m[Safecom] Connexion fermée par le pair.\033[0m\n";
                // L'autre thread de saisie (main) est bloqué dans std::getline.
                // Pour éviter d'obliger l'utilisateur à taper "Entrée", on coupe court ici.
                std::cout << "    ─────────────────────────────────────────────────────────\n";
                std::cout << "\033[1;35m     Déconnexion. Clés effacées. 🔒\033[0m\n" << std::endl;
                std::exit(0);
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
    std::cout << "\033[1;35m" << R"(
    ███████╗ █████╗ ███████╗███████╗ ██████╗ ██████╗ ███╗   ███╗
    ██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗████╗ ████║
    ███████╗███████║█████╗  █████╗  ██║     ██║   ██║██╔████╔██║
    ╚════██║██╔══██║██╔══╝  ██╔══╝  ██║     ██║   ██║██║╚██╔╝██║
    ███████║██║  ██║██║     ███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║
    ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝
    )" << "\033[0m";

    std::cout << "\033[1;37m"
              << "    ─────────────────────────────────────────────────────────\n"
              << "        Chat Post-Quantique Sécurisé\n"
              << "        ML-DSA-65  ·  ML-KEM-768  ·  XChaCha20-Poly1305\n"
              << "        Par Benito  |  Version 1.2\n"
              << "    ─────────────────────────────────────────────────────────\n"
              << "\033[0m" << std::endl;
}

static void print_separator() {
    std::cout << "\033[0;90m"
              << "    ─────────────────────────────────────────────────────────"
              << "\033[0m" << std::endl;
}

static void print_status(const std::string& msg, bool success = false) {
    if (success) {
        std::cout << "\033[1;32m     ✓ \033[0m" << msg << std::endl;
    } else {
        std::cout << "\033[1;33m     ⏳ \033[0;37m" << msg << "\033[0m" << std::endl;
    }
}

static void print_error(const std::string& msg) {
    std::cout << "\033[1;31m     ✗ \033[0m" << msg << std::endl;
}

// ============================================================================
//  Main
// ============================================================================

int main(int argc, char* argv[]) {
    print_banner();

    // ---- Menu interactif ----
    bool is_server = false;
    bool is_client = false;
    std::string host;
    uint16_t port = 0;

    // Vérifier si des arguments CLI ont été fournis
    if (argc >= 3) {
        std::string mode_arg = argv[1];
        if (mode_arg == "--listen" && argc >= 3) {
            is_server = true;
            port = static_cast<uint16_t>(std::stoi(argv[2]));
        } else if (mode_arg == "--connect" && argc >= 4) {
            is_client = true;
            host = argv[2];
            port = static_cast<uint16_t>(std::stoi(argv[3]));
        }
    }

    // Si pas d'arguments valides, menu interactif
    if (!is_server && !is_client) {
        std::cout << "\033[1;37m     Choisissez un mode :\033[0m\n\n";
        std::cout << "\033[1;36m       [1]\033[0m  🖥️   Héberger une session  (serveur)\n";
        std::cout << "\033[1;36m       [2]\033[0m  🔗   Rejoindre une session (client)\n";
        std::cout << "\033[1;36m       [3]\033[0m  🚪   Quitter\n\n";

        int choice = 0;
        while (true) {
            std::cout << "\033[1;35m     ❯ \033[0m";
            std::cin >> choice;

            if (std::cin.fail()) {
                std::cin.clear();
                std::cin.ignore(10000, '\n');
                print_error("Entrée invalide. Tapez 1, 2 ou 3.");
                continue;
            }
            std::cin.ignore(10000, '\n');

            if (choice == 3) {
                std::cout << "\n\033[0;90m     Au revoir ! 🔒\033[0m\n" << std::endl;
                return 0;
            }
            if (choice == 1 || choice == 2) break;
            print_error("Choix invalide. Tapez 1, 2 ou 3.");
        }

        is_server = (choice == 1);
        is_client = (choice == 2);

        print_separator();

        // Demander le port
        if (is_server) {
            std::cout << "\033[1;37m     Port d'écoute \033[0;90m(ex: 4444)\033[1;37m :\033[0m ";
        } else {
            std::cout << "\033[1;37m     Adresse de l'hôte \033[0;90m(ex: 127.0.0.1)\033[1;37m :\033[0m ";
            std::getline(std::cin, host);
            if (host.empty()) host = "127.0.0.1";
            std::cout << "\033[1;37m     Port de connexion \033[0;90m(ex: 4444)\033[1;37m :\033[0m ";
        }

        int port_input = 0;
        while (true) {
            std::cin >> port_input;
            if (std::cin.fail() || port_input < 1 || port_input > 65535) {
                std::cin.clear();
                std::cin.ignore(10000, '\n');
                print_error("Port invalide. Entrez un nombre entre 1 et 65535.");
                std::cout << "\033[1;35m     ❯ \033[0m";
                continue;
            }
            std::cin.ignore(10000, '\n');
            break;
        }
        port = static_cast<uint16_t>(port_input);

        print_separator();
        std::cout << std::endl;
    }

    // ---- Signal handler ----
    std::signal(SIGINT, signal_handler);

    try {
        // ---- Initialisation du moteur cryptographique ----
        print_status("Initialisation du moteur cryptographique...");
        CryptoEngine engine;
        print_status("Clés d'identité ML-DSA-65 générées.", true);

        // Générer la paire KEM éphémère pour cette session
        KemKeyPair kem_kp = engine.generate_kem_keypair();
        print_status("Clés éphémères ML-KEM-768 générées.", true);

        // ---- Connexion TCP ----
        TcpSocket sock;

        if (is_server) {
            print_status("Écoute sur le port " + std::to_string(port) + "...");
            sock = TcpSocket::listen_and_accept(port);
            print_status("Client connecté !", true);
        } else {
            print_status("Connexion à " + host + ":" + std::to_string(port) + "...");
            sock = TcpSocket::connect_to(host, port);
            print_status("Connecté au serveur !", true);
        }

        // ---- Handshake : échange de clés ----
        print_status("Échange de clés en cours...");

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

        print_status("Clé d'identité du pair reçue (" + std::to_string(peer_dsa_pk.size()) + " octets)", true);
        print_status("Clé éphémère du pair reçue (" + std::to_string(peer_kem_pk.size()) + " octets)", true);

        // Afficher l'empreinte de la clé DSA du pair (premiers 16 octets en hex)
        {
            std::string fingerprint = "Empreinte du pair : ";
            for (size_t i = 0; i < 16 && i < peer_dsa_pk.size(); ++i) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02x", peer_dsa_pk[i]);
                fingerprint += hex;
                if (i % 2 == 1) fingerprint += " ";
            }
            fingerprint += "...";
            print_status(fingerprint, true);
        }

        print_separator();
        std::cout << "\n\033[1;32m     ✓ Session sécurisée établie !\033[0m\n";
        std::cout << "\033[0;90m     Tapez vos messages. /quit pour quitter.\033[0m\n" << std::endl;

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

            if (input == "/quit" || input == "exit") {
                g_running = false;
                // Important : on ferme la socket pour débloquer de force le thread de réception (recv_loop)
                // qui est bloqué dans recv(). Cela va générer une exception/fermeture côté recv_loop.
                sock.close();
                break;
            }

            try {
                send_encrypted(sock, engine, peer_kem_pk, input);
            } catch (const std::exception& e) {
                safe_print("[!] Erreur d'envoi : ", e.what());
                g_running = false;
                sock.close();
                break;
            }

            std::cout << "\033[1;32m" << "Vous" << "\033[0m" << " > " << std::flush;
        }

        // ---- Cleanup ----
        g_running = false;
        sock.close(); // Appel sûr même si déjà fermé

        if (recv_thread.joinable()) {
            recv_thread.join();
        }

        // Effacer les clés
        kem_kp.wipe();
        sodium_memzero(peer_dsa_pk.data(), peer_dsa_pk.size());
        sodium_memzero(peer_kem_pk.data(), peer_kem_pk.size());

        print_separator();
        std::cout << "\033[1;35m     Déconnexion. Clés effacées. 🔒\033[0m\n" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "\n[ERREUR FATALE] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
