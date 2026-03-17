/**
 * @file Network.hpp
 * @author Benoît Ferrandini
 * @brief Couche réseau bas niveau (TCP) pour messagerie sécurisée.nux/Tails OS).
 *
 * Fournit une classe TcpSocket avec envoi/réception longueur-préfixé
 * et gestion RAII du descripteur de fichier.
 */

#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <cstdint>
#include <string>
#include <vector>

using ByteVec = std::vector<uint8_t>;

/**
 * @brief Socket TCP avec framing longueur-préfixé.
 *
 * Protocole de transport : chaque message est précédé de 4 octets
 * little-endian indiquant la taille du payload.
 *
 * Non-copiable, déplaçable (transfert de propriété du fd).
 */
class TcpSocket {
public:
    /** Construit un TcpSocket vide (fd = -1). */
    TcpSocket() noexcept;

    /** Construit à partir d'un fd existant (prend la propriété). */
    explicit TcpSocket(int fd) noexcept;

    /** Destructeur — ferme le socket si ouvert. */
    ~TcpSocket() noexcept;

    // Déplaçable
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;

    // Non-copiable
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    // ---- Factory methods ---------------------------------------------------

    /**
     * @brief Mode serveur : écoute sur un port et accepte UNE connexion.
     * @param port Port TCP d'écoute.
     * @return TcpSocket connecté au client.
     */
    static TcpSocket listen_and_accept(uint16_t port);

    /**
     * @brief Mode client : se connecte à un hôte distant.
     * @param host Adresse IP ou hostname.
     * @param port Port TCP distant.
     * @return TcpSocket connecté au serveur.
     */
    static TcpSocket connect_to(const std::string& host, uint16_t port);

    // ---- Envoi / Réception -------------------------------------------------

    /**
     * @brief Envoie un message avec framing longueur-préfixé.
     * @param data Payload à envoyer.
     * @throws std::runtime_error si l'envoi échoue.
     */
    void send_framed(const ByteVec& data) const;

    /**
     * @brief Reçoit un message longueur-préfixé.
     * @return Payload reçu.
     * @throws std::runtime_error si la réception échoue ou la connexion est fermée.
     */
    ByteVec recv_framed() const;

    /** @brief Vérifie si le socket est valide. */
    [[nodiscard]] bool is_valid() const noexcept;

    /** @brief Ferme le socket. */
    void close() noexcept;

    /** @brief Retourne le fd sous-jacent (pour select/poll). */
    [[nodiscard]] int fd() const noexcept;

private:
    int fd_;

    /** Envoie exactement n octets (boucle sur send). */
    void send_all(const void* data, size_t len) const;

    /** Reçoit exactement n octets (boucle sur recv). */
    void recv_exact(void* buf, size_t len) const;
};

#endif // NETWORK_HPP
