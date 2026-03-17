/**
 * @file Network.cpp
 * @author Benoît Ferrandini
 * @brief Implémentation de la couche réseau TCP POSIX pour Safecom.
 */

#include "Network.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

// ============================================================================
//  Helpers internes
// ============================================================================

/** Encode un uint32_t en little-endian. */
static void encode_u32_le(uint8_t* buf, uint32_t val) {
    buf[0] = static_cast<uint8_t>(val & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

/** Décode un uint32_t depuis un buffer little-endian. */
static uint32_t decode_u32_le(const uint8_t* buf) {
    return static_cast<uint32_t>(buf[0])
         | (static_cast<uint32_t>(buf[1]) << 8)
         | (static_cast<uint32_t>(buf[2]) << 16)
         | (static_cast<uint32_t>(buf[3]) << 24);
}

// ============================================================================
//  TcpSocket — Constructeurs / Destructeur
// ============================================================================

TcpSocket::TcpSocket() noexcept : fd_(-1) {}

TcpSocket::TcpSocket(int fd) noexcept : fd_(fd) {}

TcpSocket::~TcpSocket() noexcept {
    close();
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

// ============================================================================
//  TcpSocket — Factory methods
// ============================================================================

TcpSocket TcpSocket::listen_and_accept(uint16_t port) {
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        throw std::runtime_error(
            std::string("socket() : ") + std::strerror(errno));
    }

    // Réutiliser le port immédiatement après fermeture
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; // Écoute sur toutes les interfaces
    addr.sin_port = htons(port);

    if (::bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(listen_fd);
        throw std::runtime_error(
            std::string("bind() sur le port ") + std::to_string(port) +
            " : " + std::strerror(errno));
    }

    if (::listen(listen_fd, 1) < 0) {
        ::close(listen_fd);
        throw std::runtime_error(
            std::string("listen() : ") + std::strerror(errno));
    }

    // Accepter une seule connexion
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = ::accept(listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
    ::close(listen_fd); // Fermer le socket d'écoute

    if (client_fd < 0) {
        throw std::runtime_error(
            std::string("accept() : ") + std::strerror(errno));
    }

    return TcpSocket(client_fd);
}

TcpSocket TcpSocket::connect_to(const std::string& host, uint16_t port) {
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    int rc = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
    if (rc != 0) {
        throw std::runtime_error(
            std::string("getaddrinfo(") + host + ") : " + gai_strerror(rc));
    }

    int fd = ::socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(result);
        throw std::runtime_error(
            std::string("socket() : ") + std::strerror(errno));
    }

    if (::connect(fd, result->ai_addr, result->ai_addrlen) < 0) {
        ::close(fd);
        freeaddrinfo(result);
        throw std::runtime_error(
            std::string("connect(") + host + ":" + std::to_string(port) +
            ") : " + std::strerror(errno));
    }

    freeaddrinfo(result);
    return TcpSocket(fd);
}

// ============================================================================
//  TcpSocket — Envoi / Réception
// ============================================================================

void TcpSocket::send_all(const void* data, size_t len) const {
    const auto* ptr = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd_, ptr + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            throw std::runtime_error("Connexion fermée par le pair (send)");
        }
        sent += static_cast<size_t>(n);
    }
}

void TcpSocket::recv_exact(void* buf, size_t len) const {
    auto* ptr = static_cast<uint8_t*>(buf);
    size_t received = 0;
    while (received < len) {
        ssize_t n = ::recv(fd_, ptr + received, len - received, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            throw std::runtime_error("Connexion fermée par le pair (recv)");
        }
        received += static_cast<size_t>(n);
    }
}

void TcpSocket::send_framed(const ByteVec& data) const {
    if (data.size() > 0xFFFFFFFF) {
        throw std::runtime_error("Message trop volumineux pour le framing 32 bits");
    }

    uint8_t header[4];
    encode_u32_le(header, static_cast<uint32_t>(data.size()));
    send_all(header, 4);
    if (!data.empty()) {
        send_all(data.data(), data.size());
    }
}

ByteVec TcpSocket::recv_framed() const {
    uint8_t header[4];
    recv_exact(header, 4);

    uint32_t len = decode_u32_le(header);

    // Limite de sécurité : max 16 Mo par message
    static constexpr uint32_t MAX_MSG_SIZE = 16 * 1024 * 1024;
    if (len > MAX_MSG_SIZE) {
        throw std::runtime_error(
            "Taille de message suspecte : " + std::to_string(len) +
            " octets (max " + std::to_string(MAX_MSG_SIZE) + ")");
    }

    ByteVec data(len);
    if (len > 0) {
        recv_exact(data.data(), len);
    }
    return data;
}

// ============================================================================
//  TcpSocket — Utilitaires
// ============================================================================

bool TcpSocket::is_valid() const noexcept {
    return fd_ >= 0;
}

void TcpSocket::close() noexcept {
    if (fd_ >= 0) {
        // Force the socket to shutdown both reading and writing.
        // This is crucial in multithreaded environments to immediately
        // unblock any thread currently waiting in recv() or send()
        // before we close the file descriptor.
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
}

int TcpSocket::fd() const noexcept {
    return fd_;
}
