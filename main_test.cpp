/**
 * @file main_test.cpp
 * @brief Test round-trip : encrypt → serialize → deserialize → decrypt.
 *
 * Ce fichier sert de validation end-to-end du CryptoEngine.
 * Compilez-le avec : cmake --build build && ./build/crypto_test
 */

#include "CryptoEngine.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

int main() {
    try {
        std::cout << "[*] Initialisation de Alice (CryptoEngine)..." << std::endl;
        CryptoEngine alice;

        std::cout << "[*] Initialisation de Bob (CryptoEngine)..." << std::endl;
        CryptoEngine bob;

        // Bob génère une paire de clés KEM éphémère et envoie sa clé publique à Alice
        std::cout << "[*] Bob génère sa paire de clés ML-KEM éphémère..." << std::endl;
        KemKeyPair bob_kem = bob.generate_kem_keypair();
        std::cout << "    Clé publique KEM : " << bob_kem.public_key.size() << " octets" << std::endl;
        std::cout << "    Clé privée KEM  : " << bob_kem.private_key.size() << " octets" << std::endl;

        // Alice chiffre un message pour Bob
        const std::string message_str = "Salut Bob ! Ceci est un message ultra-secret post-quantique. 🔐";
        ByteVec plaintext(message_str.begin(), message_str.end());

        std::cout << "\n[*] Alice chiffre le message pour Bob..." << std::endl;
        std::cout << "    Message clair : \"" << message_str << "\"" << std::endl;

        EncryptedPacket packet = alice.encrypt_for_peer(plaintext, bob_kem.public_key);

        std::cout << "    KEM ciphertext : " << packet.kem_ciphertext.size() << " octets" << std::endl;
        std::cout << "    Nonce          : " << packet.nonce.size() << " octets" << std::endl;
        std::cout << "    AEAD ciphertext: " << packet.aead_ciphertext.size() << " octets" << std::endl;
        std::cout << "    Signature      : " << packet.signature.size() << " octets" << std::endl;

        // Sérialisation (simulation envoi réseau)
        std::cout << "\n[*] Sérialisation du paquet..." << std::endl;
        ByteVec wire_data = packet.serialize();
        std::cout << "    Taille totale sur le fil : " << wire_data.size() << " octets" << std::endl;

        // Désérialisation (simulation réception réseau)
        std::cout << "[*] Désérialisation du paquet..." << std::endl;
        EncryptedPacket received = EncryptedPacket::deserialize(wire_data);

        // Bob déchiffre le message
        std::cout << "\n[*] Bob déchiffre le message..." << std::endl;
        SecureBuffer decrypted = bob.decrypt_from_peer(
            received,
            alice.get_dsa_public_key(),
            bob_kem.private_key   // Sera effacée en interne (PFS)
        );

        std::string decrypted_str(decrypted.begin(), decrypted.end());
        std::cout << "    Message déchiffré : \"" << decrypted_str << "\"" << std::endl;

        // Vérification que la clé KEM a bien été effacée
        std::cout << "\n[*] Vérification PFS..." << std::endl;
        std::cout << "    Clé privée KEM de Bob après décaps : "
                  << bob_kem.private_key.size() << " octets (doit être 0)" << std::endl;

        // Vérification du round-trip
        if (decrypted_str == message_str) {
            std::cout << "\n[✓] TEST RÉUSSI — Round-trip encrypt/decrypt OK !" << std::endl;
        } else {
            std::cerr << "\n[✗] TEST ÉCHOUÉ — Le message déchiffré ne correspond pas !" << std::endl;
            return EXIT_FAILURE;
        }

        // --- Test : signature invalide ---
        std::cout << "\n[*] Test de rejet de signature invalide..." << std::endl;
        CryptoEngine eve; // Attaquante
        KemKeyPair bob_kem2 = bob.generate_kem_keypair();

        // Eve chiffre un message mais Alice va le recevoir comme venant de Bob
        EncryptedPacket evil_packet = eve.encrypt_for_peer(plaintext, bob_kem2.public_key);

        try {
            // Bob essaie de déchiffrer en vérifiant la signature de Bob (pas Eve)
            // On s'attend à ce que ça lève une exception — cast explicite pour supprimer le warning nodiscard
            (void)bob.decrypt_from_peer(evil_packet, bob.get_dsa_public_key(), bob_kem2.private_key);
            std::cerr << "[✗] TEST ÉCHOUÉ — La signature invalide n'a pas été rejetée !" << std::endl;
            return EXIT_FAILURE;
        } catch (const SignatureVerificationError& e) {
            std::cout << "[✓] Signature invalide correctement rejetée : " << e.what() << std::endl;
        }

        std::cout << "\n========================================" << std::endl;
        std::cout << "  Tous les tests ont réussi ! 🎉" << std::endl;
        std::cout << "========================================" << std::endl;

        return EXIT_SUCCESS;

    } catch (const std::exception& e) {
        std::cerr << "\n[ERREUR FATALE] " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
