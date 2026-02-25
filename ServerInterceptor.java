import java.util.Base64;


public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        // Honest relay - no modification

        /* Etape precedente
        // MITM
        // Ici, le trafic est chiffré en ROT13 par les clients, donc l'attaquant
        // peut retrouver le clair en appliquant ROT13 à nouveau.
        String clear = rot13(message);

        // Affichage côté serveur (attaquant) : ce qui circule (cipher) et le clair reconstitué
        System.out.println("[MITM] Intercepted cipher: " + message);
        System.out.println("[MITM] Decrypted clear  : " + clear);
        */

        // MITM active : modification du message chiffré en transit
        if (ENABLE_TAMPER_ATTACK) {
            System.out.println("[MITM] Tampering ciphertext before relay...");
            message = tamperBase64Ciphertext(message);
        }

		System.out.println("Relaying from " + fromClient + " to client " + toClient + " : " + message);
        return message;
    }

    // Fonction pour appliquer ROT13 sur une chaîne.
    private static String rot13(String s) {
        // Construire une String caractère par caractère
        StringBuilder out = new StringBuilder(s.length());

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            // Si c'est une lettre minuscule, on la décale de 13 dans l'alphabet
            if (c >= 'a' && c <= 'z') {
                out.append((char) ('a' + (c - 'a' + 13) % 26));

                // Si c'est une lettre majuscule, même principe
            } else if (c >= 'A' && c <= 'Z') {
                out.append((char) ('A' + (c - 'A' + 13) % 26));

                // Sinon (espace, ponctuation, chiffres...), on laisse tel quel
            } else {
                out.append(c);
            }
        }

        return out.toString();
    }


    // Active/désactive l'attaque de modification (MITM active)
    private static final boolean ENABLE_TAMPER_ATTACK = true;

     // Modifie un message chiffré encodé en Base64 en flipant 1 bit.
    private static String tamperBase64Ciphertext(String encryptedB64) {
        byte[] packet = Base64.getDecoder().decode(encryptedB64);

        int ivLen = 16;
        int ctLen = packet.length - ivLen;

        // Il faut au minimum 3 blocs ciphertext (48 bytes) pour pouvoir modifier un bloc
        // qui n'est ni le dernier ni l'avant-dernier pour eviter une erreur de padding.
        if (ctLen < 16 * 3) {
            // Message trop court -> si on modifie, on casse souvent le padding.
            System.out.println("[MITM] Ciphertext too short to tamper safely (would hit padding).");
            return encryptedB64;
        }

        // On modifie 1 byte dans le 1er bloc ciphertext
        // on est loin du padding final -> déchiffrement devrait réussir mais plaintext corrompu.
        int index = ivLen + 0; // premier octet du premier bloc ciphertext

        packet[index] = (byte) (packet[index] ^ 0x01);

        return Base64.getEncoder().encodeToString(packet);
    }
}