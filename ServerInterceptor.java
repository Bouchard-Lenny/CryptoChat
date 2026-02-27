import java.util.Base64;


public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {

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

        // L'IV fait 12 octets
        int ivLen = 12;

        // Il faut au minimum IV + 1 octet pour pouvoir modifier quelque chose
        if (packet.length <= ivLen) {
            System.out.println("[MITM] Packet too short to tamper.");
            return encryptedB64;
        }

        // On modifie 1 octet juste après l'IV (dans ciphertext||tag)
        int index = ivLen; // premier octet après l'IV
        packet[index] = (byte) (packet[index] ^ 0x01);

        return Base64.getEncoder().encodeToString(packet);
    }
}