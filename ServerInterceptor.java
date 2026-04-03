import java.util.Base64;

public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] MitM attack mode (message modification)");
    }

    // 3.2.4 - Attaque de modification : flippe un octet dans le premier bloc chiffré
    // (octets 16-31, après l'IV). Montre l'absence d'intégrité sans AEAD.
    public String onMessageRelay(String message, int fromClient, int toClient) {
        try {
            byte[] data = Base64.getDecoder().decode(message);
            // L'IV occupe les 16 premiers octets, on modifie l'octet 16 (1er bloc chiffré)
            if (data.length > 17) {
                data[16] ^= 0xFF;
                System.out.println("[MitM] Modified byte 16 of ciphertext (Client "
                        + fromClient + " -> Client " + toClient + ")");
                return Base64.getEncoder().encodeToString(data);
            }
        } catch (Exception e) {
            System.out.println("[MitM] Could not modify message: " + e.getMessage());
        }
        return message;
    }
}
