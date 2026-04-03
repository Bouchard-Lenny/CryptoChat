import java.util.Base64;

public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] MitM attack mode (message modification)");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        // 3.3.2 - Attaque de modification : flippe un octet dans le premier bloc chiffré
        // GCM doit détecter la modification via le tag d'authentification
        try {
            byte[] data = Base64.getDecoder().decode(message);
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
