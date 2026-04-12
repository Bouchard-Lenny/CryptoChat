import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServerInterceptor {

    // Clés ECDH éphémères de l'attaquant (une paire par client)
    private Map<Integer, KeyPair> attackerECDHPairs = new HashMap<>();
    // Clés ECDSA éphémères de l'attaquant (une paire par client, pour signer vers l'autre)
    private Map<Integer, KeyPair> attackerECDSAPairs = new HashMap<>();
    // Vraies clés ECDH publiques des clients (interceptées)
    private Map<Integer, PublicKey> clientRealECDHKeys = new HashMap<>();
    // Clés AES de session dérivées par l'attaquant
    private Map<Integer, SecretKey> sessionKeys = new HashMap<>();
    private int keysReceived = 0;

    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    // 3.6.5 - Attaque MitM réactivée : l'attaquant substitue ses propres clés
    // mais ne peut pas produire un certificat signé par la CA de confiance → détecté
    public String onMessageRelay(String message, int fromClient, int toClient) {
        if (keysReceived < 2) {
            return interceptHandshake(message, fromClient, toClient);
        } else {
            return interceptMessage(message, fromClient, toClient);
        }
    }

    // 3.5.3 - Substitue les clés ECDH et ECDSA de l'attaquant à celles du vrai client.
    // La signature est valide car signée par la clé ECDSA de l'attaquant elle-même.
    // Le client destinataire ne peut pas détecter la fraude sans certificat.
    private String interceptHandshake(String message, int fromClient, int toClient) {
        try {
            String[] parts = message.split("\\|");
            byte[] realECDHPubBytes = Base64.getDecoder().decode(parts[0]);
            PublicKey realECDHKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(realECDHPubBytes));
            clientRealECDHKeys.put(fromClient, realECDHKey);

            // Génère une paire ECDH éphémère de l'attaquant pour ce client
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair attackerECDH = kpg.generateKeyPair();
            attackerECDHPairs.put(fromClient, attackerECDH);

            // Génère une paire ECDSA éphémère de l'attaquant pour signer vers le destinataire
            KeyPair attackerECDSA = kpg.generateKeyPair();
            attackerECDSAPairs.put(fromClient, attackerECDSA);

            // Signe la clé ECDH de l'attaquant avec sa propre clé ECDSA
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(attackerECDSA.getPrivate());
            signer.update(attackerECDH.getPublic().getEncoded());
            byte[] fakeSignature = signer.sign();

            keysReceived++;

            if (keysReceived == 2) {
                // Dérive les clés de session avec chaque client (même logique que 3.4.2)
                for (int clientId : clientRealECDHKeys.keySet()) {
                    int otherClientId = (clientId == 1) ? 2 : 1;
                    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                    ka.init(attackerECDHPairs.get(otherClientId).getPrivate());
                    ka.doPhase(clientRealECDHKeys.get(clientId), true);
                    byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(ka.generateSecret());
                    sessionKeys.put(clientId, new SecretKeySpec(keyBytes, "AES"));
                }
                System.out.println("[MitM] ECDH+ECDSA interception complete. Session keys derived.");
            }

            // Renvoie les clés de l'attaquant avec une signature valide (mais frauduleuse)
            return Base64.getEncoder().encodeToString(attackerECDH.getPublic().getEncoded()) + "|"
                    + Base64.getEncoder().encodeToString(attackerECDSA.getPublic().getEncoded()) + "|"
                    + Base64.getEncoder().encodeToString(fakeSignature);

        } catch (Exception e) {
            System.out.println("[MitM] Handshake interception failed: " + e.getMessage());
            return message;
        }
    }

    // Déchiffre avec la clé du client émetteur, affiche le plaintext,
    // réencrypte avec la clé du client destinataire
    private String interceptMessage(String message, int fromClient, int toClient) {
        try {
            byte[] data = Base64.getDecoder().decode(message);
            byte[] nonce = Arrays.copyOfRange(data, 0, 12);
            byte[] ciphertext = Arrays.copyOfRange(data, 12, data.length);

            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, sessionKeys.get(fromClient), new GCMParameterSpec(128, nonce));
            byte[] plaintext = dec.doFinal(ciphertext);
            System.out.println("[MitM] Client " + fromClient + " -> Client " + toClient
                    + " : " + new String(plaintext, "UTF-8"));

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
