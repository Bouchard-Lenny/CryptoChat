import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.GCMParameterSpec;

import java.util.Arrays;

public class Interceptor {


    // Constructeur sans clé AES.
    // La clé sera générée pendant le handshake ECDH.
    public Interceptor() {
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        System.out.println("[Interceptor] Starting ECDH handshake...");

        try {

            // Génération d'une paire de clés ECDH
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

            // Courbe elliptique secp256r1 (~128 bits de sécurité)
            kpg.initialize(256);

            KeyPair keyPair = kpg.generateKeyPair();

            PublicKey myPublicKey = keyPair.getPublic();

            // Envoi de notre clé publique (encodée en Base64)
            String myPublicKeyB64 = Base64.getEncoder().encodeToString(myPublicKey.getEncoded());
            output.println(myPublicKeyB64);

            System.out.println("[Handshake] Sent public key");

            // Réception de la clé publique distante
            String receivedKeyB64 = input.readLine();

            byte[] receivedKeyBytes = Base64.getDecoder().decode(receivedKeyB64);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedKeyBytes);

            PublicKey otherPublicKey = keyFactory.generatePublic(keySpec);

            System.out.println("[Handshake] Received public key");

            // Calcul du secret partagé ECDH
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(keyPair.getPrivate());

            ka.doPhase(otherPublicKey, true);

            byte[] sharedSecret = ka.generateSecret();

            System.out.println("[Handshake] Shared secret computed");

            // Dérivation de la clé AES à partir du secret partagé
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            byte[] hash = sha256.digest(sharedSecret);

            byte[] aesKeyBytes = Arrays.copyOf(hash, 16);

            aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            System.out.println("[Handshake] AES session key established!");

        } catch (Exception e) {
            throw new IOException("ECDH handshake failed", e);
        }
    }

    public String beforeSend(String plainText) {
        try {
            System.out.println("[Interceptor] Encrypting message (AES-GCM): " + plainText);

            // 1) Génère un IV aléatoire de 12 octets (obligatoire en GCM)
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            random.nextBytes(iv);

            // 2) Initialise AES/GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

            // 3) Chiffre : doFinal renvoie (ciphertext || tag) automatiquement
            byte[] ciphertextAndTag = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // 4) Concatène IV || (ciphertext||tag)
            byte[] packet = new byte[iv.length + ciphertextAndTag.length];
            System.arraycopy(iv, 0, packet, 0, iv.length);
            System.arraycopy(ciphertextAndTag, 0, packet, iv.length, ciphertextAndTag.length);

            // 5) Encode en Base64 pour transport texte
            return Base64.getEncoder().encodeToString(packet);

        } catch (Exception e) {
            throw new RuntimeException("AES-CBC encryption failed", e);
        }

    }

    public String afterReceive(String encryptedText) {
        try {
            System.out.println("[Interceptor] Decrypting message (AES-GCM) ...");

            // 1) Décodage Base64 -> bytes (IV || (ciphertext||tag))
            byte[] packet = Base64.getDecoder().decode(encryptedText);

            // Vérifie qu'on a au moins un IV complet
            if (packet.length < GCM_IV_LENGTH_BYTES) {
                return "[Decryption failed: packet too short]";
            }

            // 2) Sépare IV et (ciphertext||tag)
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            byte[] ciphertextAndTag = new byte[packet.length - GCM_IV_LENGTH_BYTES];

            System.arraycopy(packet, 0, iv, 0, GCM_IV_LENGTH_BYTES);
            System.arraycopy(packet, GCM_IV_LENGTH_BYTES, ciphertextAndTag, 0, ciphertextAndTag.length);

            // 3) Initialise AES/GCM en déchiffrement
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

            // 4) Déchiffre + vérifie le tag
            byte[] clearBytes = cipher.doFinal(ciphertextAndTag);
            return new String(clearBytes, StandardCharsets.UTF_8);

        } catch (AEADBadTagException e) {
            return "[Authentication failed: message altered (GCM tag invalid)]";
        } catch (Exception e) {
            return "[Decryption failed: " + e.getMessage() + "]";
        }
    }
	
	 /**
     * ROT13 encoding/decoding (Caesar cipher with shift of 13)
     * This is NOT secure and is only for initial demonstration.
     * You will replace this with proper cryptographic algorithms.
     *
     * @param text The text to encode/decode
     * @return The ROT13 transformed text
     */
    private String rot13(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    // Clé AES partagée qui sera dérivée après l'échange ECDH
    private SecretKey aesKey;

    // Aléa crypto sûr pour générer un IV différent à chaque message
    private final SecureRandom random = new SecureRandom();

    // Paramètres AES-GCM
    // IV recommandé pour GCM : 12 octets (96 bits)
    private static final int GCM_IV_LENGTH_BYTES = 12;

    // Tag d'authentification GCM : 128 bits (standard)
    private static final int GCM_TAG_LENGTH_BITS = 128;
}
