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


public class Interceptor {


    // Constructeur : l'Interceptor doit connaître la clé AES
    public Interceptor(SecretKey aesKey) {
        this.aesKey = aesKey;
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting handshake");

            

            System.out.println("[Interceptor] Handshake complete!");
        } catch (Exception e) {
            throw new IOException("Handshake failed", e);
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

    // Clé AES partagée
    private final SecretKey aesKey;

    // Aléa crypto sûr pour générer un IV différent à chaque message
    private final SecureRandom random = new SecureRandom();

    // Paramètres AES-GCM
    // IV recommandé pour GCM : 12 octets (96 bits)
    private static final int GCM_IV_LENGTH_BYTES = 12;

    // Tag d'authentification GCM : 128 bits (standard)
    private static final int GCM_TAG_LENGTH_BITS = 128;
}
