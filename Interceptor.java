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
        /* Code de base
        try {
           System.out.println("[Interceptor] Encrypting message: " + plainText);
			return rot13(plainText);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }*/

        try {
            System.out.println("[Interceptor] Encrypting message (AES-CBC): " + plainText);

            // 1) Génère un IV aléatoire de 16 bytes (obligatoire en CBC)
            byte[] iv = new byte[AES_BLOCK_SIZE];
            random.nextBytes(iv);

            // 2) Initialise AES/CBC avec padding standard PKCS5Padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

            // 3) Chiffre le message (UTF-8 -> bytes)
            byte[] ciphertext = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // 4) Concatène IV || ciphertext pour permettre le déchiffrement
            byte[] packet = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, packet, 0, iv.length);
            System.arraycopy(ciphertext, 0, packet, iv.length, ciphertext.length);

            // 5) Encode en Base64 pour affichage et transport texte
            return Base64.getEncoder().encodeToString(packet);

        } catch (Exception e) {
            throw new RuntimeException("AES-CBC encryption failed", e);
        }
    }

    public String afterReceive(String encryptedText) {
        /* Code de base
        try {
            System.out.println("[Interceptor] Decrypting message...");
			return rot13(encryptedText);
        } catch (Exception e) {
            return "[Decryption failed: " + e.getMessage() + "]";
        }*/

        try {
            System.out.println("[Interceptor] Decrypting message (AES-CBC) ...");

            // 1) Décodage Base64 -> bytes (IV || ciphertext)
            byte[] packet = Base64.getDecoder().decode(encryptedText);

            // Vérifie qu'on a au moins un IV complet
            if (packet.length < AES_BLOCK_SIZE) {
                return "[Decryption failed: packet too short]";
            }

            // 2) Sépare IV et ciphertext
            byte[] iv = new byte[AES_BLOCK_SIZE];
            byte[] ciphertext = new byte[packet.length - AES_BLOCK_SIZE];

            System.arraycopy(packet, 0, iv, 0, AES_BLOCK_SIZE);
            System.arraycopy(packet, AES_BLOCK_SIZE, ciphertext, 0, ciphertext.length);

            // 3) Initialise le déchiffrement AES/CBC avec le même IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));

            // 4) Déchiffre et reconvertit en String UTF-8
            byte[] clearBytes = cipher.doFinal(ciphertext);
            return new String(clearBytes, StandardCharsets.UTF_8);

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

    // AES utilise un bloc de 16 octets -> IV de 16 octets en CBC
    private static final int AES_BLOCK_SIZE = 16;
}
