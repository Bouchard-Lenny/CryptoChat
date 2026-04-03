import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Interceptor {

    private SecretKey aesKey;

    // 3.2.1/3.2.2 - Reçoit le mot de passe et dérive une clé AES-256 via SHA-256
    public Interceptor(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(password.getBytes("UTF-8"));
            this.aesKey = new SecretKeySpec(keyBytes, "AES");
            System.out.println("[Interceptor] AES-256 key derived from password.");
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting handshake");

            

            System.out.println("[Interceptor] Handshake complete!");
        } catch (Exception e) {
            throw new IOException("Handshake failed", e);
        }
    }

    // 3.2.3 - Chiffre le message en AES-256-CBC avec un IV aléatoire
    // Format transmis : Base64(IV[16] || ciphertext)
    public String beforeSend(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));

            // Préfixe l'IV au chiffré avant encodage Base64
            byte[] ivAndCipher = new byte[ivBytes.length + ciphertext.length];
            System.arraycopy(ivBytes, 0, ivAndCipher, 0, ivBytes.length);
            System.arraycopy(ciphertext, 0, ivAndCipher, ivBytes.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(ivAndCipher);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    // 3.2.3 - Déchiffre un message AES-256-CBC
    // Extrait l'IV (16 premiers octets) puis déchiffre le reste
    public String afterReceive(String encryptedText) {
        try {
            byte[] ivAndCipher = Base64.getDecoder().decode(encryptedText);
            byte[] ivBytes = new byte[16];
            byte[] ciphertext = new byte[ivAndCipher.length - 16];
            System.arraycopy(ivAndCipher, 0, ivBytes, 0, 16);
            System.arraycopy(ivAndCipher, 16, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(ivBytes));
            return new String(cipher.doFinal(ciphertext), "UTF-8");
        } catch (Exception e) {
            return "[Decryption failed: " + e.getMessage() + "]";
        }
    }
}
