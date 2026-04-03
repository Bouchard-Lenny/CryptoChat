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

    // 3.3.1 - Chiffre le message en AES-256-GCM avec un nonce aléatoire de 12 octets
    // Format transmis : Base64(nonce[12] || ciphertext+tag[16])
    public String beforeSend(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
            byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));

            // Préfixe le nonce au chiffré+tag avant encodage Base64
            byte[] result = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, nonce.length);
            System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    // 3.3.1 - Déchiffre un message AES-256-GCM
    // Extrait le nonce (12 premiers octets), vérifie le tag et déchiffre
    // Lève une exception si le message a été modifié (AEADBadTagException)
    public String afterReceive(String encryptedText) {
        try {
            byte[] data = Base64.getDecoder().decode(encryptedText);
            byte[] nonce = new byte[12];
            byte[] ciphertext = new byte[data.length - 12];
            System.arraycopy(data, 0, nonce, 0, 12);
            System.arraycopy(data, 12, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
            return new String(cipher.doFinal(ciphertext), "UTF-8");
        } catch (Exception e) {
            return "[Decryption failed - message may have been tampered: " + e.getMessage() + "]";
        }
    }
}
