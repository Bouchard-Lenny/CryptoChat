import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Interceptor {

    private SecretKey aesKey;

    public Interceptor() {}

    // 3.4.1 - Échange de clé ECDH éphémère :
    // Génère une paire de clés EC, envoie la clé publique, reçoit celle de l'autre client,
    // calcule le secret partagé et en dérive la clé AES-256 via SHA-256.
    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting ECDH handshake...");

            // Génération de la paire de clés éphémère sur la courbe P-256
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = kpg.generateKeyPair();

            // Envoi de la clé publique (encodage X.509, Base64)
            String pubKeyB64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            output.println(pubKeyB64);

            // Réception de la clé publique de l'autre client
            String otherPubKeyB64 = input.readLine();
            byte[] otherPubKeyBytes = Base64.getDecoder().decode(otherPubKeyB64);
            PublicKey otherPublicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(otherPubKeyBytes));

            // Calcul du secret partagé ECDH
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(otherPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // Dérivation de la clé AES-256 via SHA-256 sur le secret partagé
            byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
            this.aesKey = new SecretKeySpec(keyBytes, "AES");

            System.out.println("[Interceptor] ECDH handshake complete. AES-256 session key derived.");
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
