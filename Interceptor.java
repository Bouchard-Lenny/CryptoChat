import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Interceptor {

    private SecretKey aesKey;
    private PrivateKey ecdsaPrivateKey;
    private PublicKey ecdsaPublicKey;

    // 3.5.1 - Charge la paire de clés ECDSA long terme depuis les fichiers PEM
    public Interceptor(String privateKeyPath, String publicKeyPath) {
        try {
            ecdsaPrivateKey = loadPrivateKey(privateKeyPath);
            ecdsaPublicKey  = loadPublicKey(publicKeyPath);
            System.out.println("[Interceptor] ECDSA long-term key pair loaded.");
        } catch (Exception e) {
            throw new RuntimeException("Failed to load ECDSA keys", e);
        }
    }

    // Charge une clé privée ECDSA depuis un fichier PEM (format PKCS8)
    private PrivateKey loadPrivateKey(String path) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        String b64 = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // Charge une clé publique ECDSA depuis un fichier PEM (format X.509)
    private PublicKey loadPublicKey(String path) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        String b64 = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    // 3.5.2 - Handshake ECDH avec signature ECDSA de la clé publique éphémère.
    // Format envoyé : Base64(ecdh_pubkey)|Base64(ecdsa_pubkey)|Base64(signature)
    // La signature porte sur les octets de la clé publique ECDH (SHA256withECDSA).
    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting ECDH handshake with ECDSA signature...");

            // Génération de la paire de clés ECDH éphémère
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair ecdhKeyPair = kpg.generateKeyPair();
            byte[] ecdhPubBytes = ecdhKeyPair.getPublic().getEncoded();

            // Signature de la clé publique ECDH avec la clé privée ECDSA long terme
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(ecdsaPrivateKey);
            signer.update(ecdhPubBytes);
            byte[] signature = signer.sign();

            // Envoi : ecdh_pubkey | ecdsa_pubkey | signature
            String message = Base64.getEncoder().encodeToString(ecdhPubBytes) + "|"
                    + Base64.getEncoder().encodeToString(ecdsaPublicKey.getEncoded()) + "|"
                    + Base64.getEncoder().encodeToString(signature);
            output.println(message);

            // Réception du message de l'autre client
            String[] parts = input.readLine().split("\\|");
            byte[] otherEcdhPubBytes  = Base64.getDecoder().decode(parts[0]);
            byte[] otherEcdsaPubBytes = Base64.getDecoder().decode(parts[1]);
            byte[] otherSignature     = Base64.getDecoder().decode(parts[2]);

            // Vérification de la signature ECDSA sur la clé ECDH reçue
            PublicKey otherEcdsaKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(otherEcdsaPubBytes));
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(otherEcdsaKey);
            verifier.update(otherEcdhPubBytes);
            if (!verifier.verify(otherSignature)) {
                throw new IOException("ECDSA signature verification failed — possible MitM attack!");
            }
            System.out.println("[Interceptor] ECDSA signature verified.");

            // Calcul du secret partagé ECDH et dérivation de la clé AES-256
            PublicKey otherEcdhKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(otherEcdhPubBytes));
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(ecdhKeyPair.getPrivate());
            ka.doPhase(otherEcdhKey, true);
            byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(ka.generateSecret());
            this.aesKey = new SecretKeySpec(keyBytes, "AES");

            System.out.println("[Interceptor] ECDH handshake complete. AES-256 session key derived.");
        } catch (IOException e) {
            throw e;
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
