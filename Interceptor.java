import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.ByteArrayInputStream;


public class Interceptor {

    private SecretKey aesKey;
    private PrivateKey ecdsaPrivateKey;
    private X509Certificate clientCert;
    private X509Certificate caCert;

    // 3.7.2 - Compteurs de séquence pour détecter rejeu et suppression
    private long sendCounter     = 0;
    private long expectedCounter = 0;

    // 3.6.3 - Charge la clé privée, le certificat client et le certificat CA au démarrage
    // La clé publique ECDSA est extraite du certificat (plus besoin de client_public.pem)
    public Interceptor(String privateKeyPath, String clientCertPath, String caCertPath) {
        try {
            ecdsaPrivateKey = loadPrivateKey(privateKeyPath);
            clientCert      = loadCertificate(clientCertPath);
            caCert          = loadCertificate(caCertPath);
            System.out.println("[Interceptor] Loaded key, certificate ("
                    + clientCert.getSubjectX500Principal().getName() + "), CA cert.");
        } catch (Exception e) {
            throw new RuntimeException("Failed to load credentials", e);
        }
    }

    // Charge une clé privée ECDSA depuis un fichier PEM (format PKCS8)
    private PrivateKey loadPrivateKey(String path) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        String b64 = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // Charge un certificat X.509 depuis un fichier PEM
    private X509Certificate loadCertificate(String path) throws Exception {
        try (FileInputStream fis = new FileInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(fis);
        }
    }

    // 3.6.4 - Handshake ECDH avec échange de certificats X.509.
    // Format : Base64(ecdh_pubkey)|Base64(certificate_DER)|Base64(signature)
    // Vérifie que le certificat reçu est signé par la CA de confiance,
    // puis vérifie la signature ECDH avec la clé publique du certificat.
    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting ECDH handshake with certificate exchange...");

            // Génération de la paire de clés ECDH éphémère
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair ecdhKeyPair = kpg.generateKeyPair();
            byte[] ecdhPubBytes = ecdhKeyPair.getPublic().getEncoded();

            // Signature de la clé ECDH éphémère avec la clé privée ECDSA long terme
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(ecdsaPrivateKey);
            signer.update(ecdhPubBytes);
            byte[] signature = signer.sign();

            // Envoi : ecdh_pubkey | certificat_DER | signature
            String msg = Base64.getEncoder().encodeToString(ecdhPubBytes) + "|"
                    + Base64.getEncoder().encodeToString(clientCert.getEncoded()) + "|"
                    + Base64.getEncoder().encodeToString(signature);
            output.println(msg);

            // Réception du message de l'autre client
            String[] parts = input.readLine().split("\\|");
            byte[] otherEcdhPubBytes = Base64.getDecoder().decode(parts[0]);
            byte[] otherCertBytes    = Base64.getDecoder().decode(parts[1]);
            byte[] otherSignature    = Base64.getDecoder().decode(parts[2]);

            // Reconstruction et vérification du certificat reçu via la CA de confiance
            X509Certificate otherCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(otherCertBytes));
            otherCert.verify(caCert.getPublicKey());
            otherCert.checkValidity();
            String remoteIdentity = otherCert.getSubjectX500Principal().getName();
            System.out.println("[Interceptor] Certificate valid. Remote identity: " + remoteIdentity);

            // Vérification de la signature ECDH avec la clé publique du certificat
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(otherCert.getPublicKey());
            verifier.update(otherEcdhPubBytes);
            if (!verifier.verify(otherSignature)) {
                throw new IOException("ECDH signature verification failed — possible MitM attack!");
            }
            System.out.println("[Interceptor] ECDH signature verified.");

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

    // 3.3.1 / 3.7.2 - Chiffre le message en AES-256-GCM avec un nonce aléatoire de 12 octets
    // Le numéro de séquence est inclus dans le plaintext avant chiffrement (protégé par GCM)
    // Format transmis : Base64(nonce[12] || ciphertext+tag[16])
    public String beforeSend(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
            String payload = sendCounter + ":" + plainText;
            sendCounter++;
            byte[] ciphertext = cipher.doFinal(payload.getBytes("UTF-8"));

            // Préfixe le nonce au chiffré+tag avant encodage Base64
            byte[] result = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, nonce.length);
            System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    // 3.3.1 / 3.7.2 - Déchiffre un message AES-256-GCM et vérifie le numéro de séquence
    // Rejette le message si le numéro est incorrect (rejeu ou suppression détectés)
    public String afterReceive(String encryptedText) {
        try {
            byte[] data = Base64.getDecoder().decode(encryptedText);
            byte[] nonce = new byte[12];
            byte[] ciphertext = new byte[data.length - 12];
            System.arraycopy(data, 0, nonce, 0, 12);
            System.arraycopy(data, 12, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
            String payload = new String(cipher.doFinal(ciphertext), "UTF-8");

            // Extraction et vérification du numéro de séquence
            int sep = payload.indexOf(':');
            long seqNum = Long.parseLong(payload.substring(0, sep));
            String message = payload.substring(sep + 1);

            if (seqNum != expectedCounter) {
                return "[Alerte sécurité : numéro de séquence attendu " + expectedCounter
                        + ", reçu " + seqNum + " — rejeu ou suppression détecté !]";
            }
            expectedCounter++;
            return message;
        } catch (Exception e) {
            return "[Decryption failed - message may have been tampered: " + e.getMessage() + "]";
        }
    }
}
