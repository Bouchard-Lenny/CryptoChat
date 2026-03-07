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


    // Constructeur de l'interceptor.
    // Il reçoit la paire de clés ECDSA long terme du client.
    public Interceptor(PrivateKey ecdsaPrivateKey, PublicKey ecdsaPublicKey) {
        this.ecdsaPrivateKey = ecdsaPrivateKey;
        this.ecdsaPublicKey = ecdsaPublicKey;
    }


    // Signe la clé publique ECDH avec la clé privée ECDSA long terme
    private byte[] signWithEcdsa(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(ecdsaPrivateKey);
        signature.update(data);
        return signature.sign();
    }

    // Vérifie la signature de la clé publique ECDH reçue
    private boolean verifyEcdsaSignature(byte[] data, byte[] signatureBytes, PublicKey signingPublicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(signingPublicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting signed ECDH handshake...");
            System.out.println("[Handshake] Long-term ECDSA keys are loaded");

            // Génère la paire ECDH éphémère de la session
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair ecdhKeyPair = kpg.generateKeyPair();

            PublicKey myEcdhPublicKey = ecdhKeyPair.getPublic();
            byte[] myEcdhPublicKeyBytes = myEcdhPublicKey.getEncoded();

            // Signe la clé publique ECDH avec la clé ECDSA long terme
            byte[] mySignature = signWithEcdsa(myEcdhPublicKeyBytes);

            // Prépare les données à envoyer
            String myEcdhPublicKeyB64 = Base64.getEncoder().encodeToString(myEcdhPublicKeyBytes);
            String myEcdsaPublicKeyB64 = Base64.getEncoder().encodeToString(ecdsaPublicKey.getEncoded());
            String mySignatureB64 = Base64.getEncoder().encodeToString(mySignature);

            // Envoie : pubECDH, pubECDSA, signature(pubECDH)
            output.println(myEcdhPublicKeyB64);
            output.println(myEcdsaPublicKeyB64);
            output.println(mySignatureB64);

            System.out.println("[Handshake] Sent ECDH public key");
            System.out.println("[Handshake] Sent ECDSA public key");
            System.out.println("[Handshake] Sent signature");

            // Reçoit les 3 éléments du pair
            String receivedEcdhPublicKeyB64 = input.readLine();
            String receivedEcdsaPublicKeyB64 = input.readLine();
            String receivedSignatureB64 = input.readLine();

            if (receivedEcdhPublicKeyB64 == null || receivedEcdsaPublicKeyB64 == null || receivedSignatureB64 == null) {
                throw new IOException("Handshake failed: missing signed handshake data");
            }

            byte[] receivedEcdhPublicKeyBytes = Base64.getDecoder().decode(receivedEcdhPublicKeyB64);
            byte[] receivedEcdsaPublicKeyBytes = Base64.getDecoder().decode(receivedEcdsaPublicKeyB64);
            byte[] receivedSignatureBytes = Base64.getDecoder().decode(receivedSignatureB64);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            // Reconstruit la clé publique ECDSA reçue
            X509EncodedKeySpec ecdsaKeySpec = new X509EncodedKeySpec(receivedEcdsaPublicKeyBytes);
            PublicKey receivedEcdsaPublicKey = keyFactory.generatePublic(ecdsaKeySpec);

            System.out.println("[Handshake] Received ECDH public key");
            System.out.println("[Handshake] Received ECDSA public key");
            System.out.println("[Handshake] Received signature");

            // Vérifie que pubECDH a bien été signée avec pubECDSA
            boolean signatureValid = verifyEcdsaSignature(
                    receivedEcdhPublicKeyBytes,
                    receivedSignatureBytes,
                    receivedEcdsaPublicKey
            );

            if (!signatureValid) {
                throw new IOException("Handshake failed: invalid ECDSA signature on ECDH public key");
            }

            System.out.println("[Handshake] Signature is valid");

            // Reconstruit la clé publique ECDH reçue
            X509EncodedKeySpec ecdhKeySpec = new X509EncodedKeySpec(receivedEcdhPublicKeyBytes);
            PublicKey otherEcdhPublicKey = keyFactory.generatePublic(ecdhKeySpec);

            // Calcule le secret partagé ECDH
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(ecdhKeyPair.getPrivate());
            ka.doPhase(otherEcdhPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            System.out.println("[Handshake] Shared secret computed");

            // Dérive la clé AES-128 de session
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(sharedSecret);
            byte[] aesKeyBytes = Arrays.copyOf(hash, 16);
            aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            System.out.println("[Handshake] AES session key established!");
            System.out.println("[Interceptor] Signed ECDH handshake complete!");

        } catch (Exception e) {
            throw new IOException("Signed ECDH handshake failed", e);
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

    // Clé privée ECDSA long terme du client.
    private final PrivateKey ecdsaPrivateKey;

    // Clé publique ECDSA long terme du client.
    private final PublicKey ecdsaPublicKey;
}
