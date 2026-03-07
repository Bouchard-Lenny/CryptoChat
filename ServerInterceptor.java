import java.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;


public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] MITM signed-handshake mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {

        // Pendant le handshake signé, chaque client envoie 3 lignes :
        // pubECDH, pubECDSA, signature(pubECDH)
        if (!isSessionKeyReady(fromClient) || !isSessionKeyReady(toClient)) {
            return handleSignedMitmHandshake(message, fromClient, toClient);
        }

        SecretKey keyFrom = getSessionKey(fromClient);
        SecretKey keyTo = getSessionKey(toClient);

        String clear = decryptAesGcmBase64(keyFrom, message);

        if (clear == null) {
            System.out.println("[MITM] Unable to decrypt message from Client " + fromClient);
            return message;
        }

        System.out.println("[MITM] CLEARTEXT from Client " + fromClient + ": " + clear);

        String reEncrypted = encryptAesGcmBase64(keyTo, clear);

        System.out.println("Relaying from " + fromClient + " to client " + toClient);
        return reEncrypted;
    }

    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private final SecureRandom random = new SecureRandom();

    private static class ClientMitmState {
        int handshakeStep = 0;

        String clientEcdhPublicKeyB64;
        String clientEcdsaPublicKeyB64;
        String clientSignatureB64;

        KeyPair mitmEcdhKeyPair;
        KeyPair mitmEcdsaKeyPair;

        String mitmEcdhPublicKeyB64;
        String mitmEcdsaPublicKeyB64;
        String mitmSignatureB64;

        SecretKey sessionKey;
    }

    private final ClientMitmState client1State = new ClientMitmState();
    private final ClientMitmState client2State = new ClientMitmState();

    private ClientMitmState getState(int clientId) {
        return (clientId == 1) ? client1State : client2State;
    }

    private boolean isSessionKeyReady(int clientId) {
        return getState(clientId).sessionKey != null;
    }

    private SecretKey getSessionKey(int clientId) {
        return getState(clientId).sessionKey;
    }

    // Prépare le faux triplet signé que le MITM enverra à un client
    private void ensureMitmHandshakeData(int clientId) {
        try {
            ClientMitmState state = getState(clientId);

            if (state.mitmEcdhKeyPair != null && state.mitmEcdsaKeyPair != null) {
                return;
            }

            KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
            ecGen.initialize(256);

            state.mitmEcdhKeyPair = ecGen.generateKeyPair();
            state.mitmEcdsaKeyPair = ecGen.generateKeyPair();

            byte[] mitmEcdhPublicKeyBytes = state.mitmEcdhKeyPair.getPublic().getEncoded();
            byte[] mitmEcdsaPublicKeyBytes = state.mitmEcdsaKeyPair.getPublic().getEncoded();
            byte[] mitmSignatureBytes = signWithEcdsa(mitmEcdhPublicKeyBytes, state.mitmEcdsaKeyPair);

            state.mitmEcdhPublicKeyB64 = Base64.getEncoder().encodeToString(mitmEcdhPublicKeyBytes);
            state.mitmEcdsaPublicKeyB64 = Base64.getEncoder().encodeToString(mitmEcdsaPublicKeyBytes);
            state.mitmSignatureB64 = Base64.getEncoder().encodeToString(mitmSignatureBytes);

        } catch (Exception e) {
            throw new RuntimeException("MITM handshake preparation failed", e);
        }
    }

    // Signe une clé publique ECDH avec la clé privée ECDSA du MITM
    private byte[] signWithEcdsa(byte[] data, KeyPair ecdsaKeyPair) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(ecdsaKeyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    // Dérive la clé AES MITM <-> client à partir de la clé publique ECDH du client
    private SecretKey deriveSessionKeyFromClientPublicKey(String clientEcdhPublicKeyB64, KeyPair mitmEcdhKeyPair) throws Exception {
        byte[] clientPubBytes = Base64.getDecoder().decode(clientEcdhPublicKeyB64);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubBytes);
        PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mitmEcdhKeyPair.getPrivate());
        ka.doPhase(clientPublicKey, true);

        byte[] sharedSecret = ka.generateSecret();

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(sharedSecret);
        byte[] aesKeyBytes = Arrays.copyOf(hash, 16);

        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    // Intercepte le handshake signé et remplace les 3 lignes par celles du MITM
    private String handleSignedMitmHandshake(String message, int fromClient, int toClient) {
        try {
            ClientMitmState fromState = getState(fromClient);
            ClientMitmState toState = getState(toClient);

            ensureMitmHandshakeData(toClient);

            if (fromState.handshakeStep == 0) {
                fromState.clientEcdhPublicKeyB64 = message;
                fromState.handshakeStep = 1;

                System.out.println("[MITM] Intercepted ECDH public key from Client " + fromClient);
                return toState.mitmEcdhPublicKeyB64;
            }

            if (fromState.handshakeStep == 1) {
                fromState.clientEcdsaPublicKeyB64 = message;
                fromState.handshakeStep = 2;

                System.out.println("[MITM] Intercepted ECDSA public key from Client " + fromClient);
                return toState.mitmEcdsaPublicKeyB64;
            }

            if (fromState.handshakeStep == 2) {
                fromState.clientSignatureB64 = message;
                fromState.handshakeStep = 3;

                fromState.sessionKey = deriveSessionKeyFromClientPublicKey(
                        fromState.clientEcdhPublicKeyB64,
                        fromState.mitmEcdhKeyPair
                );

                System.out.println("[MITM] Intercepted signature from Client " + fromClient);
                System.out.println("[MITM] Session key established with Client " + fromClient);

                return toState.mitmSignatureB64;
            }

            return message;

        } catch (Exception e) {
            throw new RuntimeException("MITM signed handshake failed", e);
        }
    }

    private String decryptAesGcmBase64(SecretKey aesKey, String encryptedB64) {
        try {
            byte[] packet = Base64.getDecoder().decode(encryptedB64);

            if (packet.length < GCM_IV_LENGTH_BYTES + 1) {
                return null;
            }

            byte[] iv = Arrays.copyOfRange(packet, 0, GCM_IV_LENGTH_BYTES);
            byte[] ciphertextAndTag = Arrays.copyOfRange(packet, GCM_IV_LENGTH_BYTES, packet.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] clearBytes = cipher.doFinal(ciphertextAndTag);
            return new String(clearBytes, StandardCharsets.UTF_8);

        } catch (AEADBadTagException e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }

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
            throw new RuntimeException("MITM AES-GCM encryption failed", e);
        }
    }
}