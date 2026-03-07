import java.io.*;
import java.net.*;
import java.util.Scanner;

import java.security.*;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8888;

    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private Interceptor interceptor;
    private volatile boolean running;

    // Clé privée ECDSA long terme du client.
    private PrivateKey ecdsaPrivateKey;

    // Clé publique ECDSA long terme du client.
    private PublicKey ecdsaPublicKey;


     /* Dérive une clé AES-128 à partir d'un mot de passe en utilisant SHA-256.
     - SHA-256 produit 32 octets (256 bits)
     - AES-128 nécessite 16 octets (128 bits) -> on tronque à 16 octets */
    private static SecretKey deriveAesKey(String password) throws NoSuchAlgorithmException {

        // Fournit l'implémentation de la fonction de hachage SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // On transforme le mot de passe (String) en octets, puis on calcule son hash (32 bytes)
        byte[] fullHash = sha256.digest(password.getBytes());

        // AES-128 nécessite exactement 16 bytes -> on prend les 16 premiers octets du hash
        byte[] aesKeyBytes = Arrays.copyOf(fullHash, 16);

        // On construit un objet "SecretKey" compatible AES à partir des 16 octets
        return new SecretKeySpec(aesKeyBytes, "AES");
    }


    // Charge une clé privée ECDSA au format PEM (PKCS8) depuis un fichier.
    private static PrivateKey loadPrivateKeyFromPem(String path) throws Exception {
        // Lit tout le contenu texte du fichier PEM
        String pem = Files.readString(Paths.get(path));

        // Supprime l'en-tête, le pied de page et les retours à la ligne
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        // Décode la partie Base64 du PEM
        byte[] keyBytes = Base64.getDecoder().decode(pem);

        // Construit une clé privée EC à partir des octets
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        // PKCS8 = format standard courant pour les clés privées
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        return keyFactory.generatePrivate(keySpec);
    }

     // Charge une clé publique ECDSA au format PEM (X.509 / SubjectPublicKeyInfo).
    private static PublicKey loadPublicKeyFromPem(String path) throws Exception {
        // Lit tout le contenu texte du fichier PEM
        String pem = Files.readString(Paths.get(path));

        // Supprime l'en-tête, le pied de page et les espaces
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        // Décode la partie Base64
        byte[] keyBytes = Base64.getDecoder().decode(pem);

        // Reconstruit la clé publique EC
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        // X509EncodedKeySpec = format standard des clés publiques
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        return keyFactory.generatePublic(keySpec);
    }


    public Client(String privateKeyPath, String publicKeyPath) {
        try {
            // Charge la clé privée ECDSA du client depuis le fichier PEM
            this.ecdsaPrivateKey = loadPrivateKeyFromPem(privateKeyPath);

            // Charge la clé publique ECDSA du client depuis le fichier PEM
            this.ecdsaPublicKey = loadPublicKeyFromPem(publicKeyPath);

            System.out.println("[Client] ECDSA private key loaded successfully");
            System.out.println("[Client] ECDSA public key loaded successfully");

            // L'interceptor reçoit maintenant les clés ECDSA long terme.
            this.interceptor = new Interceptor(ecdsaPrivateKey, ecdsaPublicKey);

            this.running = true;

        } catch (Exception e) {
            throw new RuntimeException("Failed to load ECDSA key pair", e);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {

        // Le client doit recevoir en paramètre :
        // - le chemin vers sa clé privée ECDSA long terme
        // - le chemin vers sa clé publique ECDSA long terme
        if (args.length < 2) {
            System.out.println("Usage: java Client <ecdsa_private_key.pem> <ecdsa_public_key.pem>");
            return;
        }

        String privateKeyPath = args[0];
        String publicKeyPath = args[1];

        Client client = new Client(privateKeyPath, publicKeyPath);

        System.out.println("[Client] ECDSA key pair provided via command line");


        System.out.println("Starting client ...");
        client.start();
    }

    public void start() {
        System.out.println("=== Crypto Chat Client ===");
        System.out.println("Connecting to server at " + SERVER_HOST + ":" + SERVER_PORT + "...");

        try {
            socket = new Socket(SERVER_HOST, SERVER_PORT);
            System.out.println("Connected to server successfully!\n");

            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            output = new PrintWriter(socket.getOutputStream(), true);

            // Wait for server's READY signal (sent when both clients are connected)
            System.out.println("Waiting for other client to connect...");
            String readySignal = input.readLine();
            if (!"READY".equals(readySignal)) {
                throw new IOException("Expected READY signal, got: " + readySignal);
            }
            System.out.println("Both clients connected!\n");

            System.out.println("--- Handshake Phase ---");
            interceptor.onHandshake(input, output);
            System.out.println("--- Handshake Complete ---\n");

            System.out.println("Chat session started!");
            System.out.println("Type your messages and press Enter to send.");
            System.out.println("Type 'exit' to quit.\n");

            Thread receiverThread = new Thread(new MessageReceiver());
            receiverThread.start();

            handleUserInput();

        } catch (IOException e) {
            System.err.println("Connection error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }

    private void handleUserInput() {
        Scanner scanner = new Scanner(System.in);

        try {
            while (running) {
                String message = scanner.nextLine();

                if (message.equalsIgnoreCase("exit")) {
                    System.out.println("Disconnecting...");
                    running = false;
                    break;
                }

                if (message.trim().isEmpty()) {
                    continue;
                }

                String processedMessage = interceptor.beforeSend(message);
                output.println(processedMessage);
                System.out.println("You: " + message);
            }
        } finally {
            scanner.close();
        }
    }

    private void cleanup() {
        running = false;

        try {
            if (input != null) input.close();
            if (output != null) output.close();
            if (socket != null && !socket.isClosed()) socket.close();
        } catch (IOException e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }

        System.out.println("Disconnected from server.");
    }

    private class MessageReceiver implements Runnable {
        @Override
        public void run() {
            try {
                String receivedMessage;

                while (running && (receivedMessage = input.readLine()) != null) {
                    String decryptedMessage = interceptor.afterReceive(receivedMessage);
                    System.out.println("Other: " + decryptedMessage);
                }

            } catch (IOException e) {
                if (running) {
                    System.err.println("Error receiving message: " + e.getMessage());
                }
            }
        }
    }
}
