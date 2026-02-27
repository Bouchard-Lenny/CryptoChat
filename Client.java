import java.io.*;
import java.net.*;
import java.util.Scanner;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8888;

    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private Interceptor interceptor;
    private volatile boolean running;


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

    public Client(String password) {
        try {
            // Dérive la clé AES-128 à partir du mot de passe
            javax.crypto.SecretKey aesKey = deriveAesKey(password);
            // Debug (preuve que la clé existe) : AES-128 -> 16 bytes
            System.out.println("[Client] AES key length: " + aesKey.getEncoded().length + " bytes");

            // Interceptor utilise AES-GCM + Base64
            this.interceptor = new Interceptor(aesKey);

            this.running = true;
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 est censé exister ; si ça arrive, on arrête avec une erreur claire
            throw new RuntimeException("SHA-256 not available on this JVM", e);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // Vérifie qu’un mot de passe a bien été fourni
        if (args.length < 1) {
            System.out.println("Usage: java Client <password>");
            return; // stoppe le programme si pas d’argument
        }

        // Récupération du mot de passe fourni en ligne de commande
        String password = args[0];

        Client client = new Client(password);

        // Affichage du mot de passe
        System.out.println("[Client] Password provided: " + password);

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
