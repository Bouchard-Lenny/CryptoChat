import java.io.*;
import java.net.*;
import java.util.Scanner;


public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8888;

    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private Interceptor interceptor;
    private volatile boolean running;

    public Client() {
        this.interceptor = new Interceptor();
        this.running = true;
    }

    public static void main(String[] args) {
        // Vérifie qu’un mot de passe a bien été fourni
        if (args.length < 1) {
            System.out.println("Usage: java Client <password>");
            return; // stoppe le programme si pas d’argument
        }

        // Récupération du mot de passe fourni en ligne de commande
        String password = args[0];

        // Affichage du mot de passe
        System.out.println("[Client] Password provided: " + password);

        System.out.println("Starting client ...");
        Client client = new Client();
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
