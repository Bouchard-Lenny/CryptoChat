import java.io.*;
import java.net.*;
import java.util.*;

/**
 * Simple Chat Server 
 *
 * This server accepts exactly TWO client connections and facilitates message exchange
 * between them. Messages are transmitted in plain text - students will implement
 * encryption/decryption in the client-side Interceptor class.
 *
 * Architecture:
 * - Main thread accepts incoming connections (max 2)
 * - Each client connection is handled by a separate ClientHandler thread
 * - Messages received from one client are broadcast to the other client
 * - ServerInterceptor can intercept and modify messages (MITM attack simulation)
 *
 * MITM Attack Simulation:
 * The ServerInterceptor allows students to simulate man-in-the-middle attacks
 * to test the robustness of their cryptographic protocol. 
 *
 */
public class Server {

    // Server configuration
    private static final int PORT = 8888;
    private static final int MAX_CLIENTS = 2;

    // List to store all connected client handlers
    private static List<ClientHandler> clients = new ArrayList<>();

    // Server-side interceptor for MITM attack simulation
    // Students can implement various attacks here to test their protocol's security
    private static ServerInterceptor serverInterceptor = new ServerInterceptor();

    /**
     * Main entry point for the server application
     */
    public static void main(String[] args) {
        System.out.println("=== Crypto Chat Server ===");
        System.out.println("Starting server on port " + PORT + "...");

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started successfully!");
            System.out.println("Waiting for " + MAX_CLIENTS + " clients to connect...\n");

            // Accept exactly MAX_CLIENTS connections
            while (clients.size() < MAX_CLIENTS) {
                // Block and wait for a client connection
                Socket clientSocket = serverSocket.accept();

                // Create a new handler for this client
                ClientHandler clientHandler = new ClientHandler(clientSocket, clients.size() + 1);

                // Add to our list of connected clients
                synchronized (clients) {
                    clients.add(clientHandler);
                }

                // Start the handler thread to process messages from this client
                clientHandler.start();

                System.out.println("Client " + clients.size() + " connected from " +
                                   clientSocket.getInetAddress().getHostAddress());

                // Notify when all clients are connected
                if (clients.size() == MAX_CLIENTS) {
                    System.out.println("\nAll clients connected! Chat session can begin.\n");

                    // Send "READY" signal to both clients to synchronize handshake start
                    synchronized (clients) {
                        for (ClientHandler client : clients) {
                            client.sendMessage("READY");
                        }
                    }
                }
            }

            // Keep server running while clients are connected
            System.out.println("Server is now relaying messages between clients...");

        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Broadcasts a message from one client to all other connected clients
     *
     * This method  includes a ServerInterceptor integration point for MITM
     * attack simulation. The interceptor can inspect, modify, or drop messages.
     *
     * @param message The message to broadcast
     * @param sender The ClientHandler that sent the message (will not receive it back)
     */
    public static void broadcastMessage(String message, ClientHandler sender) {
        synchronized (clients) {
            for (ClientHandler client : clients) {
                // Don't send the message back to the sender
                if (client != sender) {
                    // MITM ATTACK SIMULATION: Pass message through ServerInterceptor
                    // The interceptor can:
                    // - Return the message unchanged (honest relay)
                    // - Return a modified message (active attack)
                    // - Return null to drop the message (selective forwarding)
                    String interceptedMessage = serverInterceptor.onMessageRelay(
                        message,
                        sender.getClientId(),
                        client.getClientId()
                    );

                    // Only send the message if the interceptor didn't drop it
                    if (interceptedMessage != null) {
                        client.sendMessage(interceptedMessage);
                    } else {
                        // Message was dropped by the interceptor
                        System.out.println("[Server] Message from Client " +
                            sender.getClientId() + " was dropped by interceptor");
                    }
                }
            }
        }
    }

    /**
     * Removes a client handler from the active clients list
     * Called when a client disconnects
     *
     * @param clientHandler The client handler to remove
     */
    public static void removeClient(ClientHandler clientHandler) {
        synchronized (clients) {
            clients.remove(clientHandler);
            System.out.println("Client " + clientHandler.getClientId() + " disconnected. " +
                             "Active clients: " + clients.size());
        }
    }
}

/**
 * ClientHandler - Handles communication with a single connected client
 *
 * Each client connection runs in its own thread. This class is responsible for:
 * 1. Reading messages from the client
 * 2. Broadcasting received messages to other clients
 * 3. Sending messages to the client
 * 4. Handling disconnections
 */
class ClientHandler extends Thread {

    private Socket socket;
    private int clientId;
    private BufferedReader input;
    private PrintWriter output;
    private volatile boolean running;

    /**
     * Constructor for ClientHandler
     *
     * @param socket The socket connection to the client
     * @param clientId Unique identifier for this client (1 or 2)
     */
    public ClientHandler(Socket socket, int clientId) {
        this.socket = socket;
        this.clientId = clientId;
        this.running = true;

        try {
            // Set up input stream to receive messages from client
            // We use BufferedReader to read line-by-line (messages end with newline)
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Set up output stream to send messages to client
            // autoFlush=true ensures messages are sent immediately
            output = new PrintWriter(socket.getOutputStream(), true);

        } catch (IOException e) {
            System.err.println("Error setting up client " + clientId + ": " + e.getMessage());
        }
    }

    /**
     * Main thread execution - continuously reads messages from the client
     */
    @Override
    public void run() {
        try {
            String message;

            // Continuously read messages until client disconnects or error occurs
            while (running && (message = input.readLine()) != null) {

                // Log the received message (this is the encrypted/modified message)
                System.out.println("[Client " + clientId + " -> Server]: " + message);

                // Broadcast this message to all other connected clients
                // Note: The message is transmitted as-is. Students will implement
                // encryption on the sending side and decryption on the receiving side
                Server.broadcastMessage(message, this);
            }

        } catch (IOException e) {
            System.err.println("Error reading from client " + clientId + ": " + e.getMessage());
        } finally {
            // Clean up when client disconnects
            cleanup();
        }
    }

    /**
     * Sends a message to this client
     * Called by the server when broadcasting messages from other clients
     *
     * @param message The message to send (will be received by client's Interceptor.afterReceive)
     */
    public void sendMessage(String message) {
        if (output != null && !socket.isClosed()) {
            // Log the message being sent
            System.out.println("[Server -> Client " + clientId + "]: " + message);

            // Send the message followed by a newline
            output.println(message);
        }
    }

    /**
     * Gets the unique identifier for this client
     *
     * @return The client ID (1 or 2)
     */
    public int getClientId() {
        return clientId;
    }

    /**
     * Cleanup resources when client disconnects
     * Closes all streams and removes this handler from the active clients list
     */
    private void cleanup() {
        running = false;

        try {
            if (input != null) input.close();
            if (output != null) output.close();
            if (socket != null && !socket.isClosed()) socket.close();
        } catch (IOException e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }

        // Remove this client from the server's active client list
        Server.removeClient(this);
    }
}
