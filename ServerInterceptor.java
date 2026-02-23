
public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        // Honest relay - no modification
		System.out.println("Relaying from " + fromClient + " to client " + toClient + " : " + message);
        return message;
    }
}
