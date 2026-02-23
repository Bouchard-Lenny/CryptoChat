
public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        // Honest relay - no modification
        // MITM
        // Ici, le trafic est chiffré en ROT13 par les clients, donc l'attaquant
        // peut retrouver le clair en appliquant ROT13 à nouveau.
        String clear = rot13(message);

        // Affichage côté serveur (attaquant) : ce qui circule (cipher) et le clair reconstitué
        System.out.println("[MITM] Intercepted cipher: " + message);
        System.out.println("[MITM] Decrypted clear  : " + clear);

		System.out.println("Relaying from " + fromClient + " to client " + toClient + " : " + message);
        return message;
    }

    // Fonction pour appliquer ROT13 sur une chaîne.
    private static String rot13(String s) {
        // Construire une String caractère par caractère
        StringBuilder out = new StringBuilder(s.length());

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            // Si c'est une lettre minuscule, on la décale de 13 dans l'alphabet
            if (c >= 'a' && c <= 'z') {
                out.append((char) ('a' + (c - 'a' + 13) % 26));

                // Si c'est une lettre majuscule, même principe
            } else if (c >= 'A' && c <= 'Z') {
                out.append((char) ('A' + (c - 'A' + 13) % 26));

                // Sinon (espace, ponctuation, chiffres...), on laisse tel quel
            } else {
                out.append(c);
            }
        }

        return out.toString();
    }
}