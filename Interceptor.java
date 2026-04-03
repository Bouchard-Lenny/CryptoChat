import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;


public class Interceptor {
    

    public Interceptor() {
        
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting handshake");

            

            System.out.println("[Interceptor] Handshake complete!");
        } catch (Exception e) {
            throw new IOException("Handshake failed", e);
        }
    }

    public String beforeSend(String plainText) {
        try {
           System.out.println("[Interceptor] Encrypting message: " + plainText);
			return rot13(plainText);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String afterReceive(String encryptedText) {
        try {
            System.out.println("[Interceptor] Decrypting message...");
			return rot13(encryptedText);
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
}
