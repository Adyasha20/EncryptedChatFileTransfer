import javax.swing.*;
import java.io.File;

public class Main {
    public static void main(String[] args) {
        // AUTO-FIX: Create keys directory immediately on startup
        ensureKeyDirectoryExists();

        SwingUtilities.invokeLater(() -> {
            String[] options = {"Sender", "Receiver"};
            int choice = JOptionPane.showOptionDialog(
                    null,
                    "Choose mode to start:",
                    "Start Mode",
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.INFORMATION_MESSAGE,
                    null,
                    options,
                    options[0]
            );

            if (choice == 0) {
                // SENDER MODE
                ensureSenderKeysExist(); // Ensure sender has keys to sign files
                new GUI("Sender");
            } else if (choice == 1) {
                // RECEIVER MODE
                try {
                    // Generate keys for the receiver if they don't exist
                    CryptoUtils.generateRSAKeys("keys/public.key", "keys/private.key");
                    System.out.println("Receiver RSA keys initialized in /keys folder.");
                } catch (Exception e) {
                    System.out.println("Key generation failed: " + e.getMessage());
                }
                new GUI("Receiver");
            } else {
                System.exit(0);
            }
        });
    }

    private static void ensureKeyDirectoryExists() {
        File folder = new File("keys");
        if (!folder.exists()) {
            if (folder.mkdir()) {
                System.out.println("Created missing 'keys' directory.");
            }
        }
    }

    private static void ensureSenderKeysExist() {
        File pub = new File("keys/public.key");
        File priv = new File("keys/private.key");
        if (!pub.exists() || !priv.exists()) {
            try {
                CryptoUtils.generateRSAKeys("keys/public.key", "keys/private.key");
                System.out.println("Sender keys generated for digital signature.");
            } catch (Exception e) {
                System.err.println("Could not initialize sender keys: " + e.getMessage());
            }
        }
    }
}