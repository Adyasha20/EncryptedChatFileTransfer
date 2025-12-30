import javax.swing.*;

public class Main {
    public static void main(String[] args) {

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
                new GUI("Sender");
            } else if (choice == 1) {

                try {
                    CryptoUtils.generateRSAKeys("keys/public.key", "keys/private.key");
                    System.out.println("Receiver RSA keys created.");
                } catch (Exception e) {
                    System.out.println("Key generation failed: " + e.getMessage());
                }

                new GUI("Receiver");
            } else {
                System.exit(0);
            }
        });
    }
}
