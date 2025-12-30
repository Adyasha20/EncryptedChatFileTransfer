import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.DataInputStream;
import java.net.Socket;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public class GUI {

    private JFrame frame;
    private JTextArea statusArea;
    private JTextField ipField, portField;
    private File selectedFile;

    private SecretKey aesKey;          
    private SecretKey sessionAESKey;   
    private byte[] encryptedAES;       

    private final String mode;

    public GUI(String mode) {
        this.mode = mode;

        frame = new JFrame("Encrypted Chat File Transfer — " + mode + " Mode");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        // ===== Generate AES Key =====
        try {
            aesKey = CryptoUtils.generateAESKey();
            System.out.println("AES Key generated successfully.");
        } catch (Exception e) {
            System.out.println("AES Key generation failed: " + e.getMessage());
        }

        // ===== UI Layout =====
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JButton selectFileBtn = new JButton("Select File");
        selectFileBtn.addActionListener(e -> selectFile());
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(selectFileBtn, gbc);

        JButton encryptBtn = new JButton("Encrypt");
        encryptBtn.addActionListener(e -> encryptFile());
        gbc.gridx = 1;
        panel.add(encryptBtn, gbc);

        JButton decryptBtn = new JButton("Decrypt");
        decryptBtn.addActionListener(e -> decryptFile());
        gbc.gridx = 2;
        panel.add(decryptBtn, gbc);

        ipField = new JTextField("127.0.0.1", 10);
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(ipField, gbc);

        portField = new JTextField("5000", 5);
        gbc.gridx = 1;
        panel.add(portField, gbc);

        JButton sendBtn = new JButton("Send");
        sendBtn.addActionListener(e -> sendFile());
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(sendBtn, gbc);

        JButton receiveBtn = new JButton("Receive");
        receiveBtn.addActionListener(e -> receiveFile());
        gbc.gridx = 1;
        panel.add(receiveBtn, gbc);

        statusArea = new JTextArea(10, 40);
        statusArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(statusArea);
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        panel.add(scrollPane, gbc);

        frame.add(panel);

        // ===== Sender-only RSA handling =====
        if (mode.equalsIgnoreCase("Sender")) {
            try {
                appendStatus("Loading receiver public key...");
                PublicKey receiverPublicKey = CryptoUtils.loadPublicKey("keys/public.key");
                appendStatus("Public key loaded successfully.");

                encryptedAES = CryptoUtils.encryptRSA(aesKey.getEncoded(), receiverPublicKey);
                appendStatus("AES key encrypted and ready to send.");
            } catch (Exception e) {
                appendStatus("Sender initialization failed: " + e.getMessage());
            }
        }

        frame.setVisible(true);
    }

    // ================= FILE SELECTION =================
    private void selectFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            selectedFile = chooser.getSelectedFile();
            appendStatus("Selected: " + selectedFile.getAbsolutePath());
            statusArea.setCaretPosition(statusArea.getDocument().getLength());
        }
    }

    // ================= LOCAL ENCRYPT =================
    private void encryptFile() {
        if (selectedFile == null) {
            appendStatus("No file selected.");
            return;
        }
        try {
            File encrypted = CryptoUtils.encryptFileAES(selectedFile, aesKey);
            appendStatus("Encryption successful: " + encrypted.getName());
        } catch (Exception e) {
            appendStatus("Encryption failed: " + e.getMessage());
        }
    }

    // ================= LOCAL DECRYPT =================
    private void decryptFile() {
        if (selectedFile == null) {
            appendStatus("No file selected.");
            return;
        }
        try {
            File decrypted = CryptoUtils.decryptFileAES(selectedFile, aesKey);
            appendStatus("Decryption successful: " + decrypted.getName());
        } catch (Exception e) {
            appendStatus("Decryption failed: " + e.getMessage());
        }
    }

    // ================= SEND =================
    private void sendFile() {
    if (!mode.equalsIgnoreCase("Sender")) {
        appendStatus("Send is only available in Sender mode.");
        return;
    }

    if (selectedFile == null || encryptedAES == null) {
        appendStatus("Missing file or encryption key.");
        return;
    }

    try {
        appendStatus("Encrypting file before sending...");

        // ENCRYPT FIRST
        File encryptedFile = CryptoUtils.encryptFileAES(selectedFile, aesKey);

        appendStatus("Sending encrypted file...");

        // SEND THE .enc FILE
        NetworkUtils.sendEncrypted(
                encryptedFile,
                encryptedAES,
                ipField.getText(),
                Integer.parseInt(portField.getText()),
                statusArea
        );

    } catch (Exception e) {
        appendStatus("Send failed: " + e.getMessage());
    }
}


    // ================= RECEIVE =================
    private void receiveFile() {
        if (!mode.equalsIgnoreCase("Receiver")) {
            appendStatus("Receive is only available in Receiver mode.");
            return;
        }

        appendStatus("Waiting for encrypted key and file...");
        int port = Integer.parseInt(portField.getText());

        Socket socket = NetworkUtils.receiveConnection(port, statusArea);
        if (socket == null) return;

        try {
            DataInputStream dis = new DataInputStream(socket.getInputStream());

            // Receive AES key
            sessionAESKey = NetworkUtils.receiveAESKey(dis, statusArea);
            if (sessionAESKey == null) return;

            // Receive encrypted file
            File encryptedFile = NetworkUtils.receiveFile(dis, statusArea);

            // Receive hash
            byte[] receivedHash = NetworkUtils.receiveFileHash(dis);
            appendStatus("File integrity hash received.");

            // Verify hash
            byte[] localHash = CryptoUtils.generateFileHash(encryptedFile);
            if (!CryptoUtils.verifyHash(receivedHash, localHash)) {
                appendStatus("File integrity check FAILED ❌");
                socket.close();
                return;
            }
            appendStatus("File integrity verified ✅");

            // Receive digital signature
            byte[] signature = NetworkUtils.receiveSignature(dis);

            // Verify digital signature
            PublicKey senderPublicKey = CryptoUtils.loadPublicKey("keys/public.key");
            if (!CryptoUtils.verifySignature(localHash, signature, senderPublicKey)) {
                appendStatus("Digital signature verification FAILED ❌");
                socket.close();
                return;
            }
            appendStatus("Digital signature verified ✅ Sender authenticated");

            // Decrypt file
            File decryptedFile = CryptoUtils.decryptReceivedFile(encryptedFile, sessionAESKey);
            appendStatus("Decrypted file saved as: " + decryptedFile.getName());

            socket.close();

        } catch (Exception e) {
            appendStatus("Receive failed: " + e.getMessage());
        }
    }

    private void appendStatus(String message) {
        statusArea.append(message + "\n");
        statusArea.setCaretPosition(statusArea.getDocument().getLength());
    }
}
