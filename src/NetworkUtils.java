import javax.swing.*;
import java.io.*;
import java.net.*;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class NetworkUtils {

    // ===================== SEND FILE WITH AES KEY =====================
    public static void sendEncrypted(File file, byte[] encryptedAESKey,
                                     String ip, int port, JTextArea statusArea) {

        try (Socket socket = new Socket(ip, port);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             FileInputStream fis = new FileInputStream(file)) {

            statusArea.append("Connected to receiver...\n");

            // Send encrypted AES key
            out.writeInt(encryptedAESKey.length);
            out.write(encryptedAESKey);
            statusArea.append("Encrypted AES key sent.\n");

            // Send file name
            out.writeUTF(file.getName());

            // Send file size
            out.writeLong(file.length());

            // Send file bytes
            byte[] buffer = new byte[4096];
            int bytesRead;
            long remaining = file.length();

            while (remaining > 0 &&
                   (bytesRead = fis.read(buffer, 0,
                           (int) Math.min(buffer.length, remaining))) != -1) {

                out.write(buffer, 0, bytesRead);
                remaining -= bytesRead;
            }

            statusArea.append("File sent successfully.\n");

            // Send SHA-256 hash
            byte[] hash = CryptoUtils.generateFileHash(file);
            out.writeInt(hash.length);
            out.write(hash);
            statusArea.append("File integrity hash sent.\n");

            //DIGITAL SIGNATURE 
            PrivateKey senderPrivateKey = CryptoUtils.loadPrivateKey("keys/private.key");
            byte[] signature = CryptoUtils.signHash(hash, senderPrivateKey);

            out.writeInt(signature.length);
            out.write(signature);
            statusArea.append("Digital signature sent.\n");

        } catch (Exception e) {
            statusArea.append("Send failed: " + e.getMessage() + "\n");
        }
    }

    // ===================== RECEIVE CONNECTION =====================
    public static Socket receiveConnection(int port, JTextArea statusArea) {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            Socket socket = serverSocket.accept();
            statusArea.append("Receiver connected.\n");
            return socket;
        } catch (Exception e) {
            statusArea.append("Connection failed: " + e.getMessage() + "\n");
            return null;
        }
    }

    // ===================== RECEIVE AES KEY =====================
    public static SecretKey receiveAESKey(DataInputStream dis, JTextArea statusArea) {
        try {
            int keyLength = dis.readInt();
            byte[] encryptedKey = new byte[keyLength];
            dis.readFully(encryptedKey);

            statusArea.append("Encrypted AES key received.\n");

            PrivateKey privateKey = CryptoUtils.loadPrivateKey("keys/private.key");
            byte[] decrypted = CryptoUtils.decryptRSA(encryptedKey, privateKey);

            SecretKey aesKey = new SecretKeySpec(decrypted, "AES");
            statusArea.append("AES key decrypted successfully.\n");

            return aesKey;

        } catch (Exception e) {
            statusArea.append("AES key receive failed: " + e.getMessage() + "\n");
            return null;
        }
    }

    // ===================== RECEIVE FILE =====================
    public static File receiveFile(DataInputStream dis, JTextArea statusArea) {
        try {
            // 1️⃣ Read file name
            String fileName = dis.readUTF();

            // 2️⃣ Read file size
            long fileSize = dis.readLong();

            File outputFile = new File("received_" + fileName);
            FileOutputStream fos = new FileOutputStream(outputFile);

            // 3️⃣ Read exact file bytes
            byte[] buffer = new byte[4096];
            long remaining = fileSize;

            while (remaining > 0) {
                int read = dis.read(buffer, 0,
                        (int) Math.min(buffer.length, remaining));
                if (read == -1)
                    throw new EOFException("Unexpected end of stream");

                fos.write(buffer, 0, read);
                remaining -= read;
            }

            fos.close();
            statusArea.append("File received: " + outputFile.getAbsolutePath() + "\n");
            return outputFile;

        } catch (Exception e) {
            statusArea.append("File receive failed: " + e.getMessage() + "\n");
            return null;
        }
    }

    // ===================== RECEIVE FILE HASH =====================
    public static byte[] receiveFileHash(DataInputStream dis) throws Exception {
        int hashLength = dis.readInt();
        byte[] hash = new byte[hashLength];
        dis.readFully(hash);
        return hash;
    }

    // ===================== RECEIVE DIGITAL SIGNATURE =====================
    public static byte[] receiveSignature(DataInputStream dis) throws Exception {
        int sigLength = dis.readInt();
        byte[] signature = new byte[sigLength];
        dis.readFully(signature);
        return signature;
    }
}
