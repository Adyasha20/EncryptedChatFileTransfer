import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class CryptoUtils {

    // ================= RSA KEY GENERATION =================
    public static void generateRSAKeys(String publicKeyPath, String privateKeyPath) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        try (FileOutputStream pubOut = new FileOutputStream(publicKeyPath);
             FileOutputStream privOut = new FileOutputStream(privateKeyPath)) {

            pubOut.write(pair.getPublic().getEncoded());
            privOut.write(pair.getPrivate().getEncoded());
        }

        System.out.println("RSA Key Pair generated successfully!");
    }

    // ================= AES KEY GENERATION =================
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // ================= RSA ENCRYPT / DECRYPT =================
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // ================= LOAD RSA KEYS =================
    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filePath).toPath());
        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filePath).toPath());
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // ================= FILE ENCRYPTION (AES/CBC + IV) =================
    public static File encryptFileAES(File inputFile, SecretKey secretKey) throws Exception {

        byte[] data = Files.readAllBytes(inputFile.toPath());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(data);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(encrypted);

        File outFile = new File(inputFile.getAbsolutePath() + ".enc");
        Files.write(outFile.toPath(), baos.toByteArray());

        return outFile;
    }

    // ================= FILE DECRYPTION (AES/CBC + IV) =================
    public static File decryptFileAES(File encryptedFile, SecretKey secretKey) throws Exception {

        byte[] all = Files.readAllBytes(encryptedFile.toPath());

        if (all.length < 16) {
            throw new IllegalArgumentException("Invalid encrypted file (missing IV)");
        }

        byte[] iv = Arrays.copyOfRange(all, 0, 16);
        byte[] cipherText = Arrays.copyOfRange(all, 16, all.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] decrypted = cipher.doFinal(cipherText);

        File outFile = new File(
                encryptedFile.getParent(),
                "decrypted_" + encryptedFile.getName().replace(".enc", "")
        );

        Files.write(outFile.toPath(), decrypted);
        return outFile;
    }

    public static File decryptReceivedFile(File encryptedFile, SecretKey secretKey) throws Exception {
        return decryptFileAES(encryptedFile, secretKey);
    }

    // ================= HASH (SHA-256) =================
    public static byte[] generateFileHash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(Files.readAllBytes(file.toPath()));
    }

    public static boolean verifyHash(byte[] h1, byte[] h2) {
        return Arrays.equals(h1, h2);
    }

    // ================= DIGITAL SIGNATURE =================
public static byte[] signHash(byte[] hash, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(hash);
    return signature.sign();
}

public static boolean verifySignature(byte[] hash, byte[] signatureBytes, PublicKey publicKey)
        throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initVerify(publicKey);
    signature.update(hash);
    return signature.verify(signatureBytes);
    }
}
