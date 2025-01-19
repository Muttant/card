import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class AESCFBExample {

    public static void main(String[] args) throws Exception {
        // Tạo khóa AES 128-bit
        SecretKey secretKey = generateAESKey();

        // Tạo IV (Initialization Vector) ngẫu nhiên
        IvParameterSpec iv = generateIV();

        // Dữ liệu cần mã hóa
        String plaintext = "This is a secret message.";

        // Mã hóa dữ liệu
        String ciphertext = encrypt(plaintext, secretKey, iv);
        System.out.println("Encrypted text: " + ciphertext);

        // Giải mã dữ liệu
        String decryptedText = decrypt(ciphertext, secretKey, iv);
        System.out.println("Decrypted text: " + decryptedText);
    }

    // Tạo khóa AES 128-bit
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // Sử dụng AES-128
        return keyGenerator.generateKey();
    }

    // Tạo IV (Initialization Vector) ngẫu nhiên
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16]; // Độ dài IV 128-bit (16 byte)
        // Sinh giá trị ngẫu nhiên cho IV
        new java.security.SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Mã hóa dữ liệu
    public static String encrypt(String plaintext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        // Chuyển mã hóa sang Base64 để dễ hiển thị
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Giải mã dữ liệu
    public static String decrypt(String ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] decodedCiphertext = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(decodedCiphertext);

        return new String(decryptedBytes);
    }
}
