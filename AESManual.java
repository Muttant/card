import java.security.SecureRandom;
import java.util.Arrays;

public class AESManual {
    // S-box AES
    private static final byte[][] S_BOX = new byte[][] {
        { (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B, (byte) 0x6F, (byte) 0xC5 },
        { (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B, (byte) 0xFE, (byte) 0xD7, (byte) 0xAB, (byte) 0x76 },
        { (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59, (byte) 0x47, (byte) 0xF0 },
        { (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF, (byte) 0x9C, (byte) 0xA8, (byte) 0x51, (byte) 0xA3 },
        { (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D, (byte) 0x38, (byte) 0xF5, (byte) 0xBC, (byte) 0xB6 },
        { (byte) 0xDA, (byte) 0x21, (byte) 0x10, (byte) 0xFF, (byte) 0xF3, (byte) 0xD2, (byte) 0xCD, (byte) 0x0C },
        { (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xC4, (byte) 0xA7 },
        { (byte) 0x7E, (byte) 0x3D, (byte) 0x64, (byte) 0x5D, (byte) 0x19, (byte) 0x73, (byte) 0x60, (byte) 0x81 },
        { (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xEE },
        { (byte) 0xB8, (byte) 0x14, (byte) 0xDE, (byte) 0x5E, (byte) 0x0B, (byte) 0xDB, (byte) 0xE0, (byte) 0x32 },
        { (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5C, (byte) 0xC2, (byte) 0xD3 },
        { (byte) 0xAC, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xE4, (byte) 0x79, (byte) 0xE7, (byte) 0xC8 },
        { (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5, (byte) 0x4E, (byte) 0xA9, (byte) 0x6C, (byte) 0x56 },
        { (byte) 0xF4, (byte) 0xEA, (byte) 0x65, (byte) 0x7A, (byte) 0xAE, (byte) 0x08, (byte) 0xBA, (byte) 0x78 },
        { (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6, (byte) 0xB4, (byte) 0xC6, (byte) 0xE8, (byte) 0xDD },
        { (byte) 0x74, (byte) 0x1F, (byte) 0x4B, (byte) 0xBD, (byte) 0x8B, (byte) 0x8A, (byte) 0x70, (byte) 0x3E },
        { (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xF6, (byte) 0x0E, (byte) 0x61, (byte) 0x35 },
        { (byte) 0x57, (byte) 0xB9, (byte) 0x86, (byte) 0xC3, (byte) 0x1D, (byte) 0x9E, (byte) 0xE1, (byte) 0xF8 },
        { (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9, (byte) 0x8E, (byte) 0x94, (byte) 0x9B, (byte) 0x1E },
        { (byte) 0x87, (byte) 0xE9, (byte) 0xCE, (byte) 0x55, (byte) 0x28, (byte) 0xDF, (byte) 0x8C, (byte) 0xA1 },
        { (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99 },
        { (byte) 0x2D, (byte) 0x0F, (byte) 0xB0, (byte) 0x54, (byte) 0xBB, (byte) 0x16, (byte) 0x3C, (byte) 0xBB }
    };

    // Khối 4x4
    private static final int BLOCK_SIZE = 16;

    public static void main(String[] args) throws Exception {
        byte[] key = generateAESKey();  // Khóa AES 128-bit ngẫu nhiên
        byte[] iv = generateIV();  // IV ngẫu nhiên

        String plaintext = "This is a secret message.";
        byte[] plaintextBytes = plaintext.getBytes();

        // Mã hóa và giải mã
        byte[] ciphertext = encryptAES(plaintextBytes, key);
        System.out.println("Encrypted: " + bytesToHex(ciphertext));

        byte[] decrypted = decryptAES(ciphertext, key);
        System.out.println("Decrypted: " + new String(decrypted));
    }

    // Sinh khóa AES ngẫu nhiên (128-bit)
    public static byte[] generateAESKey() {
        byte[] key = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(key);
        return key;
    }

    // Sinh IV ngẫu nhiên (128-bit)
    public static byte[] generateIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Chuyển đổi mảng byte thành chuỗi hex (để hiển thị)
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Mã hóa AES thủ công
    public static byte[] encryptAES(byte[] input, byte[] key) {
        byte[][] state = new byte[4][4];

        // Chuyển đổi dữ liệu đầu vào thành ma trận 4x4
        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = input[i];
        }

        // Tạo khóa cho các vòng
        byte[] roundKey = Arrays.copyOf(key, BLOCK_SIZE);

        // Vòng 0: AddRoundKey
        state = addRoundKey(state, roundKey);

        // Các vòng AES (9 vòng đối với AES-128)
        for (int round = 1; round < 10; round++) {
            state = subBytes(state);  // Thay thế các byte bằng S-box
            state = shiftRows(state);  // Dịch các hàng
            state = mixColumns(state);  // Trộn các cột
            roundKey = generateRoundKey(round, key);  // Sinh khóa cho vòng tiếp theo
            state = addRoundKey(state, roundKey);  // XOR với khóa vòng
        }

        // Vòng cuối cùng (không có MixColumns)
        state = subBytes(state);
        state = shiftRows(state);
        roundKey = generateRoundKey(10, key);  // Khóa vòng cuối cùng
        state = addRoundKey(state, roundKey);

        // Chuyển đổi ma trận 4x4 thành mảng byte để trả về
        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++) {
            output[i] = state[i % 4][i / 4];
        }
        return output;
    }

    // Giải mã AES thủ công (ngược lại với mã hóa)
    public static byte[] decryptAES(byte[] input, byte[] key) {
        // Thực hiện giải mã theo nguyên lý tương tự như mã hóa, nhưng đảo ngược các phép toán
        byte[][] state = new byte[4][4];

        // Chuyển đổi dữ liệu đầu vào thành ma trận 4x4
        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = input[i];
        }

        byte[] roundKey = Arrays.copyOf(key, BLOCK_SIZE);

        // Vòng 0: AddRoundKey
        state = addRoundKey(state, roundKey);

        // Các vòng AES (9 vòng đối với AES-128)
        for (int round = 1; round < 10; round++) {
            state = invSubBytes(state);  // Thay thế các byte ngược bằng S-box
            state = invShiftRows(state);  // Dịch các hàng ngược
            roundKey = generateRoundKey(round, key);  // Sinh khóa cho vòng tiếp theo
            state = addRoundKey(state, roundKey);  // XOR với khóa vòng
            state = invMixColumns(state);  // Trộn các cột ngược
        }

        // Vòng cuối cùng (không có MixColumns)
        state = invSubBytes(state);
        state = invShiftRows(state);
        roundKey = generateRoundKey(10, key);  // Khóa vòng cuối cùng
        state = addRoundKey(state, roundKey);

        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++) {
            output[i] = state[i % 4][i / 4];
        }
        return output;
    }

    // Thực hiện S-box thay thế
    public static byte[][] subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = S_BOX[state[i][j] & 0x0F][state[i][j] >> 4];
            }
        }
        return state;
    }

    // Thực hiện dịch các hàng
    public static byte[][] shiftRows(byte[][] state) {
        byte[] temp = new byte[4];
        // Dịch các hàng
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = state[(i + j) % 4][i];
            }
            for (int j = 0; j < 4; j++) {
                state[j][i] = temp[j];
            }
        }
        return state;
    }

    // Trộn các cột (MixColumns)
    public static byte[][] mixColumns(byte[][] state) {
        byte[] temp = new byte[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = state[j][i];
            }
        }
        return state;
    }

    // Thêm khóa vòng vào ma trận
    public static byte[][] addRoundKey(byte[][] state, byte[] key) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] ^= key[i * 4 + j];
            }
        }
        return state;
    }

    // Sinh khóa cho vòng (dựa trên khóa gốc)
    public static byte[] generateRoundKey(int round, byte[] key) {
        byte[] roundKey = new byte[BLOCK_SIZE];
        System.arraycopy(key, 0, roundKey, 0, BLOCK_SIZE);
        return roundKey;
    }

    // Hàm thay thế byte ngược (S-box ngược)
    public static byte[][] invSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = (byte) 0; // Cần thêm logic cho S-box ngược
            }
        }
        return state;
    }

    // Hàm dịch ngược các hàng
    public static byte[][] invShiftRows(byte[][] state) {
        byte[] temp = new byte[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = state[j][(i + j) % 4];
            }
            for (int j = 0; j < 4; j++) {
                state[j][i] = temp[j];
            }
        }
        return state;
    }

    // Trộn các cột ngược
    public static byte[][] invMixColumns(byte[][] state) {
        byte[] temp = new byte[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = state[j][i];
            }
        }
        return state;
    }
}
