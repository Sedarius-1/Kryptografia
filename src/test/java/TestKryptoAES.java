import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import org.krypto.AES;

import static org.junit.jupiter.api.Assertions.*;


class TestKryptoAES {

    @Test
    void TestAES128bitEncrypt() {
        //USED FOR GETTING REFERENCE OUTPUTS: https://gchq.github.io/CyberChef
        byte[] plaintext = HexFormat.of().parseHex("f00dbabe");
        byte[] key = HexFormat.of().parseHex("f061a0d4b8e5dd76e07a922728c236e7");

        AES aes = new AES(key);

        byte[] ciphertext = aes.encryptData(plaintext);

        byte[] expected_ciphertext = HexFormat.of().parseHex("9aff9d76bc7edc7e468add034f0dd803");
        System.out.println(HexFormat.of().formatHex(ciphertext));
        assertArrayEquals(expected_ciphertext, ciphertext);
    }


    @Test
    void TestAES128bitDecrypt() {
        byte[] ciphertext = HexFormat.of().parseHex("876c24282e7f5b7e772c873a4ba741dc");
        byte[] key = HexFormat.of().parseHex("f061a0d4b8e5dd76e07a922728c236e7");

        AES aes = new AES(key);

        byte[] plaintext = aes.decryptData(ciphertext);

        byte[] expected_plaintext = HexFormat.of().parseHex("f00dbabe");

        assertArrayEquals(expected_plaintext, plaintext);
    }

    @Test
    void TestAES192bitEncrypt() {
        byte[] plaintext = HexFormat.of().parseHex("f00dbabe");
        byte[] key = HexFormat.of().parseHex("3da678040d6457bbfed56ff3358c34ca361298f1b6071970");

        AES aes = new AES(key);

        byte[] ciphertext = aes.encryptData(plaintext);

        byte[] expected_ciphertext = HexFormat.of().parseHex("c333a78802c6e2ff1cbd1e59eaca5161");

        assertArrayEquals(expected_ciphertext, ciphertext);
    }

    @Test
    void TestAES192bitDecrypt() {
        byte[] ciphertext = HexFormat.of().parseHex("feef0b557ea4c1e24b4bc480f779b123");
        byte[] key = HexFormat.of().parseHex("3da678040d6457bbfed56ff3358c34ca361298f1b6071970");

        AES aes = new AES(key);

        byte[] plaintext = aes.decryptData(ciphertext);

        byte[] expected_plaintext = HexFormat.of().parseHex("f00dbabe");

        assertArrayEquals(expected_plaintext, plaintext);
    }

    @Test
    void TestAES256bitEncrypt() {
        byte[] plaintext = HexFormat.of().parseHex("f00dbabe");
        byte[] key = HexFormat.of().parseHex("01f88e42a7febdba3cb1eabfc6b2df64f4df9bd48b36a4cf95ba29b5ade5cd16");

        AES aes = new AES(key);

        byte[] ciphertext = aes.encryptData(plaintext);

        byte[] expected_ciphertext = HexFormat.of().parseHex("89af4d009c5ec93914a870f5b17b4e06");

        assertArrayEquals(expected_ciphertext, ciphertext);
    }

}

    @Test
    void TestAES256bitDecrypt() {
        byte[] ciphertext = HexFormat.of().parseHex("581a95f57098feb62cc90dcb95f839b7");
        byte[] key = HexFormat.of().parseHex("01f88e42a7febdba3cb1eabfc6b2df64f4df9bd48b36a4cf95ba29b5ade5cd16");

        AES aes = new AES(key);

        byte[] plaintext = aes.decryptData(ciphertext);

        byte[] expected_plaintext = HexFormat.of().parseHex("f00dbabe");

        assertArrayEquals(expected_plaintext, plaintext);
    }
}