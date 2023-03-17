package org.krypto;

public interface Cipher {
    void setKey(byte[] key);
    byte[] encrypyData(byte[] plaintext);
    byte[] decryptData(byte[] ciphertext);
}
