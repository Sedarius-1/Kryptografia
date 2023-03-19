package org.krypto;

public interface Cipher {
    void setKey(byte[] key);
    byte[] encryptData(byte[] plaintext);
    byte[] decryptData(byte[] ciphertext);
}
