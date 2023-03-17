package org.krypto;

public class AES implements Cipher{
    private byte[] key;

    public AES(byte[] key) {
        this.key = key;
    }

    @Override
    public void setKey(byte[] key) {
        this.key = key;
    }
    @Override
    public byte[] encrypyData(byte[] plaintext) {
        return new byte[0];
    }

    @Override
    public byte[] decryptData(byte[] ciphertext) {
        return new byte[0];
    }
}
