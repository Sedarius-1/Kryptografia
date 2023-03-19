package org.krypto;

public class AES implements Cipher {
    private byte[] key;

    public AES(byte[] key) {
        this.key = key;
    }

    @Override
    public void setKey(byte[] key) {
        this.key = key;
    }

    // ENCRYPTION:
    private byte[] pad(byte[] data) {
        int pad_length;
        pad_length = 16 - (data.length % 16);
        byte[] padded_data = new byte[data.length + pad_length];
        System.arraycopy(data, 0, padded_data, 0, data.length);
        padded_data[padded_data.length - 1] = Byte.parseByte(Integer.toString(pad_length));
        return padded_data;
    }

    private byte[] encryptGetRoundKey(int round_number) {
        System.out.println("TODO: AES:getRoundKey");
        return new byte[0];
    }

    private byte[] encryptSubBytes(byte[] block) {
        System.out.println("TODO: AES:encryptSubBytes");
        return new byte[0];
    }

    private byte[] encryptShiftRows(byte[] block) {
        System.out.println("TODO: AES:encryptShiftRows");
        return new byte[0];
    }

    private byte[] encryptMixColumns(byte[] block) {
        System.out.println("TODO: AES:encryptMixColumns");
        return new byte[0];
    }

    private byte[] encryptAddRoundKey(byte[] block, byte[] round_key) {
        System.out.println("TODO: AES:encryptAddRoundKey");
        return new byte[0];
    }

    // https://www.geeksforgeeks.org/advanced-encryption-standard-aes/
    @Override
    public byte[] encryptData(byte[] plaintext) {
        byte[] padded_plaintext = pad(plaintext);
        int round_count;
        switch (key.length) {
            case 128 -> round_count = 10;
            case 192 -> round_count = 12;
            case 256 -> round_count = 14;
            default -> {
                System.out.println("AES:encryptData: INVALID KEY LENGTH!");
                return null;
            }
        }

        byte[] ciphertext = new byte[padded_plaintext.length];
        // encrypt block
        for (int block_start_index = 0; block_start_index < plaintext.length; block_start_index += 16) {
            byte[] block = new byte[16];
            // take one block
            System.arraycopy(padded_plaintext, block_start_index, block, 0, 16);

            // n-1 rounds (R0 - R(n-2)
            byte[] round_key;
            for (int round_number = 0; round_number < round_count - 1; round_number++) {
                round_key = encryptGetRoundKey(round_number);
                block = encryptSubBytes(block);
                block = encryptShiftRows(block);
                block = encryptMixColumns(block);
                block = encryptAddRoundKey(block, round_key);
            }

            // last "special" round (R(n-1))
            round_key = encryptGetRoundKey(round_count - 1);
            block = encryptSubBytes(block);
            block = encryptShiftRows(block);
            block = encryptAddRoundKey(block, round_key);

            // add block to output
            System.arraycopy(block, 0, ciphertext, block_start_index, 16);
        }

        return ciphertext;
    }

    // DECRYPTION:

    private byte[] unpad(byte[] plaintext) {
        System.out.println("TODO: AES:unpad");
        return new byte[0];
    }

    private byte[] decryptGetRoundKey(int round_number) {
        System.out.println("TODO: AES:decryptGetRoundKey");
        return new byte[0];
    }

    private byte[] decryptAddRoundKey(byte[] block, byte[] round_key) {
        System.out.println("TODO: AES:decryptAddRoundKey");
        return new byte[0];
    }

    private byte[] decryptMixColumns(byte[] block) {
        System.out.println("TODO: AES:decryptMixColumns");
        return new byte[0];
    }

    private byte[] decryptShiftRows(byte[] block) {
        System.out.println("TODO: AES:decryptShiftRows");
        return new byte[0];
    }

    private byte[] decryptSubBytes(byte[] block) {
        System.out.println("TODO: AES:decryptSubBytes");
        return new byte[0];
    }

    @Override
    public byte[] decryptData(byte[] ciphertext) {
        int round_count;
        switch (key.length) {
            case 128 -> round_count = 10;
            case 192 -> round_count = 12;
            case 256 -> round_count = 14;
            default -> {
                System.out.println("AES:decryptData: INVALID KEY LENGTH!");
                return null;
            }
        }

        byte[] plaintext = new byte[ciphertext.length];
        // decrypt block
        for (int block_start_index = 0; block_start_index < ciphertext.length; block_start_index += 16) {
            byte[] block = new byte[16];
            // take one block
            System.arraycopy(ciphertext, block_start_index, block, 0, 16);

            // first "special" round (R(n-1))
            byte[] round_key;
            round_key = decryptGetRoundKey(round_count - 1);
            block = decryptAddRoundKey(block, round_key);
            block = decryptShiftRows(block);
            block = decryptSubBytes(block);

            // n-1 rounds (R0 - R(n-2)
            for (int round_number = round_count - 2; round_number >= 0; round_number--) {
                round_key = decryptGetRoundKey(round_number);
                block = decryptAddRoundKey(block, round_key);
                block = decryptMixColumns(block);
                block = decryptShiftRows(block);
                block = decryptSubBytes(block);
            }


            // add block to output
            System.arraycopy(block, 0, ciphertext, block_start_index, 16);
        }

        return unpad(plaintext);
    }
}
