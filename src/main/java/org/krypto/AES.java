package org.krypto;

public class AES implements Cipher {
    private byte[] key;

    private byte[] sub_keys;


//    private byte[] SubBox;
//    private byte[] DomBox;

    public AES(byte[] key) {
        this.key = key;
        initSBoxes();
    }

    @Override
    public void setKey(byte[] key) {
        this.key = key;
    }

    private byte funniMultiply(byte value, byte[] lookup) {
        return lookup[(int) value];
    }

    private void debugPrintBlock(byte[] block) {
        StringBuilder sb = new StringBuilder();
        for (byte b : block) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb);
    }

    private void initSBoxes() {
        // https://en.wikipedia.org/wiki/Rijndael_S-box
        // SubBox - forward
        // DomBox - inverse
        // TODO

        System.out.println("TODO: AES:initSBoxes");
    }

    private byte[] rcon(int number) {
        return new byte[]{LookupTables.rcon_table[number - 1], 0, 0, 0};
    }

    private byte[] SubWord(byte[] word) {
        return new byte[]{(byte) LookupTables.SBox[word[0]],
                (byte) LookupTables.SBox[word[1]],
                (byte) LookupTables.SBox[word[2]],
                (byte) LookupTables.SBox[word[3]]};
    }

    private byte[] RotWord(byte[] word) {
        return new byte[]{word[1], word[2], word[3], word[0]};
    }

    private byte[] XORWord(byte[] word1, byte[] word2) {
        return new byte[]{(byte) (word1[0] ^ word2[0]),
                (byte) (word1[1] ^ word2[1]),
                (byte) (word1[2] ^ word2[2]),
                (byte) (word1[3] ^ word2[3])};
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

    public void encryptInitSubKeys(int round_count) {
        // https://en.wikipedia.org/wiki/AES_key_schedule
        sub_keys = new byte[16 * round_count];
        int N = key.length / 4;
        for (int i = 0; i < 4 * round_count; i += 4) {
            if (i < N) {
                System.arraycopy(key, i, sub_keys, i, 4);
                continue;
            } else if (i >= N && i % N == 0) {
                byte[] Win = new byte[4];
                System.arraycopy(sub_keys, i - (N * 4), Win, 0, 4);
                byte[] Wi1 = new byte[4];
                System.arraycopy(sub_keys, i - 4, Wi1, 0, 4);

                byte[] Wi;
                Wi = XORWord(XORWord(Win, SubWord(RotWord(Wi1))), rcon(i / N));

                System.arraycopy(Wi, 0, sub_keys, i, 4);
                continue;
            } else if (i >= N && N > 6 && i % N == 4) {
                byte[] Win = new byte[4];
                System.arraycopy(sub_keys, i - (N * 4), Win, 0, 4);
                byte[] Wi1 = new byte[4];
                System.arraycopy(sub_keys, i - 4, Wi1, 0, 4);

                byte[] Wi;
                Wi = XORWord(Win, SubWord(Wi1));

                System.arraycopy(Wi, 0, sub_keys, i, 4);
                continue;
            } else {
                byte[] Win = new byte[4];
                System.arraycopy(sub_keys, i - (N * 4), Win, 0, 4);
                byte[] Wi1 = new byte[4];
                System.arraycopy(sub_keys, i - 4, Wi1, 0, 4);

                byte[] Wi;
                Wi = XORWord(Win, Wi1);

                System.arraycopy(Wi, 0, sub_keys, i, 4);
                continue;
            }
        }
    }

    private byte[] encryptGetRoundKey(int round_number) {
        byte[] sub_key = new byte[16];
        System.arraycopy(sub_keys, round_number * 16, sub_key, 0, 16);
        return sub_key;
    }

    private byte[] encryptSubBytes(byte[] block) {
        for (int i = 0; i < 16; i++) block[i] = (byte) LookupTables.SBox[block[i]];
        return block;
    }

    private byte[] encryptShiftRows(byte[] block) {
        //  0  4  8 12
        //  1  5  9 13
        //  2  6 10 14
        //  3  7 11 15
        // Ignore row 0
        // Shift row 1 by 1
        byte tmp = block[1];
        block[1] = block[5];
        block[5] = block[9];
        block[9] = block[13];
        block[13] = tmp;
        // Shift row 2 by 2
        tmp = block[2];
        block[2] = block[10];
        block[10] = tmp;
        tmp = block[6];
        block[6] = block[14];
        block[14] = tmp;
        // Shift row 3 by 3
        //TODO: finish
        tmp = block[3];
        block[3] = block[15];
        block[15] = block[11];
        block[11] = block[7];
        block[7] = tmp;
        return block;
    }

    private byte[] encryptMixColumns(byte[] block) {
        // TODO: it's now broken

        //  0  4  8 12
        //  1  5  9 13
        //  2  6 10 14
        //  3  7 11 15
        byte[] new_block = new byte[16];
        for (int i = 0; i < 4; i++) {
            new_block[4 * i] = (byte) (funniMultiply(block[4 * i], LookupTables.GalloisMultiplyBy2_table) ^ funniMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy3_table) ^ block[4 * i + 2] ^ block[4 * i + 3]);
            new_block[4 * i + 1] = (byte) (block[4 * i] ^ funniMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy2_table) ^ funniMultiply(block[4 * i + 2], LookupTables.GalloisMultiplyBy3_table) ^ block[4 * i + 3]);
            new_block[4 * i + 2] = (byte) (block[4 * i] ^ block[4 * i + 1] ^ funniMultiply(block[4 * i + 2], LookupTables.GalloisMultiplyBy2_table) ^ funniMultiply(block[4 * i + 3], LookupTables.GalloisMultiplyBy3_table));
            new_block[4 * i + 3] = (byte) (funniMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy3_table) ^ block[4 + i] ^ block[4 * i + 2] ^ funniMultiply(block[4 * i + 3], LookupTables.GalloisMultiplyBy2_table));
        }
        return new_block;
    }

    private byte[] encryptAddRoundKey(byte[] block, byte[] round_key) {
        for (int i = 0; i < 16; i++) {
            block[i] = (byte) (block[i] ^ round_key[i]);
        }
        return block;
    }

    // https://www.geeksforgeeks.org/advanced-encryption-standard-aes/
    // https://www.cryptool.org/en/cto/aes-step-by-step
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

        encryptInitSubKeys(round_count);

        byte[] ciphertext = new byte[padded_plaintext.length];
        // encrypt block
        // https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
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
        // TODO
        System.out.println("TODO: AES:unpad");
        return new byte[0];
    }

    private byte[] decryptGetRoundKey(int round_number) {
        // TODO
        System.out.println("TODO: AES:decryptGetRoundKey");
        return new byte[0];
    }

    private byte[] decryptAddRoundKey(byte[] block, byte[] round_key) {
        // TODO
        System.out.println("TODO: AES:decryptAddRoundKey");
        return new byte[0];
    }

    private byte[] decryptMixColumns(byte[] block) {
        // TODO
        System.out.println("TODO: AES:decryptMixColumns");
        return new byte[0];
    }

    private byte[] decryptShiftRows(byte[] block) {
        System.out.println("TODO: AES:decryptShiftRows");
        return new byte[0];
    }

    private byte[] decryptSubBytes(byte[] block) {
        // TODO
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

        // TODO: I don't know if any of this is correct

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
