package org.krypto;

public class AES implements Cipher {
    private byte[] key;

    private byte[] sub_keys;

    public AES(byte[] key) {
        setKey(key);
    }

    @Override
    public void setKey(byte[] key) {
        this.key = key;
        int round_count = 10;
        switch (key.length) {
            // case 128 / 8 -> round_count = 10;
            case 192 / 8 -> round_count = 12;
            case 256 / 8 -> round_count = 14;
            default -> System.out.println("AES:setKey: INVALID KEY LENGTH!");
        }
        encryptInitSubKeys(round_count + 1);
    }

    private byte GalloisMultiply(byte value, int[] lookup) {
        return (byte) lookup[(int) value & 0xff];
    }

    private byte[] rcon(int number) {
        return new byte[]{LookupTables.rcon_table[number - 1], 0, 0, 0};
    }

    private byte[] SubWord(byte[] word) {
        return new byte[]{(byte) LookupTables.SBox[word[0] & 0xff],
                (byte) LookupTables.SBox[word[1] & 0xff],
                (byte) LookupTables.SBox[word[2] & 0xff],
                (byte) LookupTables.SBox[word[3] & 0xff]};
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
        for (int i = data.length; i < padded_data.length; i++) {
            padded_data[i] = Byte.parseByte(Integer.toString(pad_length));
        }
        return padded_data;
    }

    public void encryptInitSubKeys(int round_count) {
        int current_sub_keys_length;
        sub_keys = new byte[16 * round_count];
        System.arraycopy(key, 0, sub_keys, 0, key.length);
        current_sub_keys_length = key.length;
        int iteration = 1;
        while (current_sub_keys_length < round_count * 16) {
            //1.1
            byte[] temp = new byte[4];
            System.arraycopy(sub_keys, current_sub_keys_length - 4, temp, 0, 4);
            if (current_sub_keys_length == round_count * 16) {
                break;
            }
            //1.2
            temp = RotWord(temp);
            //1.3
            temp = SubWord(temp);
            //1.4
            temp = XORWord(temp, rcon(iteration));
            iteration++;
            //1.5
            byte[] in = new byte[4];
            System.arraycopy(sub_keys, current_sub_keys_length - key.length, in, 0, 4);
            temp = XORWord(temp, in);
            System.arraycopy(temp, 0, sub_keys, current_sub_keys_length, 4);
            current_sub_keys_length += 4;

            for (int i = 0; i < 3; i++) {
                //2.1
                System.arraycopy(sub_keys, current_sub_keys_length - 4, temp, 0, 4);
                if (current_sub_keys_length == round_count * 16) {
                    break;
                }
                //2.2
                System.arraycopy(sub_keys, current_sub_keys_length - key.length, in, 0, 4);
                temp = XORWord(temp, in);
                System.arraycopy(temp, 0, sub_keys, current_sub_keys_length, 4);
                current_sub_keys_length += 4;
            }

            if (key.length * 8 == 256) {
                //3.1
                System.arraycopy(sub_keys, current_sub_keys_length - 4, temp, 0, 4);
                if (current_sub_keys_length == round_count * 16) {
                    break;
                }
                //3.2
                temp = SubWord(temp);
                //3.3
                System.arraycopy(sub_keys, current_sub_keys_length - key.length, in, 0, 4);
                temp = XORWord(temp, in);
                System.arraycopy(temp, 0, sub_keys, current_sub_keys_length, 4);
                current_sub_keys_length += 4;
            }

            int imax = 0;
            switch (key.length) {
                // case 128 / 8 -> imax = 0;
                case 192 / 8 -> imax = 2;
                case 256 / 8 -> imax = 3;
            }

            for (int i = 0; i < imax; i++) {
                //4.1
                System.arraycopy(sub_keys, current_sub_keys_length - 4, temp, 0, 4);
                if (current_sub_keys_length == round_count * 16) {
                    break;
                }
                //4.2
                System.arraycopy(sub_keys, current_sub_keys_length - key.length, in, 0, 4);
                temp = XORWord(temp, in);
                System.arraycopy(temp, 0, sub_keys, current_sub_keys_length, 4);
                current_sub_keys_length += 4;

            }

        }
    }

    private byte[] encryptGetRoundKey(int round_number) {
        byte[] sub_key = new byte[16];
        System.arraycopy(sub_keys, round_number * 16, sub_key, 0, 16);
        return sub_key;
    }

    private byte[] encryptSubBytes(byte[] block) {
        for (int i = 0; i < 16; i++) block[i] = (byte) LookupTables.SBox[block[i] & 0xff];
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
        tmp = block[3];
        block[3] = block[15];
        block[15] = block[11];
        block[11] = block[7];
        block[7] = tmp;
        return block;
    }

    private byte[] encryptMixColumns(byte[] block) {
        //  0  4  8 12
        //  1  5  9 13
        //  2  6 10 14
        //  3  7 11 15
        byte[] new_block = new byte[16];
        for (int i = 0; i < 4; i++) {
            new_block[4 * i] = (byte) (GalloisMultiply(block[4 * i], LookupTables.GalloisMultiplyBy2_table) ^ GalloisMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy3_table) ^ block[4 * i + 2] ^ block[4 * i + 3]);
            new_block[4 * i + 1] = (byte) (block[4 * i] ^ GalloisMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy2_table) ^ GalloisMultiply(block[4 * i + 2], LookupTables.GalloisMultiplyBy3_table) ^ block[4 * i + 3]);
            new_block[4 * i + 2] = (byte) (block[4 * i] ^ block[4 * i + 1] ^ GalloisMultiply(block[4 * i + 2], LookupTables.GalloisMultiplyBy2_table) ^ GalloisMultiply(block[4 * i + 3], LookupTables.GalloisMultiplyBy3_table));
            new_block[4 * i + 3] = (byte) (GalloisMultiply(block[4 * i], LookupTables.GalloisMultiplyBy3_table) ^ block[4 * i + 1] ^ block[4 * i + 2] ^ GalloisMultiply(block[4 * i + 3], LookupTables.GalloisMultiplyBy2_table));
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
            case 128 / 8 -> round_count = 10;
            case 192 / 8 -> round_count = 12;
            case 256 / 8 -> round_count = 14;
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
            byte[] round_key;
            round_key = encryptGetRoundKey(0);
            block = encryptAddRoundKey(block, round_key);
            // n-1 rounds (R0 - R(n-2)

            for (int round_number = 1; round_number < round_count; round_number++) {
                round_key = encryptGetRoundKey(round_number);
                block = encryptSubBytes(block);
                block = encryptShiftRows(block);
                block = encryptMixColumns(block);
                block = encryptAddRoundKey(block, round_key);
            }

            // last "special" round (R(n-1))
            round_key = encryptGetRoundKey(round_count);
            block = encryptSubBytes(block);
            block = encryptShiftRows(block);
            block = encryptAddRoundKey(block, round_key);

            // add block to output
            System.arraycopy(block, 0, ciphertext, block_start_index, 16);
        }

        return ciphertext;
    }

    // DECRYPTION:

    private byte[] unpad(byte[] padded_data) {
        System.out.println("Padded data length:" + padded_data.length);
        int pad_length;
        pad_length = padded_data[padded_data.length - 1];
        byte[] unpadded_data = new byte[padded_data.length - pad_length];
        System.arraycopy(padded_data, 0, unpadded_data, 0, unpadded_data.length);
        System.out.println("Unpadded data length:" + unpadded_data.length);
        return unpadded_data;
    }

    private byte[] decryptGetRoundKey(int round_number) {
        byte[] round_key = new byte[16];
        int total_rounds = sub_keys.length / 16;
        System.arraycopy(sub_keys, (total_rounds - 1 - round_number) * 16, round_key, 0, 16);
        return round_key;
    }

    private byte[] decryptAddRoundKey(byte[] block, byte[] round_key) {
        for (int i = 0; i < 16; i++) {
            block[i] = (byte) (block[i] ^ round_key[i]);
        }
        return block;
    }

    private byte[] decryptMixColumns(byte[] block) {
        // Mix columns matrix for decryption:
        // e b d 9 -  14 11 13  9
        // 9 e b d -   9 14 11 13
        // d 9 e b -  13  9 14 11
        // d b 9 e -  11 13  9 14
        byte[] new_block = new byte[16];
        for (int i = 0; i < 4; i++) {
            new_block[4 * i] = (byte) (GalloisMultiply(block[4 * i], LookupTables.GalloisMultiplyBy14_table) ^
                    GalloisMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy11_table) ^
                    GalloisMultiply(block[4 * i + 2], LookupTables.GalloisMultiplyBy13_table) ^
                    GalloisMultiply(block[4 * i + 3], LookupTables.GalloisMultiplyBy9_table));
            new_block[4 * i + 1] = (byte) (GalloisMultiply(block[4 * i], LookupTables.GalloisMultiplyBy9_table) ^
                    GalloisMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy14_table) ^
                    GalloisMultiply(block[4 * i + 2], LookupTables.GalloisMultiplyBy11_table) ^
                    GalloisMultiply(block[4 * i + 3], LookupTables.GalloisMultiplyBy13_table));
            new_block[4 * i + 2] = (byte) (GalloisMultiply(block[4 * i], LookupTables.GalloisMultiplyBy13_table) ^
                    GalloisMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy9_table) ^
                    GalloisMultiply(block[4 * i + 2], LookupTables.GalloisMultiplyBy14_table) ^
                    GalloisMultiply(block[4 * i + 3], LookupTables.GalloisMultiplyBy11_table));
            new_block[4 * i + 3] = (byte) (GalloisMultiply(block[4 * i], LookupTables.GalloisMultiplyBy11_table) ^
                    GalloisMultiply(block[4 * i + 1], LookupTables.GalloisMultiplyBy13_table) ^
                    GalloisMultiply(block[4 * i + 2], LookupTables.GalloisMultiplyBy9_table) ^
                    GalloisMultiply(block[4 * i + 3], LookupTables.GalloisMultiplyBy14_table));
        }
        return new_block;
    }

    private byte[] decryptShiftRows(byte[] block) {
        //  0  4  8 12
        //  1  5  9 13
        //  2  6 10 14
        //  3  7 11 15
        // Ignore row 0
        // Shift row 1 by 1
        byte tmp = block[13];
        block[13] = block[9];
        block[9] = block[5];
        block[5] = block[1];
        block[1] = tmp;
        // Shift row 2 by 2
        tmp = block[10];
        block[10] = block[2];
        block[2] = tmp;
        tmp = block[6];
        block[6] = block[14];
        block[14] = tmp;
        // Shift row 3 by 3
        tmp = block[15];
        block[15] = block[3];
        block[3] = block[7];
        block[7] = block[11];
        block[11] = tmp;
        return block;
    }


    private byte[] decryptSubBytes(byte[] block) {
        for (int i = 0; i < 16; i++) block[i] = (byte) LookupTables.inverseSBox[block[i] & 0xff];
        return block;
    }

    @Override
    public byte[] decryptData(byte[] ciphertext) {
        System.out.println("Ciphertext length:" + ciphertext.length);
        int round_count;
        switch (key.length) {
            case 128 / 8 -> round_count = 10;
            case 192 / 8 -> round_count = 12;
            case 256 / 8 -> round_count = 14;
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

            byte[] round_key;

            // first "special" round (R0)
            round_key = decryptGetRoundKey(0);
            block = decryptAddRoundKey(block, round_key);

            // n-1 rounds (R1 - R(n-1)
            for (int round_number = 1; round_number < round_count; round_number++) {
                round_key = decryptGetRoundKey(round_number);
                block = decryptShiftRows(block);
                block = decryptSubBytes(block);
                block = decryptAddRoundKey(block, round_key);
                block = decryptMixColumns(block);
            }

            round_key = decryptGetRoundKey(round_count);
            block = decryptShiftRows(block);
            block = decryptSubBytes(block);
            block = decryptAddRoundKey(block, round_key);

            // add block to output
            System.arraycopy(block, 0, plaintext, block_start_index, 16);
        }

        return unpad(plaintext);
    }
}
