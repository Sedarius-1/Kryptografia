package org.krypto;

public class AES implements Cipher {
    private byte[] key;

    private byte[] sub_keys;

    private final static byte[] rcon_table = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte) 0x80, 0x1b, 0x36};

    private final static byte[] GalloisMultiplyBy2_table = {
            0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
            0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
            0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
            0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
            (byte) 0x80, (byte) 0x82, (byte) 0x84, (byte) 0x86, (byte) 0x88, (byte) 0x8a, (byte) 0x8c, (byte) 0x8e, (byte) 0x90, (byte) 0x92, (byte) 0x94, (byte) 0x96, (byte) 0x98, (byte) 0x9a, (byte) 0x9c, (byte) 0x9e,
            (byte) 0xa0, (byte) 0xa2, (byte) 0xa4, (byte) 0xa6, (byte) 0xa8, (byte) 0xaa, (byte) 0xac, (byte) 0xae, (byte) 0xb0, (byte) 0xb2, (byte) 0xb4, (byte) 0xb6, (byte) 0xb8, (byte) 0xba, (byte) 0xbc, (byte) 0xbe,
            (byte) 0xc0, (byte) 0xc2, (byte) 0xc4, (byte) 0xc6, (byte) 0xc8, (byte) 0xca, (byte) 0xcc, (byte) 0xce, (byte) 0xd0, (byte) 0xd2, (byte) 0xd4, (byte) 0xd6, (byte) 0xd8, (byte) 0xda, (byte) 0xdc, (byte) 0xde,
            (byte) 0xe0, (byte) 0xe2, (byte) 0xe4, (byte) 0xe6, (byte) 0xe8, (byte) 0xea, (byte) 0xec, (byte) 0xee, (byte) 0xf0, (byte) 0xf2, (byte) 0xf4, (byte) 0xf6, (byte) 0xf8, (byte) 0xfa, (byte) 0xfc, (byte) 0xfe,
            0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
            0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
            0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
            0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
            (byte) 0x9b, (byte) 0x99, (byte) 0x9f, (byte) 0x9d, (byte) 0x93, (byte) 0x91, (byte) 0x97, (byte) 0x95, (byte) 0x8b, (byte) 0x89, (byte) 0x8f, (byte) 0x8d, (byte) 0x83, (byte) 0x81, (byte) 0x87, (byte) 0x85,
            (byte) 0xbb, (byte) 0xb9, (byte) 0xbf, (byte) 0xbd, (byte) 0xb3, (byte) 0xb1, (byte) 0xb7, (byte) 0xb5, (byte) 0xab, (byte) 0xa9, (byte) 0xaf, (byte) 0xad, (byte) 0xa3, (byte) 0xa1, (byte) 0xa7, (byte) 0xa5,
            (byte) 0xdb, (byte) 0xd9, (byte) 0xdf, (byte) 0xdd, (byte) 0xd3, (byte) 0xd1, (byte) 0xd7, (byte) 0xd5, (byte) 0xcb, (byte) 0xc9, (byte) 0xcf, (byte) 0xcd, (byte) 0xc3, (byte) 0xc1, (byte) 0xc7, (byte) 0xc5,
            (byte) 0xfb, (byte) 0xf9, (byte) 0xff, (byte) 0xfd, (byte) 0xf3, (byte) 0xf1, (byte) 0xf7, (byte) 0xf5, (byte) 0xeb, (byte) 0xe9, (byte) 0xef, (byte) 0xed, (byte) 0xe3, (byte) 0xe1, (byte) 0xe7, (byte) 0xe5};
    private final static byte[] GalloisMultiplyBy3_table = {
            0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
            0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
            0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
            0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
            (byte) 0xc0,(byte) 0xc3,(byte) 0xc6,(byte) 0xc5,(byte) 0xcc,(byte) 0xcf,(byte) 0xca,(byte) 0xc9,(byte) 0xd8,(byte) 0xdb,(byte) 0xde,(byte) 0xdd,(byte) 0xd4,(byte) 0xd7,(byte) 0xd2,(byte) 0xd1,
            (byte) 0xf0,(byte) 0xf3,(byte) 0xf6,(byte) 0xf5,(byte) 0xfc,(byte) 0xff,(byte) 0xfa,(byte) 0xf9,(byte) 0xe8,(byte) 0xeb,(byte) 0xee,(byte) 0xed,(byte) 0xe4,(byte) 0xe7,(byte) 0xe2,(byte) 0xe1,
            (byte) 0xa0,(byte) 0xa3,(byte) 0xa6,(byte) 0xa5,(byte) 0xac,(byte) 0xaf,(byte) 0xaa,(byte) 0xa9,(byte) 0xb8,(byte) 0xbb,(byte) 0xbe,(byte) 0xbd,(byte) 0xb4,(byte) 0xb7,(byte) 0xb2,(byte) 0xb1,
            (byte) 0x90,(byte) 0x93,(byte) 0x96,(byte) 0x95,(byte) 0x9c,(byte) 0x9f,(byte) 0x9a,(byte) 0x99,(byte) 0x88,(byte) 0x8b,(byte) 0x8e,(byte) 0x8d,(byte) 0x84,(byte) 0x87,(byte) 0x82,(byte) 0x81,
            (byte) 0x9b,(byte) 0x98,(byte) 0x9d,(byte) 0x9e,(byte) 0x97,(byte) 0x94,(byte) 0x91,(byte) 0x92,(byte) 0x83,(byte) 0x80,(byte) 0x85,(byte) 0x86,(byte) 0x8f,(byte) 0x8c,(byte) 0x89,(byte) 0x8a,
            (byte) 0xab,(byte) 0xa8,(byte) 0xad,(byte) 0xae,(byte) 0xa7,(byte) 0xa4,(byte) 0xa1,(byte) 0xa2,(byte) 0xb3,(byte) 0xb0,(byte) 0xb5,(byte) 0xb6,(byte) 0xbf,(byte) 0xbc,(byte) 0xb9,(byte) 0xba,
            (byte) 0xfb,(byte) 0xf8,(byte) 0xfd,(byte) 0xfe,(byte) 0xf7,(byte) 0xf4,(byte) 0xf1,(byte) 0xf2,(byte) 0xe3,(byte) 0xe0,(byte) 0xe5,(byte) 0xe6,(byte) 0xef,(byte) 0xec,(byte) 0xe9,(byte) 0xea,
            (byte) 0xcb,(byte) 0xc8,(byte) 0xcd,(byte) 0xce,(byte) 0xc7,(byte) 0xc4,(byte) 0xc1,(byte) 0xc2,(byte) 0xd3,(byte) 0xd0,(byte) 0xd5,(byte) 0xd6,(byte) 0xdf,(byte) 0xdc,(byte) 0xd9,(byte) 0xda,
            0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
            0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
            0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
            0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
    };
    private byte[] SubBox;
    private byte[] DomBox;

    public AES(byte[] key) {
        this.key = key;
        initSBoxes();
    }

    @Override
    public void setKey(byte[] key) {
        this.key = key;
    }

    private byte funniMultiply(byte value, byte[]lookup){
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
        return new byte[]{rcon_table[number - 1], 0, 0, 0};
    }

    private byte[] SubWord(byte[] word) {
        return new byte[]{SubBox[word[0]],
                SubBox[word[1]],
                SubBox[word[2]],
                SubBox[word[3]]};
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
        for (int i = 0; i < 16; i++) block[i] = SubBox[block[i]];
        return block;
    }

    private byte[] encryptShiftRows(byte[] block) {
//          0  1  2  3
//          4  5  6  7
//          8  9 10 11
//         12 13 14 15
//         Ignore row 0
//         Shift row 1 by 1

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
        tmp = block[12];
        block[12] = block[15];
        block[15] = block[14];
        block[14] = block[13];
        block[13] = tmp;
        return new byte[0];
    }

    private byte[] encryptMixColumns(byte[] block) {
        // TODO: it's now broken
        byte[] new_block = new byte[16];
        for(int i =0; i<4;i++) {
            new_block[i] = (byte) (funniMultiply(block[i], GalloisMultiplyBy2_table) ^ funniMultiply(block[4+i], GalloisMultiplyBy3_table) ^ block[8+i] ^ block[12+i]);
            new_block[4+i] = (byte) (block[i] ^ funniMultiply(block[4+i], GalloisMultiplyBy2_table) ^ funniMultiply(block[8+i], GalloisMultiplyBy3_table) ^ block[12+i]);
            new_block[8+i] = (byte) (block[i] ^ block[4+i] ^ funniMultiply(block[8+i],GalloisMultiplyBy2_table) ^ funniMultiply(block[12+i],GalloisMultiplyBy3_table));
            new_block[12+i] = (byte) (funniMultiply(block[i], GalloisMultiplyBy3_table) ^ block[4+i] ^ block[8+i] ^ funniMultiply(block[12+i], GalloisMultiplyBy2_table));
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
