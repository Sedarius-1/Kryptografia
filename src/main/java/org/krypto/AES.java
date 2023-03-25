package org.krypto;

import java.util.HexFormat;

public class AES implements Cipher {
    private byte[] key;

    private byte[] sub_keys;

    public AES(byte[] key) {
        this.key = key;
    }

    @Override
    public void setKey(byte[] key) {
        this.key = key;
    }

    private byte GalloisMultiply(byte value, byte[] lookup) {
        return lookup[(int) value & 0xff];
    }

    private void debugPrintBlock(byte[] block) {
        StringBuilder sb = new StringBuilder();
        for (byte b : block) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb);
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
        for(int i =data.length;i<padded_data.length;i++){
            padded_data[i] = Byte.parseByte(Integer.toString(pad_length));
        }
        return padded_data;
    }

    public void oldencryptInitSubKeys(int round_count) {
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

    public void encryptInitSubKeys(int round_count) {
        int current_sub_keys_length = 0;
        sub_keys = new byte[16 * round_count];
        System.arraycopy(key, 0, sub_keys, 0, key.length);
        current_sub_keys_length = key.length;
        int iter = 1;
        while(current_sub_keys_length<round_count*16){
            //1.1
            byte[] temp = new byte[4];
            System.arraycopy(sub_keys, current_sub_keys_length - 4, temp, 0, 4);
            if(current_sub_keys_length==round_count*16) {
                break;
            }
            //1.2
            temp = RotWord(temp);
            //1.3
            temp = SubWord(temp);
            //1.4
            temp = XORWord(temp, rcon(iter));
            iter++;
            //1.5
            byte[] in = new byte[4];
            System.arraycopy(sub_keys, current_sub_keys_length - key.length, in, 0, 4);
            temp = XORWord(temp, in);
            System.arraycopy(temp, 0, sub_keys, current_sub_keys_length, 4);
            current_sub_keys_length += 4;

            for (int i = 0; i < 3; i++) {
                //2.1
                System.arraycopy(sub_keys, current_sub_keys_length - 4, temp, 0, 4);
                if(current_sub_keys_length==round_count*16){
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
                if(current_sub_keys_length==round_count*16){
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
                case 128/8 -> imax = 0;
                case 192/8 -> imax = 2;
                case 256/8 -> imax = 3;
            }

            for (int i = 0; i < imax; i++) {
                //4.1
                System.arraycopy(sub_keys, current_sub_keys_length - 4, temp, 0, 4);
                if(current_sub_keys_length==round_count*16){
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
            case 128/8 -> round_count = 10;
            case 192/8 -> round_count = 12;
            case 256/8 -> round_count = 14;
            default -> {
                System.out.println("AES:encryptData: INVALID KEY LENGTH!");
                return null;
            }
        }

        encryptInitSubKeys(round_count+1);
        System.out.println(HexFormat.of().formatHex(sub_keys));
        byte[] ciphertext = new byte[padded_plaintext.length];
        // encrypt block
        for (int block_start_index = 0; block_start_index < plaintext.length; block_start_index += 16) {
            byte[] block = new byte[16];
            // take one block
            System.arraycopy(padded_plaintext, block_start_index, block, 0, 16);
            byte[] round_key = new byte[16];
            System.arraycopy(sub_keys,0,round_key,0,16);
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
            case 128/8 -> round_count = 10;
            case 192/8 -> round_count = 12;
            case 256/8 -> round_count = 14;
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
