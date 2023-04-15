import org.junit.jupiter.api.Test;
import org.krypto.DSA;


import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class TestKryptoDSA {

    @Test
    public void signTest(){

        DSA dsa = new DSA();
        byte[] data = "uwu".getBytes();
        try {
            dsa.generateKeys();
            org.krypto.Signature signature = dsa.signData(data);
            assertTrue(dsa.verifySignature(data,signature));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


}
