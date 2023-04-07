package org.krypto;

import java.math.BigInteger;

public interface Sign {
    void setPublicKey(BigInteger key);

    void setPrivateKey(BigInteger key);

    void setParams(BigInteger p, BigInteger q, BigInteger h);

    Signature signData(byte[] data);

    boolean verifySignature(byte[] data, Signature s);
}
