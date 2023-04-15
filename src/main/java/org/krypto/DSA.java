package org.krypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class DSA implements Sign {
    private BigInteger p;
    private BigInteger q;
    private BigInteger h;
    private BigInteger privateKey;
    private BigInteger publicKey;

    @Override
    public void setPublicKey(BigInteger key) {
        publicKey = key;
    }

    @Override
    public void setPrivateKey(BigInteger key) {
        privateKey = key;
    }

    @Override
    public void setParams(BigInteger p, BigInteger q, BigInteger h) {
        this.p = p;
        this.q = q;
        this.h = h;
    }

    private byte[] getMessageDigest(byte[] data) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return messageDigest.digest(data);
    }

    public List<List<BigInteger>> generateKeys() {
        SecureRandom random = new SecureRandom();

        BigInteger hPre;
        int bitLength;
        q = BigInteger.probablePrime(160, random);
        bitLength = 512 + random.nextInt(9) * 64;
        do {
            p = BigInteger.probablePrime(bitLength, random);
            p = p.subtract(p.subtract(BigInteger.ONE).remainder(q));
        }
        while (!(p.isProbablePrime(4)));
        BigInteger pMinusOneDivQ = p.subtract(BigInteger.ONE).divide(q);
        do {
            hPre = new BigInteger(bitLength, random).mod(p.subtract(BigInteger.valueOf(3))).add(BigInteger.TWO);
            h = hPre.mod(p).modPow(pMinusOneDivQ, p);
        }
        while (!(h.compareTo(BigInteger.ONE) > 0 && h.compareTo(p) < 0 && h.mod(p).modPow(q, p).compareTo(BigInteger.ONE) == 0));

        privateKey = new BigInteger(160, random).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        publicKey = h.mod(p).modPow(privateKey, p);
        List<BigInteger> privateKeyList = new ArrayList<>();
        List<BigInteger> publicKeyList = new ArrayList<>();
        privateKeyList.add(p);
        privateKeyList.add(q);
        privateKeyList.add(h);
        privateKeyList.add(this.privateKey);
        publicKeyList.add(p);
        publicKeyList.add(q);
        publicKeyList.add(h);
        publicKeyList.add(this.publicKey);
        List<List<BigInteger>> keyList = new ArrayList<>(2);
        keyList.add(privateKeyList);
        keyList.add(publicKeyList);
        return keyList;
    }

    @Override
    public Signature signData(byte[] data) {
        SecureRandom random = new SecureRandom();
        BigInteger hash;
        BigInteger k, r, i, s;
        hash = new BigInteger(1, getMessageDigest(data));
        do {
            k = new BigInteger(160, random).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);

            r = h.modPow(k, p).mod(q);

            if (r.compareTo(BigInteger.ZERO) == 0)
                continue;

            i = k.modInverse(q);
            s = i.multiply(hash.add(r.multiply(privateKey))).mod(q);

            if (s.compareTo(BigInteger.ZERO) == 0)
                continue;

            break;
        }
        while (true);

        Signature signature = new Signature();
        signature.s1 = r;
        signature.s2 = s;

        return signature;
    }

    @Override
    public boolean verifySignature(byte[] data, Signature signature) {
        BigInteger sPrime, u1, u2, t;
        BigInteger hash = new BigInteger(1, getMessageDigest(data));

        sPrime = signature.s2.modInverse(q);

        u1 = hash.multiply(sPrime).mod(q);

        u2 = signature.s1.multiply(sPrime).mod(q);

        t = h.mod(p).modPow(u1, p).multiply(publicKey.mod(p).modPow(u2, p)).mod(p).mod(q);

        return t.equals(signature.s1);
    }
}
