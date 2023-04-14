package org.krypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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


    private BigInteger getDocumentHashAsBigInt(byte[] document) {
        BigInteger document_hash;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hash = md.digest(document);
            document_hash = new BigInteger(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return document_hash;
    }


    @Override
    public Signature signData(byte[] data) {
        // 1) generate random r (0 < r <= q-1) done
        BigInteger lowerRange = new BigInteger("0");
        SecureRandom random = new SecureRandom();
        if (q.equals(lowerRange) || p.equals(lowerRange) || h.equals(lowerRange) || privateKey.equals(lowerRange)) {
            System.out.println("ERROR: signData: went inside if!");
            return new Signature();
        }
        BigInteger upperRange = q.subtract(new BigInteger("1"));

        BigInteger r;
        Signature s = new Signature();
        do {
            r = new BigInteger(upperRange.bitLength(), random);
        } while (r.compareTo(upperRange) > 0 || (r.compareTo(upperRange) < 0 && r.equals(lowerRange)));
        // 2) calculate r' = r^-1 mod q done
        BigInteger r_prime = r.modInverse(q);

        // 3) calculate s1 = (h^r mod p) mod q done
        s.s1 = (h.modPow(r, p)).mod(q);
        // calculate documents hash
        BigInteger document_hash = getDocumentHashAsBigInt(data);
        // 4) calculate s2 = (r'(SHA512(doc) + as1)) mod q done
        // s2 =(r '    *     (      SHA512    +           a   *    s1       )) mod q
        s.s2 = (r_prime.multiply((document_hash.add(privateKey.multiply(s.s1))))).mod(q);
        return s;
    }

    @Override
    public boolean verifySignature(byte[] data, Signature s) {
        // 1) calculate s' = s2 ^-1 mod q
        BigInteger s_prime = s.s2.modInverse(q);
        // calculate documents hash
        BigInteger document_hash = getDocumentHashAsBigInt(data);
        // 2) calculate u1 = (SHA512(doc) s') mod q
        BigInteger u1 = (document_hash.multiply(s_prime)).mod(q);
        // 3) calculate u2 = (s' s1) mod q
        BigInteger u2 = (s_prime.multiply(s.s1)).mod(q);
        // 4) calculate t = (h^u1 b^u2 mod p) mod q
        // TODO: this might not be ok (check)
        BigInteger t = ((h.modPow(u1, p).multiply(publicKey.modPow(u2, p))).mod(p)).mod(q);
        // 5) check signature
        System.out.println(t);
        System.out.println(s.s1);
        return t.equals(s.s1);
    }
}
