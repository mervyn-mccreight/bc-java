package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/*
 * An SRA Key Pair Generator.
 * The Public Key is not really public, since you do not want to give it
 * to someone else.
 */
public class SRAKeyPairGenerator {

    private static final BigInteger ONE = BigInteger.valueOf(1);

    private SRAKeyGenerationParameters param;

    public void init(SRAKeyGenerationParameters param) {
        this.param = param;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {

        BigInteger p, q, n, d, e, pSub1, qSub1, gcd, lcm;

        p = param.getP();
        q = param.getQ();

        n = p.multiply(q);

        e = param.getE();

        if (p.compareTo(q) < 0)
        {
            gcd = p;
            p = q;
            q = gcd;
        }

        pSub1 = p.subtract(ONE);
        qSub1 = q.subtract(ONE);
        gcd = pSub1.gcd(qSub1);
        lcm = pSub1.divide(gcd).multiply(qSub1);

        //
        // calculate the private exponent
        //
        d = e.modInverse(lcm);

        //
        // calculate the CRT factors
        //
        BigInteger dP, dQ, qInv;

        dP = d.remainder(pSub1);
        dQ = d.remainder(qSub1);
        qInv = q.modInverse(p);

        return new AsymmetricCipherKeyPair(
                new RSAKeyParameters(false, n, e),
                new RSAPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));
    }

    public static class SRAKeyGenerationParameters {
        // todo: randomly generate e, do not put it in as a parameter, since the public exponent
        // seems to be the only thing, making the difference for your keys in sra.
        private BigInteger p;
        private BigInteger q;
        private BigInteger e;

        public SRAKeyGenerationParameters(BigInteger p, BigInteger q, BigInteger publicExponent) {
            this.p = p;
            this.q = q;
            this.e = publicExponent;
        }

        public BigInteger getP() {
            return p;
        }

        public BigInteger getQ() {
            return q;
        }

        public BigInteger getE() {
            return e;
        }
    }
}
