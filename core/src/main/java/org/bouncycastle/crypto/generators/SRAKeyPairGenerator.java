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
public class SRAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private SRAKeyGenerationParameters param;

    @Override
    public void init(KeyGenerationParameters param) {
        this.param = (SRAKeyGenerationParameters) param;
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair() {

        BigInteger p, q, n, d, e, pSub1, qSub1, gcd, lcm;

        p = param.getP();
        q = param.getQ();

        n = p.multiply(q);

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

        e = chooseRandomPublicExponent(lcm);

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

    private BigInteger chooseRandomPublicExponent(BigInteger lcm) {
        while (true) {
            BigInteger prime = new BigInteger(lcm.bitLength(), param.getCertainty(), param.getRandom());

            // prime has to be greater than one.
            if (!(prime.compareTo(ONE) == 1)) {
                continue;
            }

            if (!prime.isProbablePrime(param.getCertainty())) {
                continue;
            }

            // prime has to be less than phi(n).
            if (!(prime.compareTo(lcm) == -1)) {
                continue;
            }

            return prime;
        }
    }

    public static class SRAKeyGenerationParameters extends KeyGenerationParameters {
        private final BigInteger p;
        private final BigInteger q;
        private int certainty;

        public SRAKeyGenerationParameters(BigInteger p, BigInteger q, SecureRandom random, int certainty) {
            super(random, 0);
            this.p = p;
            this.q = q;
            this.certainty = certainty;
        }

        public BigInteger getP() {
            return p;
        }

        public BigInteger getQ() {
            return q;
        }

        public int getCertainty() {
            return certainty;
        }
    }
}
