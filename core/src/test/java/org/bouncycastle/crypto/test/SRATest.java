package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

import java.math.BigInteger;

public class SRATest extends SimpleTest {

    /* copied from RSATest */
    static BigInteger p = new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16);
    static BigInteger q = new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16);
    static BigInteger pubExp = new BigInteger("11", 16);

    @Override
    public String getName() {
        return "SRA";
    }

    @Override
    public void performTest() throws Exception {
        encrypionDecryptionTest();
        commutativeTest();
    }

    private void commutativeTest() {
        String message = "This is a cool text, not including all letters :-(";

        SRAKeyPairGenerator aliceKeyGen = new SRAKeyPairGenerator();
        SRAKeyPairGenerator.SRAKeyGenerationParameters aliceParams = new SRAKeyPairGenerator.SRAKeyGenerationParameters(p, q, pubExp);
        aliceKeyGen.init(aliceParams);
        AsymmetricCipherKeyPair keyPairAlice = aliceKeyGen.generateKeyPair();

        SRAKeyPairGenerator bobKeyGen = new SRAKeyPairGenerator();
        SRAKeyPairGenerator.SRAKeyGenerationParameters bobParams = new SRAKeyPairGenerator.SRAKeyGenerationParameters(p, q, BigInteger.valueOf(7));
        bobKeyGen.init(bobParams);
        AsymmetricCipherKeyPair keyPairBob = bobKeyGen.generateKeyPair();

        SRAEngine sra = new SRAEngine();

        sra.init(true, keyPairAlice.getPublic());
        byte[] e_Alice = sra.processBlock(message.getBytes(), 0, message.getBytes().length);

        sra.init(true, keyPairBob.getPublic());
        byte[] e_Bob_e_Alice = sra.processBlock(e_Alice, 0, e_Alice.length);

        sra.init(true, keyPairBob.getPublic());
        byte[] e_Bob = sra.processBlock(message.getBytes(), 0, message.getBytes().length);

        sra.init(false, keyPairAlice.getPrivate());
        byte[] expectation = sra.processBlock(e_Bob_e_Alice, 0, e_Bob_e_Alice.length);

        if (!Arrays.areEqual(expectation, e_Bob)) {
            fail("SRA is not commutative.");
        }
    }

    private void encrypionDecryptionTest() {
        String message = "This is a cool text, not including all letters :-(";

        SRAKeyPairGenerator pairGenerator = new SRAKeyPairGenerator();
        SRAKeyPairGenerator.SRAKeyGenerationParameters params = new SRAKeyPairGenerator.SRAKeyGenerationParameters(p, q, pubExp);
        pairGenerator.init(params);
        AsymmetricCipherKeyPair keyPairAlice = pairGenerator.generateKeyPair();

        SRAEngine sra = new SRAEngine();
        sra.init(true, keyPairAlice.getPublic());

        byte[] cipher = sra.processBlock(message.getBytes(), 0, message.getBytes().length);

        sra.init(false, keyPairAlice.getPrivate());
        byte[] decrypted = sra.processBlock(cipher, 0, cipher.length);

        String decryptedString = new String(decrypted);

        if (!message.equals(decryptedString)) {
            fail("Decryption of Encryption does not give back the message");
        }
    }

    public static void main(String[] args) {
        runTest(new SRATest());
    }
}
