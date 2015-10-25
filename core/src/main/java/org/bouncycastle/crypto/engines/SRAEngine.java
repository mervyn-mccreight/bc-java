package org.bouncycastle.crypto.engines;

/*
 * SRA does the same as RSA internally. The only difference is, that you do not share your public-key,
 * and you have to use the same modulus n. So you have to agree on the same p and q.
 */
public class SRAEngine extends RSAEngine {
}
