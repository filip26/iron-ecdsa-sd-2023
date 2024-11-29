package com.apicatalog.ld.signature.ecdsa.sd;

import java.util.Collection;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.controller.method.VerificationMethod;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.KeyGenError;
import com.apicatalog.ld.signature.ecdsa.sd.BCECDSASignatureProvider.CurveType;
import com.apicatalog.vcdi.DataIntegrityDraft;
import com.apicatalog.vcdi.DataIntegritySuite;

public class ECDSASelective2023Draft extends DataIntegrityDraft {

    private final CurveType curve;
    
    private KeyPair proofKeyPair;

    private byte[] hmacKey;

    protected Collection<String> selectors;

    protected ECDSASelective2023Draft(
            DataIntegritySuite suite,
            CurveType curve,
            CryptoSuite crypto, 
            VerificationMethod method    
            ) {
        super(suite, crypto, method);
        this.curve = curve;
    }

    public void proofKeys(KeyPair proofKeyPair) {
        this.proofKeyPair = proofKeyPair;
    }

    public KeyPair proofKeys() {
        return proofKeyPair;
    }

    public byte[] hmacKey() {
        return hmacKey;
    }

    public void hmacKey(byte[] hmacKey) {
        this.hmacKey = hmacKey;
    }

    /**
     * Sets generated HMAC key. 32 bytes is a recommended key length.
     * 
     * @param length key length in bytes
     * @throws KeyGenError
     */
    public void useGeneratedHmacKey(int length) throws KeyGenError {
        this.hmacKey = HmacIdProvider.generateKey(length);
    }
    
    /**
     * Sets generated proof key pair.
     * @throws KeyGenError 
     */
    public void useGeneratedProofKeys() throws KeyGenError {
        this.proofKeyPair = new BCECDSASignatureProvider(curve).keygen();
    }

    /**
     * Sets JSON pointers specifying mandatory claims that are always disclosed.
     * 
     * @param selectors
     * 
     */
    public void selectors(Collection<String> selectors) {
        this.selectors = selectors;
    }

    public Collection<String> selectors() {
        return selectors;
    }
}
