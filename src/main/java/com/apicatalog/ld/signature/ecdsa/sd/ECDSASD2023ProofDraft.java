package com.apicatalog.ld.signature.ecdsa.sd;

import java.net.URI;
import java.util.Collection;

import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.vc.integrity.DataIntegrityProofDraft;
import com.apicatalog.vc.integrity.DataIntegritySuite;

public class ECDSASD2023ProofDraft extends DataIntegrityProofDraft {

    private KeyPair proofKeyPair;

    private byte[] hmacKey;

    protected Collection<String> selectors;

    protected ECDSASD2023ProofDraft(
            DataIntegritySuite suite, 
            CryptoSuite crypto, 
            URI method,
            URI purpose         
            ) {
        super(suite, crypto, method, purpose);
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
