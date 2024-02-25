package com.apicatalog.ld.signature.ecdsa.sd;

import java.util.Collection;

import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.vc.integrity.DataIntegrityProofDraft;

import jakarta.json.JsonObject;

public class ECDSASD2023ProofDraft extends DataIntegrityProofDraft {

    private KeyPair proofKeyPair;

    private byte[] hmacKey;

    protected Collection<String> selectors;

    protected ECDSASD2023ProofDraft(CryptoSuite crypto, JsonObject expandedProof) {
        super(crypto, expandedProof);
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
