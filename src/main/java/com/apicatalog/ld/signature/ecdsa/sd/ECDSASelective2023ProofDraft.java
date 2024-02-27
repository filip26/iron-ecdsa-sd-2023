package com.apicatalog.ld.signature.ecdsa.sd;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.KeyGenError;
import com.apicatalog.ld.signature.ecdsa.sd.BCECDSASignatureProvider.CurveType;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.vc.integrity.DataIntegrityProofDraft;
import com.apicatalog.vc.integrity.DataIntegritySuite;

public class ECDSASelective2023ProofDraft extends DataIntegrityProofDraft {

    private final CurveType curve;
    
    private KeyPair proofKeyPair;

    private byte[] hmacKey;

    protected Collection<String> selectors;

    protected ECDSASelective2023ProofDraft(
            DataIntegritySuite suite,
            CurveType curve,
            CryptoSuite crypto, 
            URI method,
            URI purpose         
            ) {
        super(suite, crypto, method, purpose);
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
     * Sets generated HMAC key.
     * 
     * @param length
     * @throws NoSuchAlgorithmException
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
