package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;

import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.SigningError;
import com.apicatalog.ld.signature.VerificationError;
import com.apicatalog.ld.signature.algorithm.CanonicalizationAlgorithm;
import com.apicatalog.ld.signature.algorithm.DigestAlgorithm;
import com.apicatalog.ld.signature.algorithm.SignatureAlgorithm;
import com.apicatalog.rdf.RdfNQuad;

import jakarta.json.JsonObject;

public class SDSignature {

    final SignatureAlgorithm signer;
    final CanonicalizationAlgorithm canonicalizer;
    final DigestAlgorithm digest;

    public SDSignature(final SignatureAlgorithm signer, final CanonicalizationAlgorithm canonicalizer, DigestAlgorithm digest) {
        this.signer = signer;
        this.canonicalizer = canonicalizer;
        this.digest = digest;
    }

    public byte[] signature(
            JsonObject unsignedProof,
            Collection<RdfNQuad> mandatory,
            byte[] proofPublicKey,
            byte[] privateKey) throws SigningError, LinkedDataSuiteError {
        return signer.sign(privateKey, hash(
                hash(unsignedProof),
                proofPublicKey,
                hash(mandatory)));
    }

    public static byte[] hash(
            final byte[] proofHash,
            final byte[] proofPublicKey,
            byte[] mandatoryHash) {

        final byte[] hash = new byte[proofHash.length
                + proofPublicKey.length
                + mandatoryHash.length];

        System.arraycopy(proofHash, 0, hash, 0, proofHash.length);
        System.arraycopy(proofPublicKey, 0, hash, proofHash.length, proofPublicKey.length);
        System.arraycopy(mandatoryHash, 0, hash, proofHash.length + proofPublicKey.length, mandatoryHash.length);
        return hash;
    }

    public byte[] hash(JsonObject unsignedProof) throws LinkedDataSuiteError {
        return digest.digest(canonicalizer.canonicalize(unsignedProof));
    }

    public byte[] hash(final Collection<RdfNQuad> nquads) throws LinkedDataSuiteError {
        StringWriter writer = new StringWriter(nquads.size() * 100);

        nquads.stream().forEach(x -> writer.write(x.toString() + '\n'));

        return digest.digest(writer.toString().getBytes(StandardCharsets.UTF_8));
    }

    public Collection<byte[]> signatures(final Collection<RdfNQuad> nquads, byte[] proofPrivateKey) throws SigningError {
        final Collection<byte[]> signatures = new ArrayList<>(nquads.size());
        for (final RdfNQuad nquad : nquads) {
            signatures.add(signature(nquad, proofPrivateKey));
        }
        return signatures;
    }

    public byte[] signature(final RdfNQuad nquad, byte[] proofPrivateKey) throws SigningError {
        return signer.sign(proofPrivateKey, (nquad.toString() + '\n').getBytes(StandardCharsets.UTF_8));
    }
    
    public void verify(byte[] publicKey, byte[] signature, byte[] data) throws VerificationError {
        signer.verify(publicKey, signature, data);
    }
}
