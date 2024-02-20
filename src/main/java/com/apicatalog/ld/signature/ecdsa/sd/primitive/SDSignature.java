package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.SigningError;
import com.apicatalog.ld.signature.algorithm.CanonicalizationAlgorithm;
import com.apicatalog.ld.signature.algorithm.DigestAlgorithm;
import com.apicatalog.ld.signature.algorithm.SignatureAlgorithm;
import com.apicatalog.rdf.RdfNQuad;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
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

    public byte[] sign(
            JsonObject unsignedProof,
            Collection<RdfNQuad> mandatory,
            byte[] proofPublicKey,
            byte[] privateKey) throws SigningError, LinkedDataSuiteError {

        final byte[] proofHash = digest.digest(canonicalizer.canonicalize(unsignedProof));
        final byte[] mandatoryHash = hash(mandatory);

        final byte[] hash = new byte[proofHash.length
                + proofPublicKey.length
                + mandatoryHash.length];

        System.arraycopy(proofHash, 0, hash, 0, proofHash.length);
        System.arraycopy(proofPublicKey, 0, hash, proofHash.length, proofPublicKey.length);
        System.arraycopy(mandatoryHash, 0, hash, proofHash.length + proofPublicKey.length, mandatoryHash.length);

        return signer.sign(privateKey, hash);
    }

    public byte[] sign(final String nquad, byte[] proofPrivateKey) throws SigningError {
        return signer.sign(proofPrivateKey, nquad.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] serialize(
            byte[] baseSignature,
            byte[] publicKey,
            byte[] hmacKey,
            Collection<byte[]> mandatory,
            Collection<String> pointers) throws CborException, IOException {

        final CborBuilder cbor = new CborBuilder();

        final ArrayBuilder<CborBuilder> top = cbor.addArray();

        top.add(baseSignature).tagged(64);
        top.add(publicKey).tagged(64);
        top.add(hmacKey).tagged(64);

        final ArrayBuilder<ArrayBuilder<CborBuilder>> cborSigs = top.addArray();

        mandatory.forEach(m -> cborSigs.add(m).tagged(64));

        final ArrayBuilder<ArrayBuilder<CborBuilder>> cborPointers = top.addArray();

        pointers.forEach(m -> cborPointers.add(m).tagged(64));

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[] { (byte) 0xd9, 0x5d, 0x00 });

        (new CborEncoder(out)).encode(cbor.build());

        return out.toByteArray();
    }

    private byte[] hash(Collection<RdfNQuad> nquads) throws LinkedDataSuiteError {

        StringWriter writer = new StringWriter(nquads.size() * 100);

        nquads.stream().forEach(x -> writer.write(x.toString()));

        return digest.digest(writer.toString().getBytes(StandardCharsets.UTF_8));
    }

}
