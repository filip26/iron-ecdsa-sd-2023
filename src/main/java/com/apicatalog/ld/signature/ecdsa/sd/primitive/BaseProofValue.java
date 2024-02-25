package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.VerificationError;
import com.apicatalog.ld.signature.VerificationError.Code;
import com.apicatalog.vc.proof.ProofValue;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.UnicodeString;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;

public class BaseProofValue implements ProofValue {

    static final byte[] BYTE_PREFIX = new byte[] { (byte) 0xd9, 0x5d, 0x00 };

    protected byte[] baseSignature;
    protected byte[] proofPublicKey;
    protected byte[] hmacKey;

    protected Collection<byte[]> mandatory;
    protected Collection<String> pointers;

    protected BaseProofValue() {
        /* protected */}

    public static boolean is(byte[] signature) {
        return signature.length > 2
                && signature[0] == BYTE_PREFIX[0]
                && signature[1] == BYTE_PREFIX[1]
                && signature[2] == BYTE_PREFIX[2];
    }

    public static BaseProofValue of(byte[] signature) throws DocumentError {

        Objects.requireNonNull(signature);

        if (signature.length < 3) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        final ByteArrayInputStream is = new ByteArrayInputStream(signature);
        
        if ((byte)is.read() != BYTE_PREFIX[0] || is.read() != BYTE_PREFIX[1] || is.read() != BYTE_PREFIX[2]) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        final CborDecoder decoder = new CborDecoder(is);

        try {
            final List<DataItem> cbor = decoder.decode();

            if (cbor.size() != 1) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            if (!MajorType.ARRAY.equals(cbor.get(0).getMajorType())) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            final Array top = (Array) cbor.get(0);

            if (top.getDataItems().size() != 5) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            final BaseProofValue proofValue = new BaseProofValue();

            proofValue.baseSignature = toByteArray(top.getDataItems().get(0));
            proofValue.proofPublicKey = toByteArray(top.getDataItems().get(1));
            proofValue.hmacKey = toByteArray(top.getDataItems().get(2));

            if (!MajorType.ARRAY.equals(top.getDataItems().get(3).getMajorType())) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            proofValue.mandatory = new ArrayList<>(((Array) top.getDataItems().get(3)).getDataItems().size());

            for (final DataItem item : ((Array) top.getDataItems().get(3)).getDataItems()) {
                proofValue.mandatory.add(toByteArray(item));
            }

            if (!MajorType.ARRAY.equals(top.getDataItems().get(4).getMajorType())) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            proofValue.pointers = new ArrayList<>(((Array) top.getDataItems().get(4)).getDataItems().size());

            for (final DataItem item : ((Array) top.getDataItems().get(4)).getDataItems()) {
                proofValue.pointers.add(toString(item));
            }

            return proofValue;

        } catch (CborException e) {
            throw new DocumentError(e, ErrorType.Invalid, "ProofValue");
        }
    }

    public byte[] toByteArray() throws DocumentError {
        return toByteArray(baseSignature, proofPublicKey, hmacKey, mandatory, pointers);
    }

    public static byte[] toByteArray(
            byte[] baseSignature,
            byte[] proofPublicKey,
            byte[] hmacKey,
            Collection<byte[]> mandatory,
            Collection<String> pointers) throws DocumentError {

        final CborBuilder cbor = new CborBuilder();

        final ArrayBuilder<CborBuilder> top = cbor.addArray();

        top.add(baseSignature).tagged(64);
        top.add(proofPublicKey).tagged(64);
        top.add(hmacKey).tagged(64);

        final ArrayBuilder<ArrayBuilder<CborBuilder>> cborSigs = top.addArray();

        mandatory.forEach(m -> cborSigs.add(m).tagged(64));

        final ArrayBuilder<ArrayBuilder<CborBuilder>> cborPointers = top.addArray();

        pointers.forEach(cborPointers::add);

        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(BYTE_PREFIX);

            (new CborEncoder(out)).encode(cbor.build());

            return out.toByteArray();
        } catch (IOException | CborException e) {
            throw new DocumentError(e, ErrorType.Invalid, "ProofValue");
        }
    }

    protected static byte[] toByteArray(DataItem item) throws DocumentError {

        if (!MajorType.BYTE_STRING.equals(item.getMajorType())) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        return ((ByteString) item).getBytes();
    }

    protected static String toString(DataItem item) throws DocumentError {

        if (!MajorType.UNICODE_STRING.equals(item.getMajorType())) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        return ((UnicodeString) item).getString();
    }

    @Override
    public void verify(CryptoSuite crypto, JsonStructure context, JsonObject data, JsonObject unsignedProof, byte[] publicKey) throws VerificationError {
        throw new VerificationError(Code.InvalidSignature);
    }

}
