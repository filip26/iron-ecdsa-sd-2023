package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.LinkedDataSuiteError.Code;
import com.apicatalog.multibase.Multibase;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.UnsignedInteger;

public class DerivedProofValue {

    protected static final byte[] BYTE_PREFIX = new byte[] { (byte) 0xd9, 0x5d, 0x01 };
    
    protected byte[] baseSignature;
    protected byte[] proofPublicKey;

    protected Collection<byte[]> signatures;
    protected Map<Integer, byte[]> labels;
    protected int[] indices;

    protected DerivedProofValue() {
        /* protected */}

    public static DerivedProofValue of(String encoded) throws LinkedDataSuiteError {
        return of(Multibase.BASE_64_URL.decode(encoded));
    }

    public static String encode(byte[] signature) {

        Objects.requireNonNull(signature);

        return Multibase.BASE_64_URL.encode(signature);
    }

    public String encode() throws LinkedDataSuiteError {
        return encode(toByteArray());
    }

    public static DerivedProofValue of(byte[] signature) throws LinkedDataSuiteError {

        Objects.requireNonNull(signature);

        if (signature.length < 3) {
            throw new LinkedDataSuiteError(Code.Signature);
        }

        final ByteArrayInputStream is = new ByteArrayInputStream(signature);

        if (is.read() != BYTE_PREFIX[0] || is.read() != BYTE_PREFIX[1] || is.read() != BYTE_PREFIX[2]) {
            throw new LinkedDataSuiteError(Code.Signature);
        }

        final CborDecoder decoder = new CborDecoder(is);

        try {
            final List<DataItem> cbor = decoder.decode();

            if (cbor.size() != 1) {
                throw new LinkedDataSuiteError(Code.Signature);
            }

            if (!MajorType.ARRAY.equals(cbor.get(0).getMajorType())) {
                throw new LinkedDataSuiteError(Code.Signature);
            }

            final Array top = (Array) cbor.get(0);

            if (top.getDataItems().size() != 5) {
                throw new LinkedDataSuiteError(Code.Signature);
            }

            final DerivedProofValue proofValue = new DerivedProofValue();

            proofValue.baseSignature = toByteArray(top.getDataItems().get(0));
            proofValue.proofPublicKey = toByteArray(top.getDataItems().get(1));

            if (!MajorType.ARRAY.equals(top.getDataItems().get(2).getMajorType())) {
                throw new LinkedDataSuiteError(Code.Signature);
            }

            proofValue.signatures = new ArrayList<>(((Array) top.getDataItems().get(2)).getDataItems().size());

            for (final DataItem item : ((Array) top.getDataItems().get(2)).getDataItems()) {
                proofValue.signatures.add(toByteArray(item));
            }

            // label map
            if (!MajorType.MAP.equals(top.getDataItems().get(3).getMajorType())) {
                throw new LinkedDataSuiteError(Code.Signature);
            }

            final co.nstant.in.cbor.model.Map labels = (co.nstant.in.cbor.model.Map) top.getDataItems().get(3);

            proofValue.labels = new LinkedHashMap<>(labels.getKeys().size());

            for (final DataItem key : labels.getKeys()) {
                proofValue.labels.put(toUInt(key), toByteArray(labels.get(key)));
            }

            // indices
            if (!MajorType.ARRAY.equals(top.getDataItems().get(4).getMajorType())) {
                throw new LinkedDataSuiteError(Code.Signature);
            }

            proofValue.indices = new int[(((Array) top.getDataItems().get(4)).getDataItems().size())];

            for (int i = 0; i < proofValue.indices.length; i++) {
                final DataItem item = ((Array) top.getDataItems().get(4)).getDataItems().get(i);
                proofValue.indices[i] = toUInt(item);
            }

            return proofValue;

        } catch (CborException e) {
            throw new LinkedDataSuiteError(Code.Signature, e);
        }
    }

    public byte[] toByteArray() throws LinkedDataSuiteError {
        return toByteArray(baseSignature, proofPublicKey, signatures, labels, indices);
    }

    public static byte[] toByteArray(
            byte[] baseSignature,
            byte[] proofPublicKey,
            Collection<byte[]> signatures,
            Map<Integer, byte[]> labels,
            int[] indices) throws LinkedDataSuiteError {

        final CborBuilder cbor = new CborBuilder();

        final ArrayBuilder<CborBuilder> top = cbor.addArray();

        top.add(baseSignature).tagged(64);
        top.add(proofPublicKey).tagged(64);

        final ArrayBuilder<ArrayBuilder<CborBuilder>> cborSigs = top.addArray();

        signatures.forEach(m -> cborSigs.add(m).tagged(64));

        final MapBuilder<ArrayBuilder<CborBuilder>> cborLabels = top.addMap();

        labels.entrySet().forEach(e -> cborLabels.put(e.getKey(), e.getValue()).tagged(64));

        final ArrayBuilder<ArrayBuilder<CborBuilder>> cborIndices = top.addArray().tagged(64);
        for (int i = 0; i < indices.length; i++) {
            cborIndices.add(new UnsignedInteger(indices[i]));
        }

        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(BYTE_PREFIX);

            (new CborEncoder(out)).encode(cbor.build());

            return out.toByteArray();
        } catch (IOException | CborException e) {
            throw new LinkedDataSuiteError(Code.Signature, e);
        }
    }

    protected static byte[] toByteArray(DataItem item) throws LinkedDataSuiteError {

        if (!MajorType.BYTE_STRING.equals(item.getMajorType())) {
            throw new LinkedDataSuiteError(Code.Signature);
        }

        return ((ByteString) item).getBytes();
    }

    protected static int toUInt(DataItem item) throws LinkedDataSuiteError {

        if (!MajorType.UNSIGNED_INTEGER.equals(item.getMajorType())) {
            throw new LinkedDataSuiteError(Code.Signature);
        }

        return ((UnsignedInteger) item).getValue().intValueExact();
    }
}
