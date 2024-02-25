package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.util.encoders.Hex;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.VerificationError;
import com.apicatalog.ld.signature.VerificationError.Code;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.vc.proof.ProofValue;

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
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;

public class DerivedProofValue implements ProofValue {

    protected static final byte[] BYTE_PREFIX = new byte[] { (byte) 0xd9, 0x5d, 0x01 };

    protected final DocumentLoader loader;

    protected byte[] baseSignature;
    protected byte[] proofPublicKey;

    protected List<byte[]> signatures;
    protected Map<Integer, byte[]> labels;
    protected int[] indices;

    protected DerivedProofValue(final DocumentLoader loader) {
        this.loader = loader;
    }

    public static boolean is(byte[] signature) {
        return signature.length > 2
                && signature[0] == BYTE_PREFIX[0]
                && signature[1] == BYTE_PREFIX[1]
                && signature[2] == BYTE_PREFIX[2];
    }

    public static DerivedProofValue of(byte[] signature, DocumentLoader loader) throws DocumentError {

        Objects.requireNonNull(signature);

        if (signature.length < 3) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        final ByteArrayInputStream is = new ByteArrayInputStream(signature);

        if ((byte) is.read() != BYTE_PREFIX[0] || is.read() != BYTE_PREFIX[1] || is.read() != BYTE_PREFIX[2]) {
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

            final DerivedProofValue proofValue = new DerivedProofValue(loader);

            proofValue.baseSignature = toByteArray(top.getDataItems().get(0));
            proofValue.proofPublicKey = toByteArray(top.getDataItems().get(1));

            if (!MajorType.ARRAY.equals(top.getDataItems().get(2).getMajorType())) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            proofValue.signatures = new ArrayList<>(((Array) top.getDataItems().get(2)).getDataItems().size());

            for (final DataItem item : ((Array) top.getDataItems().get(2)).getDataItems()) {
                proofValue.signatures.add(toByteArray(item));
            }

            // label map
            if (!MajorType.MAP.equals(top.getDataItems().get(3).getMajorType())) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            final co.nstant.in.cbor.model.Map labels = (co.nstant.in.cbor.model.Map) top.getDataItems().get(3);

            proofValue.labels = new LinkedHashMap<>(labels.getKeys().size());

            for (final DataItem key : labels.getKeys()) {
                proofValue.labels.put(toUInt(key), toByteArray(labels.get(key)));
            }

            // indices
            if (!MajorType.ARRAY.equals(top.getDataItems().get(4).getMajorType())) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            proofValue.indices = new int[(((Array) top.getDataItems().get(4)).getDataItems().size())];

            for (int i = 0; i < proofValue.indices.length; i++) {
                final DataItem item = ((Array) top.getDataItems().get(4)).getDataItems().get(i);
                proofValue.indices[i] = toUInt(item);
            }

            return proofValue;

        } catch (CborException e) {
            throw new DocumentError(e, ErrorType.Invalid, "ProofValue");
        }
    }

    public byte[] toByteArray() throws DocumentError {
        return toByteArray(baseSignature, proofPublicKey, signatures, labels, indices);
    }

    public static byte[] toByteArray(
            byte[] baseSignature,
            byte[] proofPublicKey,
            Collection<byte[]> signatures,
            Map<Integer, byte[]> labels,
            int[] indices) throws DocumentError {

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
            throw new DocumentError(e, ErrorType.Invalid, "ProofValue");
        }
    }

    protected static byte[] toByteArray(DataItem item) throws DocumentError {

        if (!MajorType.BYTE_STRING.equals(item.getMajorType())) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        return ((ByteString) item).getBytes();
    }

    protected static int toUInt(DataItem item) throws DocumentError {

        if (!MajorType.UNSIGNED_INTEGER.equals(item.getMajorType())) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        return ((UnsignedInteger) item).getValue().intValueExact();
    }

    @Override
    public void verify(CryptoSuite cryptoSuite, JsonStructure context, JsonObject data, JsonObject unsignedProof, byte[] publicKey) throws VerificationError {

        // TODO Auto-generated method stub
        System.out.println("TODO verify derived proof");
        System.out.println("  baseSignature: " + Hex.toHexString(baseSignature));
        System.out.println("  proofPublicKey: " + Multibase.BASE_58_BTC.encode(proofPublicKey));
        System.out.println("  inidices: " + Arrays.toString(indices));
        System.out.println("  labels: " + labels.size());
        System.out.println("  signatures: " + signatures.size());

        final SDSignature signer = new SDSignature(cryptoSuite, cryptoSuite, cryptoSuite);

        try {
            final byte[] proofHash = signer.hash(unsignedProof);
            System.out.println("  proofHash: " + Hex.toHexString(proofHash));

            final VerifyData verifyData = VerifyData.of(context, data, loader, labels, indices);

            final byte[] mandatoryHash = signer.hash(verifyData.mandatory);
            
            System.out.println("  mandatoryHash: " + Hex.toHexString(mandatoryHash));
            System.out.println("  nonMandatory: " + verifyData.nonMandatory.size());
//            final Map<Integer, RdfNQuad> selected = cdoc.select(Selector.of(selectors));

            if (signatures.size() != verifyData.nonMandatory.size()) {
                throw new VerificationError(Code.InvalidSignature);
            }
            
            final byte[] signature = SDSignature.hash(proofHash, proofPublicKey, mandatoryHash);
            
            System.out.println("  signature: " + Hex.toHexString(signature));
            
            signer.verify(publicKey, baseSignature, signature);
            
            
            verifyData.nonMandatory.forEach(System.out::println);
            for (int i = 0; i < signatures.size(); i++) {
                signer.verify(KeyCodec.P256_PUBLIC_KEY.decode(proofPublicKey), signatures.get(i), (verifyData.nonMandatory.get(i).toString() + '\n').getBytes(StandardCharsets.UTF_8));
            }
            
            
            System.out.println(">> DONE");
            
        } catch (LinkedDataSuiteError | DocumentError e) {
            throw new VerificationError(Code.InvalidSignature, e);
        }

        throw new UnsupportedOperationException();
    }
    
}
