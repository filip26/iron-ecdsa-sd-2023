package com.apicatalog.ld.signature.ecdsa.sd;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.SigningError;
import com.apicatalog.ld.signature.ecdsa.sd.DerivedDocument.Group;
import com.apicatalog.ld.signature.sd.DocumentSelector;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.RdfResource;
import com.apicatalog.rdf.canon.RdfCanonicalizer;
import com.apicatalog.vc.proof.BaseProofValue;
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

public class ECDSASDBaseProofValue implements BaseProofValue {

    static final byte[] BYTE_PREFIX = new byte[] { (byte) 0xd9, 0x5d, 0x00 };

    protected final DocumentLoader loader;

    protected byte[] baseSignature;
    protected byte[] proofPublicKey;
    protected byte[] hmacKey;

    protected Collection<byte[]> signatures;
    protected Collection<String> pointers;

    protected ECDSASDBaseProofValue(final DocumentLoader loader) {
        this.loader = loader;
    }

    public static boolean is(byte[] signature) {
        return signature.length > 2
                && signature[0] == BYTE_PREFIX[0]
                && signature[1] == BYTE_PREFIX[1]
                && signature[2] == BYTE_PREFIX[2];
    }

    public static ECDSASDBaseProofValue of(byte[] signature, final DocumentLoader loader) throws DocumentError {

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

            final ECDSASDBaseProofValue proofValue = new ECDSASDBaseProofValue(loader);

            proofValue.baseSignature = toByteArray(top.getDataItems().get(0));
            proofValue.proofPublicKey = toByteArray(top.getDataItems().get(1));
            proofValue.hmacKey = toByteArray(top.getDataItems().get(2));

            if (!MajorType.ARRAY.equals(top.getDataItems().get(3).getMajorType())) {
                throw new DocumentError(ErrorType.Invalid, "ProofValue");
            }

            proofValue.signatures = new ArrayList<>(((Array) top.getDataItems().get(3)).getDataItems().size());

            for (final DataItem item : ((Array) top.getDataItems().get(3)).getDataItems()) {
                proofValue.signatures.add(toByteArray(item));
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

    @Override
    public byte[] toByteArray() throws DocumentError {
        return toByteArray(baseSignature, proofPublicKey, hmacKey, signatures, pointers);
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
    public Collection<String> pointers() {
        return pointers;
    }

    @Override
    public ProofValue derive(JsonStructure context, JsonObject data, Collection<String> selectors) throws SigningError, DocumentError {

        ECDSASDDerivedProofValue derived = new ECDSASDDerivedProofValue(loader);
        derived.baseSignature = baseSignature;
        derived.proofPublicKey = proofPublicKey;
        
        HmacIdLabeLMap hmac = HmacIdLabeLMap.newInstance(hmacKey);

        Collection<String> combinedPointers = selectors != null 
                ? Stream.of(pointers, selectors).flatMap(Collection::stream).collect(Collectors.toList())
                : pointers;

        BaseDocument cdoc = BaseDocument.of(context, data, loader, hmac);
                
        DerivedDocument ddoc = new DerivedDocument(cdoc);

        Group mand = ddoc.select(DocumentSelector.of(pointers));
        Group combined = ddoc.select(DocumentSelector.of(combinedPointers));
        
        derived.indices = mandatory(combined.matching.keySet(), mand.matching.keySet());
      
        Group selective = ddoc.select(DocumentSelector.of(selectors));
        
        derived.signatures = signatures(signatures, mand.matching.keySet(), selective.matching.keySet());
        
        derived.labels = verifierLabel(combined.deskolemizedNQuads, cdoc.labelMap);

        return derived;
    }
    
    protected static Map<Integer, byte[]> verifierLabel(Collection<RdfNQuad> deskolemizedNQuads, Map<RdfResource, RdfResource> labelMap) {
        final RdfCanonicalizer canonicalizer = RdfCanonicalizer.newInstance(deskolemizedNQuads);

        canonicalizer.canonicalize();
        
        final Map<Integer, byte[]> verifierLabels = new HashMap<>();
        
        for (final Map.Entry<RdfResource, RdfResource> nquad : canonicalizer.canonIssuer().mappingTable().entrySet()) {
            verifierLabels.put(getCanonLabelIndex(nquad.getValue()), Multibase.BASE_64_URL.decode(labelMap.get(nquad.getKey()).getValue().substring("_:".length())));
        }

        return verifierLabels;
    }
    
    protected static int getCanonLabelIndex(RdfResource canonBlankId) {
        return Integer.valueOf(canonBlankId.getValue().substring("_:c14n".length()));
    }

    protected static int[] mandatory(Collection<Integer> combined, Collection<Integer> mandatory) {
        int relative = 0;
        Collection<Integer> indexes = new ArrayList<>();
        
        for (int index : combined) {
            if (mandatory.contains(index)) {
                indexes.add(relative);
            } 
            relative++;
        }
        return indexes.stream().mapToInt(Integer::intValue).toArray();
    }
    
    protected static Collection<byte[]> signatures(Collection<byte[]> signatures, Collection<Integer> mandatory, Collection<Integer> selective) {
        int index = 0;
        Collection<byte[]> filteredSignatures = new ArrayList<>();

        var x = new ArrayList<>();
        //[3,4,5,8,9,10]
        int hit = 0;
        for (byte[] signature : signatures) {
            while (mandatory.contains(index)) {
                index++;
            } 
            if (selective.contains(index)) {
                filteredSignatures.add(signature);
                x.add(hit);
            }
            index++;
            hit++;
        }
        return filteredSignatures;
    }

}
