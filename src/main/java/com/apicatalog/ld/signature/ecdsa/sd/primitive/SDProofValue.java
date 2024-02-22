package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.LinkedDataSuiteError.Code;
import com.apicatalog.multibase.Multibase;

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

public class SDProofValue {

    protected byte[] baseSignature;
    protected byte[] proofPublicKey;
    protected byte[] hmacKey;
    protected Collection<byte[]> mandatory;
    protected Collection<String> pointers;

    protected SDProofValue() {
        /* protected */}

    public static SDProofValue of(String encoded) throws LinkedDataSuiteError {
        return of(Multibase.BASE_64_URL.decode(encoded));
    }

    public static String encode(byte[] value) {
        return Multibase.BASE_64_URL.encode(value);
    }
    
    public String encode() throws LinkedDataSuiteError {
        return encode(toByteArray());
    }

    public static SDProofValue of(byte[] signature) throws LinkedDataSuiteError {

        CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(signature));

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

            final SDProofValue proofValue = new SDProofValue();

            proofValue.baseSignature = toByteArray(top.getDataItems().get(0));
            proofValue.proofPublicKey = toByteArray(top.getDataItems().get(1));
            proofValue.hmacKey = toByteArray(top.getDataItems().get(2));

            if (!MajorType.ARRAY.equals(top.getDataItems().get(3).getMajorType())) {
                throw new LinkedDataSuiteError(Code.Signature);
            }

            proofValue.mandatory = new ArrayList<>(((Array) top.getDataItems().get(3)).getDataItems().size());

            for (final DataItem item : ((Array) top.getDataItems().get(3)).getDataItems()) {
                proofValue.mandatory.add(toByteArray(item));
            }

            if (!MajorType.ARRAY.equals(top.getDataItems().get(4).getMajorType())) {
                throw new LinkedDataSuiteError(Code.Signature);
            }

            proofValue.pointers = new ArrayList<>(((Array) top.getDataItems().get(4)).getDataItems().size());

            for (final DataItem item : ((Array) top.getDataItems().get(4)).getDataItems()) {
                proofValue.pointers.add(toString(item));
            }

            return proofValue;

        } catch (CborException e) {
            throw new LinkedDataSuiteError(Code.Signature, e);
        }
    }

    public byte[] toByteArray() throws LinkedDataSuiteError {
        return toByteArray(baseSignature, proofPublicKey, hmacKey, mandatory, pointers);
    }

    public static byte[] toByteArray(
            byte[] baseSignature,
            byte[] proofPublicKey,
            byte[] hmacKey,
            Collection<byte[]> mandatory,
            Collection<String> pointers) throws LinkedDataSuiteError {

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
            out.write(new byte[] { (byte) 0xd9, 0x5d, 0x00 });

            (new CborEncoder(out)).encode(cbor.build());

            return out.toByteArray();
        } catch (IOException | CborException e) {
            throw new LinkedDataSuiteError(Code.Signature, e);
        }
    }

    public static void main(String[] args) throws LinkedDataSuiteError {
        var x = of(
                "u2V0AhdhAWECRYow7zOlGZ9xQySwdQy1kztwm3w-Y0uyWMpNiFKLyBnvABacrgGs5mSsfd1m_EpaWfEYb_TGUVeZTmxrn6PvV2EBYI4AkAipyzhm2PxbjPgEqUpJDsbCEdhPJ-zJdqtVEOrRMM4uT2EBYIAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7_jthAWEApVgozbnQMNw1Y5hClSZgLVnk1mElHCJ7y9VR6_3hAay3zdaGhbv9QzolQuwqM1UePFmVlDKi83jHDUz-aGfpM2EBYQLKjEoM9BHmj3tB5qOUjdSTWZgo4mfgjSQeEnJsiuOrO4Q6LTWbhh8ShmgBQuNztBcXCnlAveqv8_TxnheQt1aXYQFhAmeoEU8I1ZzxFyR-QMxwoSkqRG9E8_CaSrhH8TD2t-tV32HKAC4hJkKl6xHuz6XL2G-V0cm6d_rWozjhmmVaMjdhAWEBtAwxySlwwASjXlYLoLwyjdsIRYUa05OQzE0P4skx1-QJKi8HtGcJHtJfOTn7RhWKC0nkXODvUAChvnKDVY02T2EBYQKUB5WERpVFZL_ll9ToyWCdfTsO4qb1cFL5vdEp9yIzUS7svaa-Qx5t8FZVTD1aS6o0vhPP4yQ3iVeaWNG3yvwPYQFhAas2wx9bcEj0Sh7t8w9Cj-2FpceGpdRhaLZxYs1ZEG8-obUjb0CHOyH8S7uwDtn7oSW2oCW2SpZvlX-2jW17rmthAWEB7fh5Dz6AkfJBqFjQSZmHyZmjLSy-elOOR1wueugsgGyJWR8LMwos5Z4S1ZlRWcgF66BPwjYLuaeakc2N2jZ3i2EBYQDPKJAlF_BeBmMfa5Z0g76-aUxzzozjieOycxXQ7V_0OG2cVsCxsKpbWKIw3nMreKMUB2M-eWUZ4U1yx6mu-Ae3YQFhAO_Hj0vxsuJZzpVGtgoMKK2ZlGKvhLX3_vUCvdL-MTlszVr2iC3XJpCbOc8B_W_On-csaLPzUSvlSDtNec1ZVk9hAWEB2bYe3iy_95zezUdGp66X77IQbHhKunDI1BF0trlkrIkOCqviH4S1U3Nz4n5WWW8qsc3zAEq1Spquojg2mevHt2EBYQDkTC12M95efTs3O0g5Nno-3Ja3q_QZ-nmgVEBu-9wKkOem3PqBl3npnpMGQjR4xSzhEjaDau6nrTvBUW4hR2-DYQFhAW-otSFVlUPFmg119n3TeSE7up5hBS34AqP2TGUQA5pDGyOTetrf8qq3bWj1lpCu1Z6yEZJlQ6nrLiCoaNVhpL9hAWEDXBb8eGxM9R9SWoxfpkywt6byFtZoV7-tkOk-nk03Ta8wcicOM7UafQGtdTJUAydNjd8asOOy7LawaAzNH5ujX2EBYQLzhklx-dXkaAlrVfS5aWQ9dIsdCLrlQp2reX0cVO4ahrNAMzNPZBrJrgzEY6MKedcYYhSd4jGoyDjoVlIT8RwqFZy9pc3N1ZXJ4HS9jcmVkZW50aWFsU3ViamVjdC9zYWlsTnVtYmVyeBovY3JlZGVudGlhbFN1YmplY3Qvc2FpbHMvMXggL2NyZWRlbnRpYWxTdWJqZWN0L2JvYXJkcy8wL3llYXJ4Gi9jcmVkZW50aWFsU3ViamVjdC9zYWlscy8y");
    }

    protected static byte[] toByteArray(DataItem item) throws LinkedDataSuiteError {

        if (!MajorType.BYTE_STRING.equals(item.getMajorType())) {
            throw new LinkedDataSuiteError(Code.Signature);
        }

        return ((ByteString) item).getBytes();
    }

    protected static String toString(DataItem item) throws LinkedDataSuiteError {

        if (!MajorType.UNICODE_STRING.equals(item.getMajorType())) {
            throw new LinkedDataSuiteError(Code.Signature);
        }

        return ((UnicodeString) item).getString();
    }
}
