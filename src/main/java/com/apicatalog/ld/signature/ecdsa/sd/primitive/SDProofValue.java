package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.LinkedDataSuiteError.Code;
import com.apicatalog.multibase.Multibase;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;

public class SDProofValue {

    public static String toString(byte[] value) {
        return Multibase.BASE_64_URL.encode(value);
    }
    
    public static byte[] compute(
            byte[] baseSignature,
            byte[] publicKey,
            byte[] hmacKey,
            Collection<byte[]> mandatory,
            Collection<String> pointers) throws LinkedDataSuiteError {

        final CborBuilder cbor = new CborBuilder();

        final ArrayBuilder<CborBuilder> top = cbor.addArray();

        top.add(baseSignature).tagged(64);
        top.add(publicKey).tagged(64);
        top.add(hmacKey).tagged(64);

        final ArrayBuilder<ArrayBuilder<CborBuilder>> cborSigs = top.addArray();

        mandatory.forEach(m -> cborSigs.add(m).tagged(64));

        final ArrayBuilder<ArrayBuilder<CborBuilder>> cborPointers = top.addArray();

        pointers.forEach(m -> cborPointers.add(m).tagged(64));
        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new byte[] { (byte) 0xd9, 0x5d, 0x00 });

            (new CborEncoder(out)).encode(cbor.build());

            return out.toByteArray();
        } catch (IOException | CborException e) {
            throw new LinkedDataSuiteError(Code.Signature, e);
        }
    }
}
