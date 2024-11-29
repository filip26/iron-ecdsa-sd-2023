package com.apicatalog.ld.signature.ecdsa.sd;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import com.apicatalog.cryptosuite.CryptoSuiteError;
import com.apicatalog.cryptosuite.KeyGenError;
import com.apicatalog.cryptosuite.SigningError;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.KeyCodec;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.json.JsonWriter;
import jakarta.json.JsonWriterFactory;
import jakarta.json.stream.JsonGenerator;

public class IssuerTest {

    final static Collection<String> MP_TV = Arrays.asList(
            "/issuer",
            "/credentialSubject/sailNumber",
            "/credentialSubject/sails/1",
            "/credentialSubject/boards/0/year",
            "/credentialSubject/sails/2");

    @Test
    void testSign() throws IOException, CryptoSuiteError, JsonLdError, SigningError, DocumentError {

        JsonObject udoc = fetchResource("tv-01-udoc.jsonld");
        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");

        byte[] privateKey = KeyCodec.P256_PRIVATE_KEY.decode(Multibase.BASE_58_BTC.decode("z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN"));
        byte[] proofPublicKey = KeyCodec.P256_PUBLIC_KEY.decode(Multibase.BASE_58_BTC.decode("zDnaeTHfhmSaQKBc7CmdL3K7oYg3D6SC7yowe2eBeVd2DH32r"));
        byte[] proofPrivateKey = KeyCodec.P256_PRIVATE_KEY.decode(Multibase.BASE_58_BTC.decode("z42tqvNGyzyXRzotAYn43UhcFtzDUVdxJ7461fwrfhBPLmfY"));
        byte[] hmacKey = Hex.decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

//        MultiKey keys = new MultiKey();
//        keys.setPrivateKey(privateKey);
//
//        MultiKey proofKeys = new MultiKey();
//        proofKeys.setPublicKey(proofPublicKey);
//        proofKeys.setPrivateKey(proofPrivateKey);

        final ECDSASelective2023Suite suite = new ECDSASelective2023Suite();

//        final ECDSASelective2023ProofDraft draft = suite.createP256Draft(
//                URI.create("did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"),
//                URI.create(VcdmVocab.SECURITY_VOCAB + "assertionMethod")
//                );
//
//        draft.created(Instant.parse("2023-08-15T23:36:38Z"));
//        draft.selectors(MP_TV);
//        draft.proofKeys(proofKeys);
//        draft.hmacKey(hmacKey);
//
//        Issuer issuer = suite.createIssuer(keys);
//
//        JsonObject signed = issuer.sign(udoc, draft).compacted();
//
//        assertNotNull(signed);
//
//        if (!JsonLdComparison.equals(sdoc, signed)) {
//            System.out.println("Expected:");
//            System.out.println(write(sdoc));
//            System.out.println("Actual:");
//            System.out.println(write(signed));
//            fail("Expected does not match actual.");
//        }
    }

    @Test
    void testSignGeneratedKeys() throws IOException, CryptoSuiteError, JsonLdError, SigningError, DocumentError, KeyGenError {

        JsonObject udoc = fetchResource("tv-01-udoc.jsonld");

        byte[] privateKey = KeyCodec.P256_PRIVATE_KEY.decode(Multibase.BASE_58_BTC.decode("z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN"));

//        MultiKey keys = new MultiKey();
//        keys.setPrivateKey(privateKey);
//
//        final ECDSASelective2023 suite = new ECDSASelective2023();
//
//        final ECDSASelective2023ProofDraft draft = suite.createP256Draft(
//                URI.create("did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"),
//                URI.create(VcVocab.SECURITY_VOCAB + "assertionMethod")
//                );
//        draft.created(Instant.parse("2023-08-15T23:36:38Z"));
//        draft.selectors(MP_TV);
//        draft.useGeneratedHmacKey(32);
//        draft.useGeneratedProofKeys();
//
//        Issuer issuer = suite.createIssuer(keys);
//
//        JsonObject signed = issuer.sign(udoc, draft).compacted();
//
//        assertNotNull(signed);
    }
    
    JsonObject fetchResource(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(name)) {
            return Json.createReader(is).readObject();
        }
    }

    public static String write(JsonValue doc) {
        StringWriter sw = new StringWriter();
        final JsonWriterFactory writerFactory = Json.createWriterFactory(
                Collections.singletonMap(JsonGenerator.PRETTY_PRINTING, true));

        try (JsonWriter writer = writerFactory.createWriter(sw)) {
            writer.write(doc);
        }
        return sw.toString();
    }
}
