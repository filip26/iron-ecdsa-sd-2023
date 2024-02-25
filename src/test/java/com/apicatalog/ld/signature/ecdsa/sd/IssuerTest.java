package com.apicatalog.ld.signature.ecdsa.sd;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.json.JsonLdComparison;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.SigningError;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.multikey.MultiKey;
import com.apicatalog.vc.VcVocab;
import com.apicatalog.vc.issuer.Issuer;

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
    void testSign() throws IOException, LinkedDataSuiteError, JsonLdError, SigningError, DocumentError {

        JsonObject udoc = fetchResource("tv-01-udoc.jsonld");
        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");

        byte[] privateKey = KeyCodec.P256_PRIVATE_KEY.decode(Multibase.BASE_58_BTC.decode("z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN"));
        byte[] proofPublicKey = Multibase.BASE_58_BTC.decode("zDnaeTHfhmSaQKBc7CmdL3K7oYg3D6SC7yowe2eBeVd2DH32r");
        byte[] proofPrivateKey = KeyCodec.P256_PRIVATE_KEY.decode(Multibase.BASE_58_BTC.decode("z42tqvNGyzyXRzotAYn43UhcFtzDUVdxJ7461fwrfhBPLmfY"));
        byte[] hmacKey = Hex.decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

        MultiKey keys = new MultiKey();
        keys.setPrivateKey(privateKey);

        MultiKey proofKeys = new MultiKey();
        proofKeys.setPublicKey(proofPublicKey);
        proofKeys.setPrivateKey(proofPrivateKey);

        final ECDSASD2023Suite suite = new ECDSASD2023Suite();

        final ECDSASD2023ProofDraft draft = suite.createP256Draft(
                URI.create("did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"),
                URI.create(VcVocab.SECURITY_VOCAB + "assertionMethod")
                );
        draft.created(Instant.parse("2023-08-15T23:36:38Z"));
        draft.selectors(MP_TV);
        draft.proofKeys(proofKeys);
        draft.hmacKey(hmacKey);

        Issuer issuer = suite.createIssuer(keys);

        JsonObject signed = issuer.sign(udoc, draft).compacted();

        assertNotNull(signed);

        if (!JsonLdComparison.equals(sdoc, signed)) {
            System.out.println("Expected:");
            System.out.println(write(sdoc));
            System.out.println("Actual:");
            System.out.println(write(signed));
            fail("Expected does not match actual.");
        }
    }

    JsonObject fetchResource(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(name)) {
            return Json.createReader(is).readObject();
        }
    }

    public static String write(JsonValue doc) {
        var sw = new StringWriter();
        final JsonWriterFactory writerFactory = Json.createWriterFactory(
                Collections.singletonMap(JsonGenerator.PRETTY_PRINTING, true));

        try (JsonWriter writer = writerFactory.createWriter(sw)) {
            writer.write(doc);
        }
        return sw.toString();
    }
}
