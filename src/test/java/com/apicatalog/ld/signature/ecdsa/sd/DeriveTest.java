package com.apicatalog.ld.signature.ecdsa.sd;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import com.apicatalog.cryptosuite.CryptoSuiteError;
import com.apicatalog.jsonld.json.JsonLdComparison;
import com.apicatalog.vc.VerifiableDocument;
import com.apicatalog.vc.model.DocumentError;
import com.apicatalog.vc.processor.DocumentReader;
import com.apicatalog.vc.proof.Proof;

import jakarta.json.Json;
import jakarta.json.JsonObject;

public class DeriveTest {

    static final DocumentReader READER = DocumentReader.with(new ECDSASD2023Suite());

    @Test
    void testDerive() throws IOException, CryptoSuiteError, DocumentError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");
        JsonObject ddoc = fetchResource("tv-01-ddoc.jsonld");

        VerifiableDocument document = READER.read(sdoc);

        assertNotNull(document);

        Proof proof = document.proofs().iterator().next();

        JsonObject derived = proof
                .derive(Arrays.asList(
                        "/credentialSubject/boards/0",
                        "/credentialSubject/boards/1"));

        assertNotNull(derived);

        if (!JsonLdComparison.equals(ddoc, derived)) {
            System.out.println("Expected:");
            System.out.println(IssuerTest.write(ddoc));
            System.out.println("Actual:");
            System.out.println(IssuerTest.write(derived));
            fail("Expected does not match actual.");
        }
    }

    @Test
    void testDeriveEmptySelectors() throws IOException, CryptoSuiteError, DocumentError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");
        JsonObject mdoc = fetchResource("tv-01-mdoc.jsonld");

        VerifiableDocument verifiable = READER.read(sdoc);

        assertNotNull(verifiable);

        Proof proof = verifiable.proofs().iterator().next();

        JsonObject derived = proof.derive(Collections.emptyList());

        assertNotNull(derived);

        if (!JsonLdComparison.equals(mdoc, derived)) {
            System.out.println("Expected:");
            System.out.println(IssuerTest.write(mdoc));
            System.out.println("Actual:");
            System.out.println(IssuerTest.write(derived));
            fail("Expected does not match actual.");
        }
    }

    @Test
    void testDeriveNullSelectors() throws IOException, DocumentError, CryptoSuiteError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");
        JsonObject mdoc = fetchResource("tv-01-mdoc.jsonld");

        VerifiableDocument verifiable = READER.read(sdoc);

        assertNotNull(verifiable);

        Proof proof = verifiable.proofs().iterator().next();

        JsonObject derived = proof.derive(null);

        assertNotNull(derived);

        if (!JsonLdComparison.equals(mdoc, derived)) {
            System.out.println("Expected:");
            System.out.println(IssuerTest.write(mdoc));
            System.out.println("Actual:");
            System.out.println(IssuerTest.write(derived));
            fail("Expected does not match actual.");
        }
    }

    JsonObject fetchResource(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(name)) {
            return Json.createReader(is).readObject();
        }
    }
}
