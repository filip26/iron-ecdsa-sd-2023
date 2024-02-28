package com.apicatalog.ld.signature.ecdsa.sd;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import com.apicatalog.jsonld.json.JsonLdComparison;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.SigningError;
import com.apicatalog.vc.holder.Holder;

import jakarta.json.Json;
import jakarta.json.JsonObject;

public class HolderTest {

    static final Holder HOLDER = Holder.with(new ECDSASelective2023());

    @Test
    void testDerive() throws IOException, SigningError, DocumentError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");
        JsonObject ddoc = fetchResource("tv-01-ddoc.jsonld");

        JsonObject derived = HOLDER.derive(sdoc, Arrays.asList("/credentialSubject/boards/0", "/credentialSubject/boards/1")).compacted();

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
    void testDeriveEmptySelectors() throws IOException, SigningError, DocumentError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");

        JsonObject derived = HOLDER.derive(sdoc, Collections.emptyList()).compacted();

        assertNotNull(derived);
    }

    @Test
    void testDeriveNullSelectors() throws IOException, SigningError, DocumentError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");

        JsonObject derived = HOLDER.derive(sdoc, null).compacted();

        assertNotNull(derived);
    }
    JsonObject fetchResource(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(name)) {
            return Json.createReader(is).readObject();
        }
    }
}
