package com.apicatalog.ld.signature.ecdsa.sd;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.VerificationError;
import com.apicatalog.vc.Verifiable;
import com.apicatalog.vc.verifier.Verifier;

import jakarta.json.Json;
import jakarta.json.JsonObject;

public class VerifierTest {

    static final Verifier VERIFIER = Verifier.with(new ECDSASD2023Suite());
    
    @Test
    void testVerifyBase() throws IOException  {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");

        assertThrows(VerificationError.class, () -> VERIFIER.verify(sdoc));        
    }
    
    @Test
    void testVerifyDerived() throws IOException, VerificationError, DocumentError {

        JsonObject ddoc = fetchResource("tv-01-ddoc.jsonld");

        Verifiable verifiable = VERIFIER.verify(ddoc);
        
        assertNotNull(verifiable);
    }

    JsonObject fetchResource(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(name)) {
            return Json.createReader(is).readObject();
        }
    }
}
