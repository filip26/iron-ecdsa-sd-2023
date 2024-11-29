package com.apicatalog.ld.signature.ecdsa.sd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import com.apicatalog.controller.method.VerificationMethod;
import com.apicatalog.cryptosuite.CryptoSuiteError;
import com.apicatalog.cryptosuite.SigningError;
import com.apicatalog.jsonld.json.JsonLdComparison;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.linkedtree.json.JsonFragment;
import com.apicatalog.linkedtree.jsonld.io.JsonLdWriter;
import com.apicatalog.vc.VerifiableDocument;
import com.apicatalog.vc.holder.Holder;
import com.apicatalog.vc.processor.DocumentReader;
import com.apicatalog.vc.proof.Proof;
import com.apicatalog.vcdi.DataIntegrityProof;
import com.apicatalog.vcdm.v20.Vcdm20Credential;

import jakarta.json.Json;
import jakarta.json.JsonObject;

public class DeriveTest {

    static final Holder HOLDER = Holder.with(new ECDSASelective2023Suite());

    static final DocumentReader READER = DocumentReader.with(new ECDSASelective2023Suite());

    @Test
    void testDerive() throws IOException, CryptoSuiteError, DocumentError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");
        JsonObject ddoc = fetchResource("tv-01-ddoc.jsonld");

        VerifiableDocument verifiable = READER.read(sdoc);

        assertNotNull(verifiable);
        JsonLdWriter w = new JsonLdWriter()
                .scan(Vcdm20Credential.class)
                .scan(DataIntegrityProof.class)
                .scan(VerificationMethod.class)
                ;

//        var xxx = w.compacted(verifiable);
//        
//        if (!JsonLdComparison.equals(ddoc, xxx)) {
//            System.out.println("Expected:");
//            System.out.println(IssuerTest.write(ddoc));
//            System.out.println("Actual:");
//            System.out.println(IssuerTest.write(xxx));
//            fail("Expected does not match actual.");
//        }

        JsonObject derived = verifiable.proofs().iterator().next()
                .derive(Arrays.asList(
                        "/credentialSubject/boards/0",
                        "/credentialSubject/boards/1"));

        assertNotNull(derived);
        
        var dd = derived;
                //((JsonFragment)derived).jsonObject();

        if (!JsonLdComparison.equals(ddoc, dd)) {
            System.out.println("Expected:");
            System.out.println(IssuerTest.write(ddoc));
            System.out.println("Actual:");
            System.out.println(IssuerTest.write(dd));
            fail("Expected does not match actual.");
        }
    }

    @Test
    void testDeriveEmptySelectors() throws IOException, SigningError, DocumentError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");

        JsonObject derived = HOLDER.derive(sdoc, Collections.emptyList());

        assertNotNull(derived);
    }

    @Test
    void testDeriveNullSelectors() throws IOException, SigningError, DocumentError {

        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");

        JsonObject derived = HOLDER.derive(sdoc, null);

        assertNotNull(derived);
    }

    JsonObject fetchResource(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(name)) {
            return Json.createReader(is).readObject();
        }
    }
}
