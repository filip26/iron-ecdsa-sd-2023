package com.apicatalog.ld.signature.ecdsa.sd;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import com.apicatalog.cryptosuite.VerificationError;
import com.apicatalog.did.key.DidKey;
import com.apicatalog.did.key.DidKeyResolver;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.SchemeRouter;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.vc.VerifiableDocument;
import com.apicatalog.vc.loader.StaticContextLoader;
import com.apicatalog.vc.method.resolver.ControllableKeyProvider;
import com.apicatalog.vc.method.resolver.MethodPredicate;
import com.apicatalog.vc.method.resolver.MethodSelector;
import com.apicatalog.vc.method.resolver.VerificationKeyProvider;
import com.apicatalog.vc.verifier.Verifier;

import jakarta.json.Json;
import jakarta.json.JsonObject;

public class VerifierTest {

    public final static DocumentLoader LOADER = new StaticContextLoader(new SchemeRouter());
//    public final static DocumentLoader LOADER = new StaticContextLoader(
//            new UriBaseRewriter(
//                    VcTestCase.BASE,
//                    "classpath:",
//                    new SchemeRouter().set("classpath", new ClasspathLoader())));

    static final Verifier VERIFIER = Verifier.with(new ECDSASelective2023Suite())
            .methodResolver(defaultResolvers(LOADER));

    @Test
    void testVerifyBase() throws IOException, VerificationError, DocumentError {
        JsonObject sdoc = fetchResource("tv-01-sdoc.jsonld");
        assertThrows(VerificationError.class, () -> VERIFIER.verify(sdoc));
    }

    @Test
    void testVerifyDerived() throws IOException, VerificationError, DocumentError {

        JsonObject ddoc = fetchResource("tv-01-ddoc.jsonld");

        VerifiableDocument verifiable = VERIFIER.verify(ddoc);

        assertNotNull(verifiable);
    }

    @Test
    void testVerifyDerivedMandatory() throws IOException, VerificationError, DocumentError {

        JsonObject ddoc = fetchResource("tv-01-mdoc.jsonld");

        VerifiableDocument verifiable = VERIFIER.verify(ddoc);

        assertNotNull(verifiable);
    }

    JsonObject fetchResource(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(name)) {
            return Json.createReader(is).readObject();
        }
    }

    static final VerificationKeyProvider defaultResolvers(DocumentLoader loader) {
        return MethodSelector.create()
                // accept did:key
                .with(MethodPredicate.methodId(DidKey::isDidKeyUrl),
                        ControllableKeyProvider.of(new DidKeyResolver(ECDSASelective2023Suite.CODECS)))
                .build();
    }
}
