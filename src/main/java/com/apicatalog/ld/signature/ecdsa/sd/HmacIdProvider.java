package com.apicatalog.ld.signature.ecdsa.sd;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.apicatalog.cryptosuite.KeyGenError;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.rdf.Rdf;
import com.apicatalog.rdf.RdfResource;

class HmacIdProvider {

    final Map<RdfResource, RdfResource> mapping = new HashMap<>();
    final Mac hmac;

    protected HmacIdProvider(Mac hmac) {
        this.hmac = hmac;
    }

    public RdfResource getHmacId(final RdfResource resource) {

        RdfResource hmacId = mapping.get(resource);

        if (hmacId == null) {
            hmacId = Rdf.createBlankNode("_:" + Multibase.BASE_64_URL.encode(hmac.doFinal(resource.getValue().substring(2).getBytes(StandardCharsets.UTF_8))));
            hmac.reset();
            mapping.put(resource, hmacId);
        }
        return hmacId;
    }

    public static HmacIdProvider newInstance(final byte[] hmacKey) {
        final SecretKeySpec key = new SecretKeySpec(hmacKey, "HmacSHA256");
        try {
            final Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(key);
            return new HmacIdProvider(hmac);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public Map<RdfResource, RdfResource> mapping() {
        return mapping;
    }

    public static byte[] generateKey(int length) throws KeyGenError {
        try {
            byte[] key = new byte[length];

            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");

            random.nextBytes(key);

            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenError(e);
        }
    }
}
