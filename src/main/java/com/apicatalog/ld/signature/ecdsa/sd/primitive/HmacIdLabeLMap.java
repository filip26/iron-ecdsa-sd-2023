package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.apicatalog.multibase.Multibase;
import com.apicatalog.rdf.Rdf;
import com.apicatalog.rdf.RdfResource;

class HmacIdLabeLMap {

    final Map<RdfResource, RdfResource> labelMap = new HashMap<>();
    final Mac hmac;

    private HmacIdLabeLMap(Mac hmac) {
        this.hmac = hmac;
    }

    public RdfResource getHmacId(RdfResource resource) {

        RdfResource hmacId = labelMap.get(resource);

        if (hmacId == null) {
            hmacId = Rdf.createBlankNode("_:" + Multibase.BASE_64_URL.encode(hmac.doFinal(resource.toString().substring(2).getBytes(StandardCharsets.UTF_8))));
            hmac.reset();
            labelMap.put(resource, hmacId);
        }
        return hmacId;
    }

    public static HmacIdLabeLMap newInstance(final byte[] hmacKey) {
        final SecretKeySpec key = new SecretKeySpec(hmacKey, "HmacSHA256");
        try {
            final Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(key);
            return new HmacIdLabeLMap(hmac);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public Map<RdfResource, RdfResource> labelMap() {
        return labelMap;
    }

}
