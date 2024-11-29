package com.apicatalog.ld.signature.ecdsa.sd;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.apicatalog.cryptosuite.sd.DocumentSelector;
import com.apicatalog.jsonld.lang.Keywords;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.vc.model.DocumentError;

import jakarta.json.Json;
import jakarta.json.JsonObject;

class Selection {

    Map<Integer, RdfNQuad> matching;
    Collection<RdfNQuad> deskolemizedNQuads;

    public static Selection of(final BaseDocument base, final DocumentSelector selector) throws DocumentError {
        return get(base, selector);
    }

    protected static Selection get(final BaseDocument base, final DocumentSelector selector) throws DocumentError {

        final Selection result = new Selection();

        final JsonObject selection = selector.getNodes(base.skolemizedCompactDocument);

        result.deskolemizedNQuads = Skolemizer.deskolemize(
                Json.createObjectBuilder(selection)
                        .add(Keywords.CONTEXT, base.skolemizedCompactDocument.get(Keywords.CONTEXT)).build(),
                base.loader);

        final List<RdfNQuad> nquads = BaseDocument.relabelBlankNodes(result.deskolemizedNQuads, base.labelMap);

        result.matching = new HashMap<>();

        int index = 0;
        for (final RdfNQuad nquad : base.nquads) {
            if (nquads.contains(nquad)) {
                result.matching.put(index, nquad);
            }
            index++;
        }
        return result;
    }
}
