package com.apicatalog.ld.signature.ecdsa.sd;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.apicatalog.jsonld.lang.Keywords;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.sd.DocumentSelector;
import com.apicatalog.rdf.RdfNQuad;

import jakarta.json.Json;
import jakarta.json.JsonObject;

class DerivedDocument {

    final BaseDocument base;

    protected DerivedDocument(BaseDocument base) {
        this.base = base;
    }

    class SelectionResult {
        JsonObject selectionDocument;
        Collection<RdfNQuad> deskolemizedNQuads;
        Collection<RdfNQuad> nquads;
    }

    protected SelectionResult get(DocumentSelector selector) throws DocumentError {
        SelectionResult x = new SelectionResult();
        x.selectionDocument = selector.getNodes(base.skolemizedCompactDocument);
        x.deskolemizedNQuads = Skolemizer.deskolemize(
                Json.createObjectBuilder(x.selectionDocument)
                        .add(Keywords.CONTEXT, base.skolemizedCompactDocument.get(Keywords.CONTEXT)).build(),
                base.loader);
        x.nquads = BaseDocument.relabelBlankNodes(x.deskolemizedNQuads, base.labelMap);

        return x;
    }

    class Group {
        Map<Integer, RdfNQuad> matching;
        Map<Integer, RdfNQuad> nonMatching;
        Collection<RdfNQuad> deskolemizedNQuads;
    }

    protected Group select(SelectionResult result) {
        Group group = new Group();
        group.matching = new HashMap<>();
        group.nonMatching = new HashMap<>();
        group.deskolemizedNQuads = result.deskolemizedNQuads;

        Collection<RdfNQuad> selectedNQuads = result.nquads;

        int index = 0;
        for (final RdfNQuad nquad : base.nquads) {
            if (selectedNQuads.contains(nquad)) {
                group.matching.put(index, nquad);
            } else {
                group.nonMatching.put(index, nquad);
            }
            index++;
        }
        return group;
    }

    public Group select(DocumentSelector selector) throws DocumentError {
        return select(get(selector));
    }

}
