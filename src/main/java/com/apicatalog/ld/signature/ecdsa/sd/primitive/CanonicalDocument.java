package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.lang.Keywords;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.rdf.Rdf;
import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.RdfResource;
import com.apicatalog.rdf.RdfValue;
import com.apicatalog.rdf.urdna2015.Urdna2015;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

class CanonicalDocument {

    final HmacIdLabeLMap hmac;
    final DocumentLoader loader;

    JsonObject skolemizedCompactDocument;

    Collection<RdfNQuad> nquads;

    Map<RdfResource, RdfResource> labelMap;

    private CanonicalDocument(HmacIdLabeLMap hmac, DocumentLoader loader) {
        this.hmac = hmac;
        this.loader = loader;
    }

    public static CanonicalDocument of(JsonObject document, HmacIdLabeLMap hmac, DocumentLoader loader) throws JsonLdError {

        final CanonicalDocument cdoc = new CanonicalDocument(hmac, loader);

        final JsonArray skolemizedExpandedDocument = Skolemizer.expand(document, loader);

        cdoc.skolemizedCompactDocument = Skolemizer.compact(skolemizedExpandedDocument,
                Json.createArrayBuilder().add("https://www.w3.org/ns/credentials/v2")
                        .add(Json.createObjectBuilder().add(Keywords.VOCAB, "https://windsurf.grotto-networking.com/selective#")).build(),
                loader);

        final Collection<RdfNQuad> deskolemizedNQuads = Skolemizer.deskolemize(skolemizedExpandedDocument, loader);

        final Urdna2015 canonicalizer = new Urdna2015(deskolemizedNQuads);

        final RdfDataset dataset = canonicalizer.normalize();

        final List<RdfNQuad> canonicalNQuads = new ArrayList<>(dataset.size());

        for (RdfNQuad nquad : dataset.toList()) {
            RdfResource subject = nquad.getSubject();
            RdfValue object = nquad.getObject();

            boolean clone = false;

            if (subject.isBlankNode()) {
                subject = hmac.getHmacId(subject);
                clone = true;
            }
            if (object.isBlankNode()) {
                object = hmac.getHmacId((RdfResource) object);
                clone = true;
            }

            if (clone) {
                canonicalNQuads.add(Rdf.createNQuad(subject, nquad.getPredicate(), object, nquad.getGraphName().orElse(null)));
            } else {
                canonicalNQuads.add(nquad);
            }
        }

        Collections.sort(canonicalNQuads, new Comparator<RdfNQuad>() {
            @Override
            public int compare(RdfNQuad o1, RdfNQuad o2) {
                int r = o1.getSubject().toString().compareTo(o2.getSubject().toString());
                if (r == 0) {
                    r = o1.getPredicate().toString().compareTo(o2.getPredicate().toString());
                }
                if (r == 0) {
                    r = o1.getObject().toString().compareTo(o2.getObject().toString());
                }
                return r;
            }
        });

        cdoc.nquads = Collections.unmodifiableList(canonicalNQuads);

        cdoc.labelMap = canonicalizer.canonIssuer().labelMap()
                .entrySet().stream()
                .map(e -> Map.entry(e.getKey(), hmac.labelMap().get(e.getValue())))
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));

        return cdoc;
    }

    public Map<Integer, RdfNQuad> select(
            Selector selector) throws JsonLdError {

        Collection<RdfNQuad> selected = relabelBlankNodes(
                Skolemizer.deskolemize(
                        Json.createObjectBuilder(selector.getNodes(skolemizedCompactDocument))
                                .add(Keywords.CONTEXT, skolemizedCompactDocument.get(Keywords.CONTEXT)).build(),
                        loader),
                labelMap);

        Map<Integer, RdfNQuad> matching = new HashMap<>();

        int index = 0;
        for (final RdfNQuad nquad : nquads) {
            if (selected.contains(nquad)) {
                matching.put(index, nquad);
            }
            index++;
        }
        return matching;
    }

    private static Collection<RdfNQuad> relabelBlankNodes(Collection<RdfNQuad> nquads, Map<RdfResource, RdfResource> labelMap) {

        final Collection<RdfNQuad> relabeledNQuads = new ArrayList<>(nquads.size());

        for (final RdfNQuad nquad : nquads) {

            RdfResource subject = nquad.getSubject();
            RdfValue object = nquad.getObject();

            boolean clone = false;

            if (subject.isBlankNode() && labelMap.containsKey(subject)) {
                subject = labelMap.get(subject);
                clone = true;
            }
            if (object.isBlankNode() && labelMap.containsKey(object)) {
                object = labelMap.get(object);
                clone = true;
            }

            relabeledNQuads.add(clone
                    ? Rdf.createNQuad(subject, nquad.getPredicate(), object, nquad.getGraphName().orElse(null))
                    : nquad);
        }

        return relabeledNQuads;
    }
}
