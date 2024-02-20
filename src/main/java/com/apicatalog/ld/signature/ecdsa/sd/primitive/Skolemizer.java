package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.json.JsonUtils;
import com.apicatalog.jsonld.lang.BlankNode;
import com.apicatalog.jsonld.lang.Keywords;
import com.apicatalog.jsonld.lang.ValueObject;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.rdf.Rdf;
import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.RdfResource;
import com.apicatalog.rdf.RdfValue;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;

class Skolemizer {

    static final String URN_PREFIX = "urn:xyz:";
    
    final String urnScheme;
    final String random;
    int counter;

    private Skolemizer(final String urnScheme, final String random) {
        this.counter = 0;
        this.urnScheme = urnScheme;
        this.random = urnScheme + random + "_";
    }

    static JsonArray expand(JsonObject document, final DocumentLoader loader) throws JsonLdError {
        final JsonArray expanded = JsonLd.expand(JsonDocument.of(document)).loader(loader).get();
        return (new Skolemizer(URN_PREFIX, Long.toHexString((long) (Math.random() * 100000)))).skolemizeExpanded(expanded);
    }

    static JsonObject compact(JsonArray document, JsonStructure context, final DocumentLoader loader) throws JsonLdError {
        return JsonLd
                .compact(JsonDocument.of(document),
                        JsonDocument.of(context))
                .loader(loader)
                .get().asJsonObject();
    }
    
    static Collection<RdfNQuad> deskolemize(JsonStructure skolemizedDocument, final DocumentLoader loader) throws JsonLdError {
        
        RdfDataset skolemizedDataset = JsonLd.toRdf(JsonDocument.of(skolemizedDocument)).loader(loader).get();
     
        Collection<RdfNQuad> skolemizedNQuads = skolemizedDataset.toList();
        
        return deskolemize(skolemizedNQuads, Skolemizer.URN_PREFIX);
        
    }

    private static Collection<RdfNQuad> deskolemize(Collection<RdfNQuad> skolemizedNQuads, String urnScheme) {
        
        final Collection<RdfNQuad> deskolemizedNQuads = new ArrayList<>();
        
        for (RdfNQuad skolemized : skolemizedNQuads) {
            RdfResource subject = skolemized.getSubject();
            RdfValue object = skolemized.getObject();
            
            boolean clone = false;
            
            if (subject.isIRI() && subject.toString().startsWith(urnScheme)) {
                subject = Rdf.createBlankNode(subject.toString().substring(urnScheme.length()));
                clone = true;
            }
            if (object.isIRI() && object.toString().startsWith(urnScheme)) {
                object = Rdf.createBlankNode(object.toString().substring(urnScheme.length()));
                clone = true;                
            }
            
            if (clone) {
                deskolemizedNQuads.add(Rdf.createNQuad(subject, skolemized.getPredicate(), object, skolemized.getGraphName().orElse(null)));
            } else {
                deskolemizedNQuads.add(skolemized);
            }            
        }

        return deskolemizedNQuads;
    }

    private JsonArray skolemizeExpanded(final JsonArray expanded) {

        final JsonArrayBuilder builder = Json.createArrayBuilder();

        for (final JsonValue item : expanded) {
            if (JsonUtils.isNotObject(item) || ValueObject.isValueObject(item)) {
                builder.add(item);
                continue;
            }

            final JsonObjectBuilder node = Json.createObjectBuilder();
            boolean idFound = false;

            for (final Map.Entry<String, JsonValue> entry : item.asJsonObject().entrySet()) {

                if (Keywords.ID.equals(entry.getKey())) {
                    idFound = true;
                    final String id = ((JsonString) entry.getValue()).getString();

                    node.add(Keywords.ID, BlankNode.hasPrefix(id)
                            ? Json.createValue(urnScheme + id.substring(2))
                            : entry.getValue());

                } else if (JsonUtils.isArray(entry.getValue())) {
                    node.add(entry.getKey(), skolemizeExpanded(entry.getValue().asJsonArray()));

                } else {
                    node.add(entry.getKey(), skolemizeExpanded(Json.createArrayBuilder().add(entry.getValue()).build()).get(0));
                }
            }

            if (!idFound) {
                node.add(Keywords.ID, Json.createValue(random + (counter++)));
            }

            builder.add(node);
        }
        return builder.build();
    }
}
