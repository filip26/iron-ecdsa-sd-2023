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

    static JsonArray skolemize(JsonArray expanded) throws JsonLdError {
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
            
            if (subject.isIRI() && subject.getValue().startsWith(urnScheme)) {
                subject = Rdf.createBlankNode(subject.getValue().substring(urnScheme.length()));
                clone = true;
            }
            if (object.isIRI() && object.getValue().startsWith(urnScheme)) {
                object = Rdf.createBlankNode(object.getValue().substring(urnScheme.length()));
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

                final String key = entry.getKey();
                final JsonValue value = entry.getValue();
                
                if (Keywords.ID.equals(key)) {
                    final String id = item.asJsonObject().getString(Keywords.ID);

                    node.add(Keywords.ID, BlankNode.hasPrefix(id)
                            ? Json.createValue(urnScheme + id.substring(2))
                            : item.asJsonObject().get(Keywords.ID));
                    idFound = true;
                    
                } else if (JsonUtils.isArray(value)) {
                    node.add(key, skolemizeExpanded(value.asJsonArray()));

                } else {
                    node.add(key, skolemizeExpanded(Json.createArrayBuilder().add(value).build()).get(0));
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
