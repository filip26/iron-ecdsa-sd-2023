package com.apicatalog.ld.signature.ecdsa.sd.primitive;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.util.Arrays;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.rdf.Rdf;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.RdfResource;
import com.apicatalog.rdf.RdfValue;
import com.apicatalog.rdf.canon.RdfCanonicalizer;
import com.apicatalog.rdf.canon.RdfNQuadComparator;

import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;

class VerifyData {

    final DocumentLoader loader;
    
    List<RdfNQuad> mandatory;
    List<RdfNQuad> nonMandatory;
    
    VerifyData(DocumentLoader loader) {
        this.loader = loader;
    }
    
    static VerifyData of(JsonStructure context, JsonObject expanded, DocumentLoader loader, Map<Integer, byte[]> labels, int[] indices) throws DocumentError {

        try {
            final Collection<RdfNQuad> dataset = JsonLd.toRdf(JsonDocument.of(expanded)).get().toList();
            
            final RdfCanonicalizer canonicalizer = RdfCanonicalizer.newInstance(dataset);
            
            final Collection<RdfNQuad> cdoc = canonicalizer.canonicalize();
            
//            cdoc.forEach(System.out::println);
            
//            canonicalizer.canonIssuer().mappingTable().entrySet().stream().forEach(System.out::println);
            
            List<RdfResource> x = canonicalizer.canonIssuer().mappingTable().entrySet()
                .stream().sorted(new Comparator<>() {

                    @Override
                    public int compare(Entry<RdfResource, RdfResource> o1, Entry<RdfResource, RdfResource> o2) {
                        return o1.getValue().toString().compareTo(o2.getValue().toString());
                    }
                    
                }).map(Map.Entry::getValue).toList();
            
                Map<RdfResource, RdfResource> map = new HashMap<>(labels.size());
                
                for (int i=0; i < x.size(); i++) {
                    map.put(x.get(i), Rdf.createBlankNode(Multibase.BASE_64_URL.encode(labels.get(i))));
                }
//                map.entrySet().forEach(System.out::println);

//            Arrays.stream(x).forEach(System.out::println);
//              
//            labels.keySet().forEach(System.out::println);
//            cdoc.labelMap = canonicalizer.canonIssuer().mappingTable()
//                    .entrySet().stream()
//                    .map(e -> Map.entry(e.getKey(), hmac.labelMap().get(e.getValue())))
//                    .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
                List<RdfNQuad> cnquads = relabel(cdoc, map);
                
//                cnquads.forEach(System.out::println);
        
                VerifyData vd =  new VerifyData(loader);
                
                vd.mandatory = new ArrayList<>();
                vd.nonMandatory = new ArrayList<>();
                
                for (int i = 0 ; i < cnquads.size(); i++) {
                    if (Arrays.contains(indices, i)) {
                        vd.mandatory.add(cnquads.get(i));
                    } else {
                        vd.nonMandatory.add(cnquads.get(i));
                    }
                }
                
//                vd.mandatory.forEach(System.out::println);
                
                return vd;       
        
        } catch (JsonLdError e) {
            throw new DocumentError(e, ErrorType.Invalid);
        }
    }
    
    static List<RdfNQuad> relabel(Collection<RdfNQuad> nquads, Map<RdfResource, RdfResource> mapping) {

        final List<RdfNQuad> relabeled = new ArrayList<>(nquads.size());

        for (RdfNQuad nquad : nquads) {
            RdfResource subject = nquad.getSubject();
            RdfValue object = nquad.getObject();

            boolean clone = false;

            if (subject.isBlankNode() && mapping.containsKey(subject)) {
                subject = mapping.get(subject);
                clone = true;
            }
            if (object.isBlankNode() && mapping.containsKey(object)) {
                object = mapping.get(object);
                clone = true;
            }

            if (clone) {
                relabeled.add(Rdf.createNQuad(subject, nquad.getPredicate(), object, nquad.getGraphName().orElse(null)));
            } else {
                relabeled.add(nquad);
            }
        }

        Collections.sort(relabeled, RdfNQuadComparator.asc());

        return relabeled;
    }

    
}
