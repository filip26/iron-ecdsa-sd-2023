package com.apicatalog.ld.signature.ecdsa.sd.primitive;

class PrimitivesTest {

//
//    @Test
//    void testSkolExpanded() throws IOException, CborException, JsonLdError {
//
//        JsonObject udoc = fetchResource("tv-01-udoc.jsonld");
//                
////        var y = Skolemizer.skolemize(udoc, SchemeRouter.defaultInstance());
////        
////        var z = JsonLd.compact(JsonDocument.of(y), JsonDocument.of(Json.createArrayBuilder().add("https://www.w3.org/ns/credentials/v2").add(Json.createObjectBuilder().add(Keywords.VOCAB, "https://windsurf.grotto-networking.com/selective#")).build()))
////                .get();
////        
////        var c = Selector.of(MP_TV).getValues(z);
////        
////        System.out.println(write(z));
////        System.out.println(c);
//    }    
//    
//    final static Collection<String> MP_TV = Arrays.asList(
//            "/issuer", 
//            "/credentialSubject/sailNumber", 
//            "/credentialSubject/sails/1",
//            "/credentialSubject/boards/0/year", 
//            "/credentialSubject/sails/2"
//            );
//
//    @Test
//    void testSelector() throws IOException {
//        JsonObject doc = fetchResource("tv-01-adoc.jsonld");
//
//        
//        var x = Selector.of(MP_TV).getNodes(doc);
//        
//        System.out.println(write(x));
//    }
//
//    @Test
//    void testDerivedSelector() throws IOException {
//        JsonObject doc = fetchResource("tv-01-udoc.jsonld");
//
//        var y = new ArrayList<>(MP_TV);
//        y.add("/credentialSubject/boards/0");
//        y.add("/credentialSubject/boards/1");
//        
//        var x = Selector.of(y).getNodes(doc);
//        
//        System.out.println(write(x));
//    }
//    
//    @Test
//    void testDerivedProofValueRead() throws DocumentError {
//        
//        DerivedProofValue.of(Multibase.BASE_64_URL.decode("u2V0BhdhAWECRYow7zOlGZ9xQySwdQy1kztwm3w-Y0uyWMpNiFKLyBnvABacrgGs5mSsfd1m_EpaWfEYb_TGUVeZTmxrn6PvV2EBYI4AkAipyzhm2PxbjPgEqUpJDsbCEdhPJ-zJdqtVEOrRMM4uThthAWEBtAwxySlwwASjXlYLoLwyjdsIRYUa05OQzE0P4skx1-QJKi8HtGcJHtJfOTn7RhWKC0nkXODvUAChvnKDVY02T2EBYQKUB5WERpVFZL_ll9ToyWCdfTsO4qb1cFL5vdEp9yIzUS7svaa-Qx5t8FZVTD1aS6o0vhPP4yQ3iVeaWNG3yvwPYQFhAas2wx9bcEj0Sh7t8w9Cj-2FpceGpdRhaLZxYs1ZEG8-obUjb0CHOyH8S7uwDtn7oSW2oCW2SpZvlX-2jW17rmthAWEA78ePS_Gy4lnOlUa2CgworZmUYq-Etff-9QK90v4xOWzNWvaILdcmkJs5zwH9b86f5yxos_NRK-VIO015zVlWT2EBYQHZth7eLL_3nN7NR0anrpfvshBseEq6cMjUEXS2uWSsiQ4Kq-IfhLVTc3PiflZZbyqxzfMASrVKmq6iODaZ68e3YQFhAORMLXYz3l59Ozc7SDk2ej7clrer9Bn6eaBUQG773AqQ56bc-oGXeemekwZCNHjFLOESNoNq7qetO8FRbiFHb4KYA2EBYIOGCDmZ9TBxEtWeCI9oVmRt0eHRGAaoOXx08gxL2IQt_AdhAWCBWRS4GuU5oQsZVBYkPgz-pbltwoQdYY1s6s8D-oA4orALYQFggQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0D2EBYIJEdvfdRibsv05I3pv8e6S1aUuAuBpGQHLhrYj4QX0knBNhAWCCTQB5eAnh7qbVexXn7EW53Qv_WZSNn0x9-GDlpkZPIOQXYQFgg2IE-HtO6PyHQsGnuqhO1mX6V7RkRREhF0d0sWZlxNOaOAAECBQYICQoODxAREhM"));
//        
//
//    }
//    
//    @Test
//    void testGroup() throws JsonLdError, IOException {
//        
//        JsonObject udoc = fetchResource("tv-01-udoc.jsonld");
//        
////        Map<String, Collection<JsonPointer>> groupDefinitions = new HashMap<>();
//        
////        groupDefinitions.put("mandatory", Selector.toJsonPointers(MP_TV));
//        
//        var hmac = HmacIdLabeLMap.newInstance(Hex.decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"));
//        
////        var cdoc = CanonicalDocument.of(udoc, hmac, SchemeRouter.defaultInstance());
//        
////        var s = cdoc.select(Selector.of(MP_TV));
////        System.out.println(s);
//    }
//    
//
//    JsonObject fetchResource(String name) throws IOException {
//        try (InputStream is = XTest2.class.getResourceAsStream(name)) {
//             return Json.createReader(is).readObject();
//        }
//    }
//    
//    static String write(JsonValue doc) {
//        var sw = new StringWriter();
//        final JsonWriterFactory writerFactory = Json.createWriterFactory(
//                Collections.singletonMap(JsonGenerator.PRETTY_PRINTING, true));
//
//        try (JsonWriter writer = writerFactory.createWriter(sw)) {
//            writer.write(doc);
//        }
//        return sw.toString();
//    }
}
