package com.apicatalog.ld.signature.ecdsa.sd;

import java.util.Collection;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.node.LdScalar;
import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.SigningError;
import com.apicatalog.ld.signature.SigningError.Code;
import com.apicatalog.ld.signature.ecdsa.sd.primitive.BaseProofValue;
import com.apicatalog.ld.signature.ecdsa.sd.primitive.BaseSignature;
import com.apicatalog.ld.signature.ecdsa.sd.primitive.CanonicalDocument;
import com.apicatalog.ld.signature.ecdsa.sd.primitive.HmacIdLabeLMap;
import com.apicatalog.ld.signature.ecdsa.sd.primitive.Selector;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.vc.issuer.AbstractIssuer;
import com.apicatalog.vc.issuer.ProofDraft;
import com.apicatalog.vc.suite.SignatureSuite;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

class ECDSASD2023Issuer extends AbstractIssuer {

    protected ECDSASD2023Issuer(SignatureSuite suite, KeyPair keyPair, Multibase proofValueBase) {
        super(suite, keyPair, proofValueBase);
    }

    @Override
    protected JsonObject sign(JsonArray context, JsonObject document, ProofDraft proofDraft) throws SigningError, DocumentError {

        final ECDSASD2023ProofDraft draft = (ECDSASD2023ProofDraft) proofDraft;

        JsonObject proof = draft.unsignedCopy();
        Collection<String> selectors = draft.selectors();

        HmacIdLabeLMap hmac = HmacIdLabeLMap.newInstance(draft.hmacKey());

        CanonicalDocument cdoc = CanonicalDocument.of(context, document, getLoader(), hmac);

        cdoc.nquads().forEach(System.out::println);
        System.out.println(cdoc.labelMap());

        Map<Integer, RdfNQuad> selected = cdoc.select(Selector.of(selectors));

        System.out.println(selected.keySet());
        selected.values().forEach(System.out::println);

        BaseSignature signer = new BaseSignature(draft.cryptoSuite(), draft.cryptoSuite(), draft.cryptoSuite());

        Collection<byte[]> signatures = signer.signatures(
                cdoc.nquads().stream()
                        .filter(nq -> !selected.values().contains(nq)).toList(),
                draft.proofKeys().privateKey());

        signatures.stream().map(Hex::toHexString).forEach(System.out::println);

        try {
            byte[] proofHash = signer.hash(proof);
            System.out.println("proofHash = " + Hex.toHexString(proofHash));

            byte[] mandatoryHash = signer.hash(selected.values());
            System.out.println("mandatoryHash = " + Hex.toHexString(mandatoryHash));

            byte[] baseSignature = signer.signature(proof, selected.values(), draft.proofKeys().publicKey(), keyPair.privateKey());

            System.out.println("baseSignature = " + Hex.toHexString(baseSignature));

            byte[] proofValue = BaseProofValue.toByteArray(baseSignature, draft.proofKeys().publicKey(), draft.hmacKey(), signatures, selectors);

            return LdScalar.multibase(proofValueBase, proofValue);
            
        } catch (LinkedDataSuiteError e) {
            throw new SigningError(Code.Internal, e);
        }
    }
}
