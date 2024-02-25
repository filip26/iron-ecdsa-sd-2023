package com.apicatalog.ld.signature.ecdsa.sd;

import java.util.Collection;
import java.util.Map;

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

        final JsonObject proof = draft.unsignedCopy();

        final HmacIdLabeLMap hmac = HmacIdLabeLMap.newInstance(draft.hmacKey());

        final CanonicalDocument cdoc = CanonicalDocument.of(context, document, getLoader(), hmac);

        final Map<Integer, RdfNQuad> selected = cdoc.select(Selector.of(draft.selectors()));

        final BaseSignature signer = new BaseSignature(draft.cryptoSuite(), draft.cryptoSuite(), draft.cryptoSuite());

        final Collection<byte[]> signatures = signer.signatures(
                cdoc.nquads().stream()
                        .filter(nq -> !selected.values().contains(nq)).toList(),
                draft.proofKeys().privateKey());

        try {
            final byte[] baseSignature = signer.signature(proof, selected.values(), draft.proofKeys().publicKey(), keyPair.privateKey());

            final byte[] proofValue = BaseProofValue.toByteArray(baseSignature, draft.proofKeys().publicKey(), draft.hmacKey(), signatures, draft.selectors());

            return LdScalar.multibase(proofValueBase, proofValue);

        } catch (LinkedDataSuiteError e) {
            throw new SigningError(Code.Internal, e);
        }
    }
}
