package com.apicatalog.ld.signature.ecdsa.sd;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.CryptoSuiteError;
import com.apicatalog.cryptosuite.sd.DocumentSelector;
import com.apicatalog.ld.signature.ecdsa.sd.BCECDSASignatureProvider.CurveType;
import com.apicatalog.ld.signature.sd.SelectiveSignature;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.key.MulticodecKey;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.vc.di.DataIntegritySuite;
import com.apicatalog.vc.issuer.AbstractIssuer;
import com.apicatalog.vc.issuer.ProofDraft;
import com.apicatalog.vc.model.DocumentError;
import com.apicatalog.vc.model.DocumentModel;
import com.apicatalog.vc.model.VerifiableMaterial;

import jakarta.json.JsonObject;

class ECDSASD2023Issuer extends AbstractIssuer {

    protected final CurveType curveType;

    protected ECDSASD2023Issuer(DataIntegritySuite suite, CurveType curveType, CryptoSuite cryptosuite, KeyPair keyPair, Multibase proofValueBase) {
        super(suite,
                cryptosuite,
                keyPair,
                proofValueBase,
                method -> new ECDSASD2023Draft(suite, curveType, cryptosuite, method));
        this.curveType = curveType;
    }

    @Override
    protected JsonObject sign(DocumentModel model, VerifiableMaterial unsignedData, VerifiableMaterial unsignedDraft, ProofDraft proofDraft) throws DocumentError, CryptoSuiteError {

        final ECDSASD2023Draft draft = (ECDSASD2023Draft) proofDraft;

        final HmacIdProvider hmac = HmacIdProvider.newInstance(draft.hmacKey(), curveType);

        final BaseDocument cdoc = BaseDocument.of(
                unsignedData,
                getLoader(),
                hmac);

        final Map<Integer, RdfNQuad> selected = cdoc.select(DocumentSelector.of(draft.selectors()));

        final SelectiveSignature signer = new SelectiveSignature(cryptosuite, cryptosuite, cryptosuite);

        final Collection<byte[]> signatures = signer.signatures(
                cdoc.nquads().stream()
                        .filter(nq -> !selected.values().contains(nq)).collect(Collectors.toList()),
                draft.proofKeys().privateKey().rawBytes());

        byte[] proofPublicKey = draft.proofKeys().publicKey().rawBytes();

        final byte[] baseSignature = signer.signature(
                unsignedDraft,
                selected.values(),
                ((MulticodecKey) draft.proofKeys().publicKey()).codec().encode(proofPublicKey),
                keyPair.privateKey().rawBytes());

        final byte[] baseProofValue = ECDSASDBaseProofValue.toByteArray(
                baseSignature,
                ((MulticodecKey) draft.proofKeys().publicKey()).codec().encode(proofPublicKey),
                draft.hmacKey(),
                signatures,
                draft.selectors());

        return sign(model, unsignedDraft, draft, baseProofValue);
    }
}
