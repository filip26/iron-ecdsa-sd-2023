package com.apicatalog.ld.signature.ecdsa.sd;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.CryptoSuiteError;
import com.apicatalog.cryptosuite.sd.DocumentSelector;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.ecdsa.sd.BCECDSASignatureProvider.CurveType;
import com.apicatalog.ld.signature.sd.SelectiveSignature;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.vc.issuer.AbstractIssuer;
import com.apicatalog.vc.issuer.ProofDraft;
import com.apicatalog.vc.model.VerifiableMaterial;
import com.apicatalog.vc.model.DocumentModel;
import com.apicatalog.vcdi.DataIntegritySuite;

import jakarta.json.JsonObject;

class ECDSASelective2023Issuer extends AbstractIssuer {

    protected final CurveType curveType;

    protected ECDSASelective2023Issuer(DataIntegritySuite suite, CurveType curveType, CryptoSuite cryptosuite, KeyPair keyPair, Multibase proofValueBase) {
        super(suite,
                cryptosuite,
                keyPair,
                proofValueBase,
                method -> new ECDSASelective2023ProofDraft(suite, curveType, cryptosuite, method));
        this.curveType = curveType;
    }

    @Override
//    protected byte[] sign(JsonArray context, JsonObject document, ProofDraft proofDraft) throws SigningError, DocumentError {
    protected JsonObject sign(DocumentModel model, VerifiableMaterial unsignedData, VerifiableMaterial unsignedDraft, ProofDraft proofDraft) throws DocumentError, CryptoSuiteError {

        final ECDSASelective2023ProofDraft draft = (ECDSASelective2023ProofDraft) proofDraft;

//        final JsonObject proof = draft.unsigned();

        final HmacIdProvider hmac = HmacIdProvider.newInstance(draft.hmacKey());

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

//            final byte[] proofPublicKey = KeyCodec.P256_PUBLIC_KEY.encode(draft.proofKeys().publicKey());   //FIXME

        byte[] proofPublicKey = KeyCodec.P256_PUBLIC_KEY.encode(draft.proofKeys().publicKey().rawBytes()); // FIXME

        final byte[] baseSignature = signer.signature(
                draft.unsigned(unsignedData.context(), defaultLoader, base),
                selected.values(),
                proofPublicKey,
                keyPair.privateKey().rawBytes());

//FIXME            return ECDSASDBaseProofValue.toByteArray(baseSignature, proofPublicKey, draft.hmacKey(), signatures, draft.selectors());
        return null;
    }
}
