package com.apicatalog.ld.signature.ecdsa.sd;

import java.net.URI;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.ecdsa.sd.BCECDSASignatureProvider.CurveType;
import com.apicatalog.ld.signature.ecdsa.sd.primitive.BaseProofValue;
import com.apicatalog.ld.signature.ecdsa.sd.primitive.DerivedProofValue;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.ld.signature.primitive.MessageDigest;
import com.apicatalog.ld.signature.primitive.Urdna2015;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.multikey.MultiKey;
import com.apicatalog.multikey.MultiKeyAdapter;
import com.apicatalog.vc.integrity.DataIntegritySuite;
import com.apicatalog.vc.issuer.Issuer;
import com.apicatalog.vc.method.MethodAdapter;
import com.apicatalog.vc.proof.ProofValue;

import jakarta.json.JsonObject;

public final class ECDSASD2023Suite extends DataIntegritySuite {

    static final CryptoSuite CRYPTO_256 = new CryptoSuite(
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new BCECDSASignatureProvider(CurveType.P256));

    static final CryptoSuite CRYPTO_384 = new CryptoSuite(
            new Urdna2015(),
            new MessageDigest("SHA-384"),
            new BCECDSASignatureProvider(CurveType.P384));

    public static final String CRYPTOSUITE_NAME = "ecdsa-sd-2023";

    public static final MulticodecDecoder CODECS = MulticodecDecoder.getInstance(
            KeyCodec.P256_PUBLIC_KEY,
            KeyCodec.P256_PRIVATE_KEY,
            KeyCodec.P384_PUBLIC_KEY,
            KeyCodec.P384_PRIVATE_KEY);

    public static final MethodAdapter METHOD_ADAPTER = new MultiKeyAdapter(CODECS) {

        @Override
        protected Multicodec getPublicKeyCodec(String algo, int keyLength) {
            if (keyLength == 33) {
                return KeyCodec.P256_PUBLIC_KEY;
            }
            if (keyLength == 49) {
                return KeyCodec.P384_PUBLIC_KEY;
            }
            throw new IllegalStateException();
        }

        @Override
        protected Multicodec getPrivateKeyCodec(String algo, int keyLength) {
            throw new UnsupportedOperationException();
        }

        protected void validate(MultiKey method) throws DocumentError {
            if (method.publicKey() != null
                    && method.publicKey().length != 33 // P-256
                    && method.publicKey().length != 49 // P-384
            ) {
                throw new DocumentError(ErrorType.Invalid, "PublicKeyLength");
            }
        };
    };

    public ECDSASD2023Suite() {
        super(CRYPTOSUITE_NAME, Multibase.BASE_64_URL, METHOD_ADAPTER);
    }

    public ECDSASD2023ProofDraft createP256Draft(
            URI verificationMethod,
            URI purpose) throws DocumentError {
        return new ECDSASD2023ProofDraft(this, CRYPTO_256, verificationMethod, purpose);
    }

    public ECDSASD2023ProofDraft createP384Draft(
            URI verificationMethod,
            URI purpose) throws DocumentError {
        return new ECDSASD2023ProofDraft(this, CRYPTO_384, verificationMethod, purpose);
    }

    @Override
    public boolean isSupported(String proofType, JsonObject expandedProof) {
        if (PROOF_TYPE_ID.equals(proofType)) {
            final String proofSuite = getCryptoSuiteName(expandedProof);
            return cryptosuite.equals(proofSuite);
        }
        return false;
    }

    @Override
    public Issuer createIssuer(KeyPair keyPair) {
        return new ECDSASD2023Issuer(this, keyPair, proofValueBase);
    }

    @Override
    protected ProofValue getProofValue(byte[] proofValue) throws DocumentError {
        if (BaseProofValue.is(proofValue)) {
            return BaseProofValue.of(proofValue);
        }
        if (DerivedProofValue.is(proofValue)) {
            return DerivedProofValue.of(proofValue);
        }
        throw new DocumentError(ErrorType.Unknown, "ProofValue");
    }

    @Override
    protected CryptoSuite getCryptoSuite(String cryptoName, ProofValue proofValue) throws DocumentError {
//FIXME        
//        if (proofValue != null) {
//            if (proofValue.length == 64) {
//                return CRYPTO_256;
//            }
//            if (proofValue.length == 96) {
//                return CRYPTO_384;
//            }
//        }
        return CRYPTO_256;
    }
}