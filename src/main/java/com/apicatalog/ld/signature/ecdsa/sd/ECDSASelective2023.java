package com.apicatalog.ld.signature.ecdsa.sd;

import java.net.URI;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.primitive.MessageDigest;
import com.apicatalog.cryptosuite.primitive.Urdna2015;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.ecdsa.sd.BCECDSASignatureProvider.CurveType;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.vc.issuer.Issuer;
import com.apicatalog.vc.model.VerifiableMaterial;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidProofValue;
import com.apicatalog.vcdi.DataIntegritySuite;

public final class ECDSASelective2023 extends DataIntegritySuite {

    public static final String CRYPTOSUITE_NAME = "ecdsa-sd-2023";

    static final CryptoSuite CRYPTO_256 = new CryptoSuite(
            CRYPTOSUITE_NAME,
            256,
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new BCECDSASignatureProvider(CurveType.P256));

    static final CryptoSuite CRYPTO_384 = new CryptoSuite(
            CRYPTOSUITE_NAME,
            384,
            new Urdna2015(),
            new MessageDigest("SHA-384"),
            new BCECDSASignatureProvider(CurveType.P384));

    public static final MulticodecDecoder CODECS = MulticodecDecoder.getInstance(
            KeyCodec.P256_PUBLIC_KEY,
            KeyCodec.P256_PRIVATE_KEY,
            KeyCodec.P384_PUBLIC_KEY,
            KeyCodec.P384_PRIVATE_KEY);

    public ECDSASelective2023() {
        super(CRYPTOSUITE_NAME, Multibase.BASE_64_URL);
    }

    @Override
    public Issuer createIssuer(KeyPair keyPair) {
        
        byte[] privateKey = keyPair.privateKey().rawBytes();

        if (privateKey.length == 32) {
            return new ECDSASelective2023Issuer(this, CurveType.P256, CRYPTO_256, keyPair, proofValueBase);
        }
        if (privateKey.length == 48) {
            return new ECDSASelective2023Issuer(this, CurveType.P384, CRYPTO_384, keyPair, proofValueBase);
        }
        throw new IllegalArgumentException("Usupported key length " + privateKey.length + " bytes, expected 32 bytes (256 bits) or 48 bytes (384 bits).");
    }

    @Override
    protected ProofValue getProofValue(VerifiableMaterial verifiable, VerifiableMaterial proof, byte[] proofValue, DocumentLoader loader, URI base) throws DocumentError {
        if (ECDSASDBaseProofValue.is(proofValue)) {
            return ECDSASDBaseProofValue.of(proofValue, getCryptoSuite(proofValue), loader);
        }
        if (ECDSASDDerivedProofValue.is(proofValue)) {
            return ECDSASDDerivedProofValue.of(proofValue, getCryptoSuite(proofValue), loader);
        }
        throw new DocumentError(ErrorType.Unknown, "ProofValue");
    }

    @Override
    protected CryptoSuite getCryptoSuite(String cryptoName, ProofValue proofValue) throws DocumentError {
        if (!CRYPTOSUITE_NAME.equals(cryptoName)) {
            return null;
        }

        if (proofValue != null) {
            if (proofValue instanceof SolidProofValue solidValue) {
                return getCryptoSuite(solidValue.signature().value());
            }
        }
        return CRYPTO_256;
    }

    protected static final CryptoSuite getCryptoSuite(byte[] proofValue) throws DocumentError {
        if (proofValue != null) {
            if (proofValue.length == 64) {
                return CRYPTO_256;
            }
            if (proofValue.length == 96) {
                return CRYPTO_384;
            }
            throw new DocumentError(ErrorType.Invalid, "ProofValueLength");
        }
        throw new DocumentError(ErrorType.Unknown, "ProofValue");
    }
}