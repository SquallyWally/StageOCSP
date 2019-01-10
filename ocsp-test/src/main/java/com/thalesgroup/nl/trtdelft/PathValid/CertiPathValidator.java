package com.thalesgroup.nl.trtdelft.PathValid;

import com.thalesgroup.nl.trtdelft.CertificateVerificationException;
import com.thalesgroup.nl.trtdelft.RevocationVerifier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


import java.security.Security;
import java.security.cert.*;
import java.util.*;


/**
 * Used to validate the revocation status of a certificate chain acquired from the peer. A revocation verifier
 * (OCSP or CRL) should be given. Must be used only once when validating certificate chain for an SSLSession.
 * Create a new instance if need to be reused because the path validation process is state-full.
 * Not thread safe
 */
public class CertiPathValidator {

    private PathChecker pathChecker;

    // Certificate Chain with Root CA certificate (eg: peer cert, issuer cert, root cert)
    List<X509Certificate> fullCertChain;

    // Certificate Chain without Root CA certificate. (eg: peer cert, issuer cert)
    List<X509Certificate> certChain;

    private static final Log log = LogFactory.getLog(CertiPathValidator.class);

    public CertiPathValidator(X509Certificate[] certChainArray, RevocationVerifier verifier) {

        this.pathChecker = new PathChecker(certChainArray, verifier);
        init(certChainArray);
    }

    /**
     * Here revocation status checking is started from one below the root certificate in the chain (certChain).
     * Since ssl implementation ensures that at least one certificate in the chain is trusted,
     * we can logically say that the root is trusted.
     */
    private void init(X509Certificate[] certChainArray) {

        X509Certificate[] partCertChainArray = new X509Certificate[certChainArray.length - 1];
        System.arraycopy(certChainArray, 0, partCertChainArray, 0, partCertChainArray.length);
        certChain = Arrays.asList(partCertChainArray);
        fullCertChain = Arrays.asList(certChainArray);


    }

    /**
     * Certificate Path Validation process
     *
     * @throws CertificateVerificationException if validation process fails.
     */
    public void validatePath() throws CertificateVerificationException {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(fullCertChain);
        try {

            CertStore store = CertStore.getInstance("Collection", params, "BC");

            // create certificate path
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            CertPath certPath = fact.generateCertPath(certChain);
            TrustAnchor trustAnchor = new TrustAnchor(fullCertChain.get(fullCertChain.size() - 1), null);
            Set<TrustAnchor> trust = Collections.singleton(trustAnchor);

            // perform validation
            CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
            PKIXParameters param = new PKIXParameters(trust);

            param.addCertPathChecker(pathChecker);
            param.setRevocationEnabled(false);
            param.addCertStore(store);
            param.setDate(new Date());

            validator.validate(certPath, param);

            log.info("Certificate path validated");
        } catch (CertPathValidatorException e) {

            throw new CertificateVerificationException("Certificate Path Validation failed on certificate number "
                    + e.getIndex() + ", details: " + e.getMessage(), e);
        } catch (Exception e) {

            throw new CertificateVerificationException("Certificate Path Validation failed", e);
        }
    }
}