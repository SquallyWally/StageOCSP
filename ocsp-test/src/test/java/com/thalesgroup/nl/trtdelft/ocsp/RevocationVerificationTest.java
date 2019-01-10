package com.thalesgroup.nl.trtdelft.ocsp;

import com.thalesgroup.nl.trtdelft.CertificateVerificationException;
import com.thalesgroup.nl.trtdelft.PathValid.CertiPathValidator;
import com.thalesgroup.nl.trtdelft.RevocationVerifier;
import junit.framework.TestCase;

import java.security.Security;
import java.security.cert.X509Certificate;

public class RevocationVerificationTest extends TestCase {

    public void testCRLPathValidation() throws Exception, CertificateVerificationException {

        /**Add BouncyCastle as SP*/
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Utils utils = new Utils();
        X509Certificate[] certificates = utils.getRealCertificateChain();

        Throwable throwable = null;

        crlPathValidation(certificates);
        assertNull(throwable);

    }


    public void testOCSPPathValidation() throws Exception, CertificateVerificationException {
        //Add BouncyCastle as Security Provider.
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Utils utils = new Utils();
        X509Certificate[] certificates = utils.getRealCertificateChain();
        Throwable throwable = null;

        ocspPathValidation(certificates);


        assertNull(throwable);
    }

    private void ocspPathValidation(X509Certificate[] certificates) {

        OCSPCache ocspCache = OCSPCache.getCache();
        ocspCache.init(5,5);
        RevocationVerifier verifier = new OCSPVerifier(ocspCache);
        CertiPathValidator pathValidator = new CertiPathValidator(certificates, verifier);

    }

    private void crlPathValidation(X509Certificate[] certificates) {
    }
}
