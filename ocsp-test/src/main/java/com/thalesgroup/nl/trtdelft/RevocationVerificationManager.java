package com.thalesgroup.nl.trtdelft;



import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

import com.thalesgroup.nl.trtdelft.PathValid.CertiPathValidator;
import com.thalesgroup.nl.trtdelft.crl.CRLCache;
import com.thalesgroup.nl.trtdelft.crl.CRLVerifier;
import com.thalesgroup.nl.trtdelft.ocsp.OCSPCache;
import com.thalesgroup.nl.trtdelft.ocsp.OCSPVerifier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Manager class responsible for verifying certificates. This class will use the available verifiers according to
 * a predefined policy.
 */
public class RevocationVerificationManager {

    private int cacheSize = Constants.CACHE_DEFAULT_ALLOCATED_SIZE;
    private int cacheDelayMinutes = Constants.CACHE_DEFAULT_DELAY_MINS;
    private static final Log log = LogFactory.getLog(RevocationVerificationManager.class);


    public RevocationVerificationManager(Integer cacheAllocatedSize, Integer cacheDelayMinutes) {
        if (cacheAllocatedSize != null && cacheAllocatedSize > Constants.CACHE_DEFAULT_ALLOCATED_SIZE && cacheAllocatedSize < Constants.CACHE_MAX_ALLOCATED_SIZE) {
            this.cacheSize = cacheAllocatedSize;
        }
        if (cacheAllocatedSize != null && cacheAllocatedSize > Constants.CACHE_MIN_DELAY_MINS && cacheAllocatedSize < Constants.CACHE_MAX_DELAY_MINS) {
            this.cacheSize = cacheAllocatedSize;

        }
    }

    /**
     * This method first tries to verify the given certificate chain using OCSP since OCSP verification is
     * faster. If that fails it tries to do the verification using CRL.
     *
     * @param peerCertificates javax.security.cert.X509Certificate[] array of peer certificate chain from peer/client.
     * @throws CertificateVerificationException
     */




    public void verifyRevocationStatus(X509Certificate[] peerCertificates) throws CertificateVerificationException {

        long start = System.currentTimeMillis();

        OCSPCache ocspCache = OCSPCache.getCache();
        ocspCache.init(cacheSize, cacheDelayMinutes);
        CRLCache crlCache = CRLCache.getCache();
        crlCache.init(cacheSize, cacheDelayMinutes);

        RevocationVerifier[] verifiers = {new OCSPVerifier(ocspCache), new CRLVerifier(crlCache)};

        for (RevocationVerifier verifier : verifiers) {
            try {
                CertiPathValidator pathValidator = new CertiPathValidator(peerCertificates, verifier);
                pathValidator.validatePath();
                log.info("Path verification Successful. Took " + (System.currentTimeMillis() - start) + " ms.");
                return;
            } catch (Exception e) {
                log.info(verifier.getClass().getSimpleName() + " failed.");
                log.debug("Certificate verification with " + verifier.getClass().getSimpleName() + " failed. ", e);
            }
        }
        throw new CertificateVerificationException("Path Verification Failed for both OCSP and CRL");
    }




    /**
     * @param certs array of javax.security.cert.X509Certificate[] s.
     * @return the converted array of java.security.cert.X509Certificate[] s.
     * @throws CertificateVerificationException
     */
    private X509Certificate[] convert(X509Certificate[] certs)
            throws CertificateVerificationException {
        X509Certificate[] certChain = new X509Certificate[certs.length];
        Throwable exceptionThrown;
        for (int i = 0; i < certs.length; i++) {
            try {
                byte[] encoded = certs[i].getEncoded();
                ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
                java.security.cert.CertificateFactory cf
                        = java.security.cert.CertificateFactory.getInstance("X.509");
                certChain[i]=((X509Certificate)cf.generateCertificate(bis));
                continue;
            } catch (java.security.cert.CertificateEncodingException e) {
                exceptionThrown = e;
            } catch (java.security.cert.CertificateException e) {
                exceptionThrown = e;
            }
            throw new CertificateVerificationException("Cant Convert certificates from javax to java", exceptionThrown);
        }
        return certChain;
    }
}