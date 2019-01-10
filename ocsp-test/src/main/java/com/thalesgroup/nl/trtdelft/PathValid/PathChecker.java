package com.thalesgroup.nl.trtdelft.PathValid;

import com.thalesgroup.nl.trtdelft.CertificateVerificationException;
import com.thalesgroup.nl.trtdelft.RevocationStatus;
import com.thalesgroup.nl.trtdelft.RevocationVerifier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Set;

/**
 * This class is used by CertificatePathValidator to check revocation status of the certificate chain.
 * Certificates in the chain will be passed to the check(..,..) method one by one.
 * This is not Thread safe since the process is state full. Should not be shared among threads.
 */
class PathChecker extends PKIXCertPathChecker {

    X509Certificate[] certChainArray;
    RevocationVerifier verifier;
    private int position;
    private static final Log log = LogFactory.getLog(PathChecker.class);

    protected PathChecker(X509Certificate[] certChainArray, RevocationVerifier verifier) {
        this.certChainArray = certChainArray;
        //initialize position to Root Certificate position.
        this.position = certChainArray.length - 1;
        this.verifier = verifier;
    }

    @Override
    public void init(boolean forward) throws CertPathValidatorException {
        if (forward) {
            throw new CertPathValidatorException("Forward checking is not supported");
        }
    }

    /**
     * Forward checking is not supported. Certificates should be passed from the most trusted CA certificate
     * to the target certificate. This is the default implementation of the Path validator used
     * CertPathValidator.getInstance("PKIX", "BC") in CertificatePathValidator;
     */
    @Override
    public boolean isForwardCheckingSupported() {
        return false;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return null;
    }

    /**
     * Used by CertPathValidator to pass the certificates one by one from the certificate chain.
     *
     * @param cert the certificate passed to be checked.
     * @param unresolvedCritExts not used in this method.
     * @throws CertPathValidatorException
     */
    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        RevocationStatus status = null;
        try {
            status = verifier.checkRevocationStatus((X509Certificate) cert, nextIssuer());
        } catch (CertificateVerificationException e) {
            e.printStackTrace();
        }
        log.info("Certificate status is: "+status.getMessage());
        if (status != RevocationStatus.GOOD)
            throw new CertPathValidatorException("Revocation Status is Not Good");
    }

    /**
     * @return the immediate issuer certificate of the current certificate which is being checked. This is tracked
     *         by the position variable
     */
    private X509Certificate nextIssuer() {
        //get immediate issuer
        if (position > 0)
            return certChainArray[position--];
        else
            throw new ArrayIndexOutOfBoundsException("Certificate Chain Index Out of Bounds");
    }
}