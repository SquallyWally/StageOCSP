package com.thalesgroup.nl.trtdelft;

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

public interface RevocationVerifier {



     RevocationStatus checkRevocationStatus(X509Certificate peerCertificate, X509Certificate issuerCertificate) throws CertPathValidatorException, CertificateVerificationException;
}
