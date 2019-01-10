package com.thalesgroup.nl.trtdelft.crl;


import com.thalesgroup.nl.trtdelft.CertificateVerificationException;
import com.thalesgroup.nl.trtdelft.RevocationStatus;
import com.thalesgroup.nl.trtdelft.RevocationVerifier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

public class CRLVerifier implements RevocationVerifier {


    private CRLCache cache;
    private static final Log log = LogFactory.getLog(CRLVerifier.class);


    public CRLVerifier(CRLCache cache) {
        this.cache = cache;

    }

    /**
     * Checks revocation status (Good, Revoked) of the peer certificate. IssuerCertificate can be used
     * to check if the CRL URL has the Issuers Domain name. But this is not implemented at the moment.
     *
     * @param peerCert   peer certificate
     * @param issuerCert issuer certificate of the peer. not used currently.
     * @return revocation status of the peer certificate.
     * @throws CertificateVerificationException
     */


    public RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert) throws CertificateVerificationException {

        List<String> list = null;
        try {
            list = getCrlDistributionPoints(peerCert);
        } catch (IOException e) {
            e.printStackTrace();
        }

        for (String crlUrl : list) {
            log.info("Trying to get CRL for URL: " + crlUrl);

            if (cache != null) {
                X509CRL x509CRL = cache.getCacheValue(crlUrl);

                if (x509CRL != null) {

                    RevocationStatus status = getRevocationStatus(x509CRL, peerCert);
                    log.info("CRL taken from the cache...............");
                    return status;

                }
            }


            /**What if the certificate is unknown*/
            try {
                X509CRL x509CRL = downloadCRLFromWeb(crlUrl);
                if (x509CRL != null) {
                    if (cache != null)
                        cache.setCacheValue(crlUrl, x509CRL);
                    return getRevocationStatus(x509CRL, peerCert);
                }
            } catch (Exception e) {
                log.info("Either the URL is bad or cant build X509CRL. So check with the next url in the list.", e);
            }

        }

        throw new CertificateVerificationException("Cannot check revocation status with the certificate");
    }


    private RevocationStatus getRevocationStatus(X509CRL x509CRL, X509Certificate peerCert) {
        if (x509CRL.isRevoked(peerCert)) {
            return RevocationStatus.REVOKED;
        } else {
            return RevocationStatus.GOOD;
        }
    }

    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
     * extension in a X.509 certificate. If CRL distribution point extension is
     * unavailable, returns an empty list.
     */
    private List<String> getCrlDistributionPoints(X509Certificate cert) throws CertificateVerificationException, IOException {

        /**Gets the DER-encoded OCTET string for the extension value for CRLDistributionPoints**/

        byte[] crlDPExtensionValue = cert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());

        if (crlDPExtensionValue == null)
            throw new CertificateVerificationException("Certificate doesnt have CRL points");

        /**crlDPExtensionValue is encoded in ASN.1 format.*/

        CRLDistPoint distPoint;
        DEROctetString crlDEROctetString;
        try (ASN1InputStream asn1Input = new ASN1InputStream(crlDPExtensionValue)) {

            crlDEROctetString = (DEROctetString) asn1Input.readObject();
        }
        /**Get Input Stream in 8 Bits**/
        DERTaggedObject crlDERObject;
        try (ASN1InputStream asn1InOctets = new ASN1InputStream(crlDEROctetString.getOctets())) {
            crlDERObject = (DERTaggedObject) asn1InOctets.readObject();
            distPoint = CRLDistPoint.getInstance(crlDERObject);
        } catch (IOException e) {
            throw new CertificateVerificationException("Cannot read certificate to get CRL urls", e);
        }

        List<String> crlUrls = new ArrayList<>();

        /**Loops thorught ASN1Encodable Distponts
         *
         *
         */

        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            /** get ASN1Encobadle DistributionPintName*/

            DistributionPointName dpn = dp.getDistributionPoint();

            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {


                GeneralName[] generalNames = GeneralNames.getInstance(dpn.getName()).getNames();

                /**Looks for a URI
                 * **/

                for (GeneralName genName : generalNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {

                        String url = DERIA5String.getInstance(genName.getName()).getString().trim();
                        crlUrls.add(url);

                    }

                }

            }

        }
        if (crlUrls.isEmpty())
            throw new CertificateVerificationException("Cant get CRL urls from certificate");

        return crlUrls;

    }


    {


    }


    public X509CRL downloadCRLFromWeb(String crlUrl) throws IOException, CertificateVerificationException {

        InputStream crlStream = null;
        try {
            URL url = new URL(crlUrl);
            crlStream = url.openStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(crlStream);
        } catch (MalformedURLException e) {
            throw new CertificateVerificationException("CRL Url is malformed", e);
        } catch (IOException e) {
            throw new CertificateVerificationException("Cant reach URI: " + crlUrl + " - only support HTTP", e);
        } catch (CertificateException e) {
            throw new CertificateVerificationException(e);
        } catch (CRLException e) {
            throw new CertificateVerificationException("Cannot generate X509CRL from the stream data", e);
        } finally {
            if (crlStream != null)
                crlStream.close();
        }
    }
}
