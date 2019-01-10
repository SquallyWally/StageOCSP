package com.thalesgroup.nl.trtdelft.ocsp;


import com.thalesgroup.nl.trtdelft.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;


public class OCSPVerifier implements RevocationVerifier {

    private OCSPCache cache;
    private static final Log log = LogFactory.getLog(OCSPVerifier.class);


    public OCSPVerifier(OCSPCache cache) {
        this.cache = cache;
    }


    /**Checking the Revo Status */

    public RevocationStatus checkRevocationStatus(X509Certificate peerCertificate, X509Certificate issuerCertificate)
            throws CertificateVerificationException {


        if (cache != null) {
            SingleResp resp = cache.getCacheValue(peerCertificate.getSerialNumber());
            if (resp != null) {
                //If cant be casted, we have used the wrong cache.
                RevocationStatus status = getRevocationStatus(resp);
                log.info("OCSP response has been  taken from the cache....");
                return status;
            }
        }


        OCSPReq request =  generateOCSPRequest(issuerCertificate, peerCertificate.getSerialNumber());

        List<String> locations = getAIALocations(peerCertificate);

        for (String serviceUrl : locations) {

            SingleResp[] responses;
            try {
                OCSPResp ocspResponse = getOCSPResponce(serviceUrl, request);
                if (OCSPResponseStatus.SUCCESSFUL != ocspResponse.getStatus()) {
                    continue; // Server didn't give the response right.
                }

                BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
                responses = (basicResponse == null) ? null : basicResponse.getResponses();


            } catch (Exception e) {
                continue;
            }

            if (responses != null && responses.length == 1) {
                SingleResp resp = responses[0];
                RevocationStatus status = getRevocationStatus(resp);
                if (cache != null)
                    cache.setCacheValue(peerCertificate.getSerialNumber(), resp, request, serviceUrl);
                return status;
            }
        }
        throw new CertificateVerificationException("Cant get an Revocation Status from OCSP.");
    }

    private RevocationStatus getRevocationStatus(SingleResp resp) throws CertificateVerificationException {
        Object status = resp.getCertStatus();
        if (status == CertificateStatus.GOOD) {
            return RevocationStatus.GOOD;
        } else if (status instanceof RevokedStatus) {
            return RevocationStatus.REVOKED;
        } else if (status instanceof UnknownStatus) {
            return RevocationStatus.UNKNOWN;
        }
        throw new CertificateVerificationException("Cant recognize the Certificate Status");
    }


    protected OCSPResp getOCSPResponce(String serviceUrl, OCSPReq request) throws CertificateVerificationException {

        try {
            //Todo: Use http client.
            byte[] array = request.getEncoded();
            if (serviceUrl.startsWith("http")) {
                HttpURLConnection con;
                URL url = new URL(serviceUrl);
                con = (HttpURLConnection) url.openConnection();
                con.setRequestProperty("Content-Type", "application/ocsp-request");
                con.setRequestProperty("Accept", "application/ocsp-response");
                con.setDoOutput(true);
                OutputStream out = con.getOutputStream();
                DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
                dataOut.write(array);

                dataOut.flush();
                dataOut.close();

                //Check errors in response:
                if (con.getResponseCode() / 100 != 2) {
                    throw new CertificateVerificationException("Error getting ocsp response." +
                            "Response code is " + con.getResponseCode());
                }

                //Get Response
                InputStream in = (InputStream) con.getContent();
                return new OCSPResp(in);
            } else {
                throw new CertificateVerificationException("Only http is supported for ocsp calls");
            }
        } catch (IOException e) {
            throw new CertificateVerificationException("Cannot get ocspResponse from url: " + serviceUrl, e);
        }
    }


    private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
            throws CertificateVerificationException {

        //TODO: Have to check if this is OK with synapse implementation.
        //Add provider BC
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            //  CertID structure is used to uniquely identify certificates that are the subject of
            // an OCSP request or response and has an ASN.1 definition. CertID structure is defined in RFC 2560
            JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();

            DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
            DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);

            CertificateID id;


            id = new CertificateID(digestCalculator, new JcaX509CertificateHolder(issuerCert), serialNumber);

            // basic request generation with nonce
            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(id);

            /** create details for nonce extension. The nonce extension is used to bind
             // a request to a response to prevent replay attacks. As the name implies,
             // the nonce value is something that the client should only use once within a reasonably small period.*/

            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            Vector<ASN1ObjectIdentifier> objectIdentifiers = new Vector<ASN1ObjectIdentifier>();
            Vector<X509Extension> values = new Vector<X509Extension>();


            objectIdentifiers.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
            builder.setRequestExtensions(Extensions.getInstance(new X509Extensions(objectIdentifiers, values)));

            return builder.build();
        } catch (OCSPException | OperatorCreationException | CertificateEncodingException e) {
            throw new CertificateVerificationException("Cannot generate OSCP Request with the given certificate", e);
        }
    }

    /**
     * Authority Information Access (AIA) is a non-critical extension in an X509 Certificate. This contains the
     * URL of the OCSP endpoint if one is available.
     * TODO: This might contain non OCSP urls as well. Handle this.
     *
     * @param cert is the certificate
     * @return a lit of URLs in AIA extension of the certificate which will hopefully contain an OCSP endpoint.
     * @throws CertificateVerificationException
     */
    private List<String> getAIALocations(X509Certificate cert) throws CertificateVerificationException {

        //Gets the DER-encoded OCTET string for the extension value for Authority information access Points
        byte[] aiaExtensionValue = cert.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
        if (aiaExtensionValue == null)
            throw new CertificateVerificationException("Certificate Doesnt have Authority Information Access points");
        //might have to pass an ByteArrayInputStream(aiaExtensionValue)
        AuthorityInformationAccess authorityInformationAccess = null;
        try {
            try (ASN1InputStream asn1In = new ASN1InputStream(aiaExtensionValue)) {

                try {
                    DEROctetString aiaDEROctetString = (DEROctetString) (asn1In.readObject());
                    ASN1Sequence aiaASN1Sequence;
                    try (ASN1InputStream asn1Inoctets = new ASN1InputStream(aiaDEROctetString.getOctets())) {
                        aiaASN1Sequence = (ASN1Sequence) asn1Inoctets.readObject();
                    }
                    authorityInformationAccess = new AuthorityInformationAccess(AccessDescription.getInstance(aiaASN1Sequence));
                } catch (IOException e) {
                    throw new CertificateVerificationException("Cannot read certificate to get OSCP urls", e);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        List<String> ocspUrlList = new ArrayList<String>();
        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {

            GeneralName gn = accessDescription.getAccessLocation();
            if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                DERIA5String str = DERIA5String.getInstance(gn.getName());
                String accessLocation = str.getString();
                ocspUrlList.add(accessLocation);
            }
        }
        if (ocspUrlList.isEmpty())
            throw new CertificateVerificationException("Cant get OCSP urls from certificate");

        return ocspUrlList;
    }

}
