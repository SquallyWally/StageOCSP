package com.thalesgroup.nl.trtdelft.ocsp;


import com.thalesgroup.nl.trtdelft.RevocationStatus;
import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

public class OCSPVerifierTest extends TestCase {

    public void testOCSPVerifier() throws Exception {
        //Add BC as Provider

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Utils utils = new Utils();

        KeyPair caKeyPair = utils.generateRSAKeyPair();
        X509Certificate caCert = utils.generateFakeRootCert(caKeyPair);


        /**Create fake peer certs signed by fake CA priv key. THIS WILL BE THE REVOKED CERTIFICATE*/

        KeyPair peerKeyPair = utils.generateRSAKeyPair();
        BigInteger revokedSerialNumber = BigInteger.valueOf(111);
        X509Certificate revokedCertificate = generateFakePeerCert(revokedSerialNumber, peerKeyPair.getPublic(),
                caKeyPair.getPrivate(), caCert);

        /**Create OCSP request to check if certificate with "serialNumber == revokedSerialNumber" is revoked*/
        OCSPReq request = getOCSPRequest(caCert, revokedSerialNumber);

        /**Create OCSP response saying that certificate with given serialNumber is revoked*/


        JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);

        CertificateID revokedID = new CertificateID(digestCalculator, new JcaX509CertificateHolder(caCert), revokedSerialNumber);
        OCSPResp response = generateOCSPResponse(request,caKeyPair.getPrivate(),  caKeyPair.getPublic(), revokedID);
        SingleResp singleResp = ((BasicOCSPResp) response.getResponseObject()).getResponses()[0];

        OCSPCache cache = OCSPCache.getCache();
        cache.init(5, 5);
        cache.setCacheValue(revokedSerialNumber, singleResp, request, null);

        OCSPVerifier ocspVerifier = new OCSPVerifier(cache);
        RevocationStatus status = ocspVerifier.checkRevocationStatus(revokedCertificate, caCert);

        //the cache will have the SingleResponse derived from the OCSP response and it will be checked to see if the
        //fake certificate is revoked. So the status should be REVOKED.
        assertTrue(status == RevocationStatus.REVOKED);
    }


    /**
     * An OCSP request is made to be given to the fake CA. Reflection is used to call generateOCSPRequest(..) private
     * method in OCSPVerifier.
     *
     * @param caCert              the fake CA certificate.
     * @param revokedSerialNumber the serial number of the certificate which needs to be checked if revoked.
     * @return the created OCSP request.
     * @throws Exception
     */
    private OCSPReq getOCSPRequest(X509Certificate caCert, BigInteger revokedSerialNumber) {
        OCSPVerifier ocspVerifier = new OCSPVerifier(null);
        Class ocspVerifierClass = ocspVerifier.getClass();
        Method generateOCSPRequest = null;
        try {
            generateOCSPRequest = ocspVerifierClass.getDeclaredMethod("generateOCSPRequest", X509Certificate.class,
                    BigInteger.class);
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        generateOCSPRequest.setAccessible(true);

        OCSPReq request = null;
        try {
            request = (OCSPReq) generateOCSPRequest.invoke(ocspVerifier, caCert, revokedSerialNumber);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
        return request;
    }


    /**88888888888888888888888888888888888888888888*/

    /**
     * This makes the corresponding OCSP response to the OCSP request which is sent to the test CA. If the request
     * has a certificateID which is marked as revoked by the CA, the OCSP response will say that the certificate
     * which is referred to by the request, is revoked.
     *
     * @param request      the OCSP request which asks if the certificate is revoked.
     * @param aPrivate privateKey of the test CA.
     * @param aPublic  publicKey of the test CA
     * @param revokedID    the ID at test CA which is checked against the certificateId in the request.
     * @return the created OCSP response by the test CA.

     * @throws OCSPException
     */
    private OCSPResp generateOCSPResponse(OCSPReq request, PrivateKey aPrivate, PublicKey  aPublic, CertificateID revokedID) throws OCSPException, OperatorCreationException {


        DigestCalculator digestCalc = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1);


        byte[]encoded = aPublic.getEncoded();
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));


        BasicOCSPRespBuilder basicOCSPRespBuilder = new BasicOCSPRespBuilder(subjectPublicKeyInfo,digestCalc);






        /**Hier maak ik een verzoek Extensties aan, deze variabel bevat de OCSPReq Request die RequestExtensions moet opvragen
         * Maar als ik OCSPReqStatus gebruikt dan gaat deze hele code naar de klote*/
        X509Extensions requestExtensions = X509Extensions.getInstance(request);


        if (requestExtensions != null) {

            /**Create a bloody extension */
            X509Extension extension;
            extension = requestExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);


            if (extension != null) {

                Vector<ASN1ObjectIdentifier> oids = new Vector<ASN1ObjectIdentifier>();
                Vector<X509Extension> values = new Vector<X509Extension>(

                );

                oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                values.add(extension);

                basicOCSPRespBuilder.setResponseExtensions(Extensions.getInstance(new X509Extensions(oids, values)));
            }
        }

      /**  OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(revokedID);
        ocspReqBuilder.setRequestExtensions(Extensions.getInstance(requestExtensions));
        OCSPReq ocspReq = ocspReqBuilder.build();*/

        Req[] requests = request.getRequestList();

        for (Req req : requests) {

            CertificateID certID = req.getCertID();

            if (certID.equals(revokedID)) {

                RevokedStatus revokedStatus = new RevokedStatus(new Date(), CRLReason.privilegeWithdrawn);
                Date nextUpdate = new Date(new Date().getTime() + TestConstants.NEXT_UPDATE_PERIOD);
                basicOCSPRespBuilder.addResponse(certID, revokedStatus, nextUpdate, (Extensions) null);
            } else {
                basicOCSPRespBuilder.addResponse(certID, CertificateStatus.GOOD);
            }
        }


        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(aPrivate);
        BasicOCSPResp basicResp =  basicOCSPRespBuilder.build(contentSigner, null, new Date());
        OCSPRespBuilder respBuilder = new OCSPRespBuilder();

        return respBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicResp);
    }

    private X509Certificate generateFakePeerCert(BigInteger serialNumber, PublicKey entityKey,
                                                 PrivateKey caKey, X509Certificate caCert)
            throws Exception {
        Utils utils = new Utils();
        X509V3CertificateGenerator certGen = utils.getUsableCertificateGenerator(caCert, entityKey, serialNumber);
        return certGen.generateX509Certificate(caKey, "BC");
    }
}

