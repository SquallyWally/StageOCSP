package com.thalesgroup.nl.trtdelft.ocsp;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.*;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

public class OCSPServerTest implements HttpHandler {

    public static void main(String[] args) {


        //RevocationVerificationManager manager;


        try {
            OCSPServerTest ocspServerTest = new OCSPServerTest();
            ocspServerTest.setupCA();
            // ocspServerTest.processOCSPRequest(10000);

            /**run HTTP server on port 16000
             Listen on OCSP request on port 16000**/

            HttpServer server = HttpServer.create(new InetSocketAddress(16000), 0);
            server.createContext("/", ocspServerTest);
            server.setExecutor(null); /** createsa default executor*/
            server.start();
        } catch (IOException e) {
            System.out.println("Http exception: " + e.getMessage());

        }

    }

    /**
     * when it require any request to be signed
     */
    boolean bRequireRequestSignatur = true;
    /**
     * set true when the OCSP client use a nonce in request
     */
    boolean bRequireNonce = true;


    public void handle(HttpExchange hex) throws IOException {
        InputStream request = hex.getRequestBody();
        byte[] requestBytes = new byte[10000];
        int requestSize = request.read(requestBytes);
        System.out.println("Received OCSP request ,  size : " + requestSize);

        byte[] responseBytes = new byte[2];
        responseBytes = processOCSPRequest(requestBytes);

        Headers rh = hex.getResponseHeaders();
        rh.set("Content-Type", "application/ocsp-response");
        hex.sendResponseHeaders(200, responseBytes.length);

        OutputStream os = hex.getResponseBody();
        os.write(requestBytes);
        os.close();
    }

    /**
     * if it contains a cert
     */
    private X509CertificateHolder internalCACertificate = null;
    /**
     * if it contains a Private Key
     */
    private PrivateKey internalCAPrivateKey = null;

    /**
     * if it contans a Public Key
     */

    private PublicKey internalCAPublicKey = null;


    private void setupCA() {


        /**Initialize BouncyCastle OCSP WOOHOOOO!!!!!*/

        Security.addProvider(new BouncyCastleProvider());

        byte[] b = null;

        //OCSPVerifier verifier = new OCSPVerifier();
        /**Use CA.crt Mr Thales as example*/
        try (RandomAccessFile raf = new RandomAccessFile("bmth.crt", "r")) {

            b = new byte[(int) raf.length()];
            raf.read(b);


            /**Prints out the content within the Certificate*/
            try (InputStream inp = new FileInputStream("bmth.crt")) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) factory.generateCertificate(inp);
               System.out.println("De certificaat bestaat!");
            }


        } catch (Exception e) {
            System.out.println("Can't load the ICA certificate file: " + e.getMessage());
            return;
        }
        try {
            internalCACertificate = new X509CertificateHolder(b);
        } catch (Exception e) {
            System.out.println("Can't parse the ICA certificate: " + e.getMessage());
        }
        internalCAPrivateKey = readPrivateKey("thales_key.der");
        internalCAPublicKey = readPublicKey("bmthPublic.der");


    }

    private PublicKey
    readPublicKey(String fileName) {

        try {
            byte[] buf1;
            try (RandomAccessFile rafilePK = new RandomAccessFile(fileName, "r")) {
                buf1 = new byte[(int) rafilePK.length()];
                rafilePK.readFully(buf1);


            }

            X509EncodedKeySpec kspecPK = new X509EncodedKeySpec(buf1);

            KeyFactory kfPK = KeyFactory.getInstance("RSA");
            RSAPublicKey pubKey = (RSAPublicKey) kfPK.generatePublic(kspecPK);
            System.out.println("Public Key =   " + pubKey.getPublicExponent());
            return kfPK.generatePublic(kspecPK);

        } catch (Exception e) {
            System.out.println("Cannot load public key: " + e.getMessage());
            return null;
        }
    }


    private PrivateKey readPrivateKey(String fileName) {
        try {
            byte[] buf;
            try (RandomAccessFile rafile = new RandomAccessFile(fileName, "r")) {
                buf = new byte[(int) rafile.length()];
                rafile.readFully(buf);


            }
            PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);


            KeyFactory kf = KeyFactory.getInstance("RSA");

            RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(kspec);
            System.out.println("Private Key =   " + privKey.getPrivateExponent());
            return kf.generatePrivate(kspec);


        } catch (Exception e) {
            System.out.println("Cannot load private key: " + e.getMessage());
            return null;
        }
    }

    public byte[] processOCSPRequest(byte[] requestBytes) {
        try {
            /**get Request information*/
            OCSPReq ocspRequest = new OCSPReq(requestBytes);
            X509CertificateHolder[] requestCerts = ocspRequest.getCerts();
            Req[] requestList = ocspRequest.getRequestList();

            /**Setup response*/
            BasicOCSPRespBuilder responseBuilder =
                    new BasicOCSPRespBuilder(new RespID(internalCACertificate.getSubject()));


            System.out.println("OCSP request version: " + ocspRequest.getVersionNumber() +
                    ", Requestor name: " + ocspRequest.getRequestorName()
                    + ", is signed: " + ocspRequest.isSigned()
                    + ", has extentions: " + ocspRequest.hasExtensions()
                    + ", number of additional certificates: "
                    + requestCerts.length
                    + ", number of certificate ids to verify: "
                    + requestList.length);

            int ocspResult = OCSPRespBuilder.SUCCESSFUL;

            /**Signature checker*/

            if (ocspRequest.isSigned()) {

                System.out.println("OCSP Request verify request signature: try certificates from request");
                boolean bRequestSignatureValid = false;

                for (X509CertificateHolder cert : ocspRequest.getCerts()) {

                    ContentVerifierProvider cpv =
                            new JcaContentVerifierProviderBuilder().setProvider("BC").build(cert);
                    bRequestSignatureValid = ocspRequest.isSignatureValid(cpv);

                    if (bRequestSignatureValid) {
                        break;
                    }
                }
                if (!bRequestSignatureValid) {
                    System.out.println("OCSP Request verify request signature: try CA certificate");
                    ContentVerifierProvider cpv =
                            new JcaContentVerifierProviderBuilder().setProvider("BC").build(internalCACertificate);
                    bRequestSignatureValid = ocspRequest.isSignatureValid(cpv);
                }

                if (bRequestSignatureValid) {
                    System.out.println("OCSP Request signature validation succesfull");
                } else {

                    System.out.println("OCSP Request signature valiation failed");
                    ocspResult = OCSPRespBuilder.UNAUTHORIZED;
                }

            } else {
                if (bRequireRequestSignatur) {
                    System.out.println("OCSP Request signature is not present but required, fail the request");
                    ocspResult = OCSPRespBuilder.SIG_REQUIRED;
                }
            }

            /**Process nonce*/
            Extension extNonce = ocspRequest.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"));

            if (extNonce != null) {
                System.out.println("Nonce is present in the request");
                responseBuilder.setResponseExtensions(new Extensions(extNonce));
            } else {
                System.out.println("Nonce is not present in the request");
                if (bRequireNonce) {
                    System.out.println("Nonce is required, fail the request");
                    ocspResult = OCSPRespBuilder.UNAUTHORIZED;
                }
            }
            /** check all certificate serial numbers*/

            if (ocspResult == OCSPRespBuilder.SUCCESSFUL) {
                for (Req req : requestList) {
                    CertificateID certId = req.getCertID();
                    String serialNumber = "0x" + certId.getSerialNumber().toString(16);

                    CertificateStatus certificateStatus = null;

                    /**Check CertID isuer and PK hash*/

                    System.out.println("Check issuer for certificate entry serial number: " + serialNumber);

                    if (certId.matchesIssuer(internalCACertificate, new BcDigestCalculatorProvider())) {

                        System.out.println("Check issuer succesful");

                    } else {
                        System.out.println("Check issuer failed. Status unknown lol");
                        certificateStatus = new UnknownStatus();
                    }

                    if (certificateStatus == null) {
                        System.out.println("Check revocation status for certificate entryt serial number : " + serialNumber);

                        if (serialNumber.equals("00b19c9a5b518ae2ed")) {
                            certificateStatus = CertificateStatus.GOOD;
                        } else {
                            System.out.println("Status unknown");
                            certificateStatus = new UnknownStatus();
                        }

                    }

                    Calendar thisUpdate = new GregorianCalendar();
                    thisUpdate.set(2017, 12, 1);

                    Calendar nextUpdate = new GregorianCalendar();
                    nextUpdate.set(2018, 2, 1);

                    responseBuilder.addResponse(certId, certificateStatus, thisUpdate.getTime(), nextUpdate.getTime(), null);


                }
            }

            X509CertificateHolder[] chain = {internalCACertificate};
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(internalCAPrivateKey);

            BasicOCSPResp ocspResponse = responseBuilder.build(signer, chain, Calendar.getInstance().getTime());

            OCSPRespBuilder ocspResponseBuilder = new OCSPRespBuilder();
            byte[] encoded = ocspResponseBuilder.build(ocspResult, ocspResponse).getEncoded();

            System.out.println("Sending OCSP response to client, size: " + encoded.length);
            return encoded;

        } catch (Exception e) {
            System.out.println("Exception during processing OCSP request: " + e.getMessage());
        }

        return null;
    }
}