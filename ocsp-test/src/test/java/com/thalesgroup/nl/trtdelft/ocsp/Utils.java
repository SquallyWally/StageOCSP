package com.thalesgroup.nl.trtdelft.ocsp;

import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Utils {


    public X509Certificate generateFakeRootCert(KeyPair pair) throws Exception {


        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X500Principal("CN=Test CA Certificate"));
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + TestConstants.VALIDITY_PERIOD));
        certGen.setSubjectDN(new X500Principal("CN=Test CA Certificate"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");

        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }

    public KeyPair generateRSAKeyPair() throws Exception{
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA" , "BC");
        kpGen.initialize(1024 , new SecureRandom());
        return kpGen.generateKeyPair();
    }

    public X509V3CertificateGenerator getUsableCertificateGenerator(X509Certificate caCert,
                                                                    PublicKey peerPublicKey, BigInteger serialNumber) {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + TestConstants.VALIDITY_PERIOD));
        certGen.setSubjectDN(new X500Principal("CN=Test End Certificate"));
        certGen.setPublicKey(peerPublicKey);
        certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");

        return certGen;
    }

    public X509Certificate getRealPeerCertificate()throws Exception {
        return createCertificateFromResourceFile(TestConstants.REAL_PEER_CERT);
    }

    public X509Certificate[] getRealCertificateChain() throws Exception {

        X509Certificate peerCert = createCertificateFromResourceFile(TestConstants.REAL_PEER_CERT);
        X509Certificate rootCert = createCertificateFromResourceFile(TestConstants.ROOT_CERT);
        X509Certificate revokeCert = createCertificateFromResourceFile(TestConstants.REVOKE_CERT);


        return new X509Certificate[]{ peerCert , rootCert , revokeCert};
    }

    public X509Certificate[] getTestCertificateChain() throws Exception{

        KeyPair rootKeyPair = generateRSAKeyPair();
        X509Certificate rootCert = generateFakeRootCert(rootKeyPair);
        KeyPair entityKeyPair = generateRSAKeyPair();
        BigInteger entitySerialNum =BigInteger.valueOf(111);
        X509V3CertificateGenerator certGen = getUsableCertificateGenerator(rootCert,
                entityKeyPair.getPublic(), entitySerialNum);
        X509Certificate entityCert = certGen.generateX509Certificate(rootKeyPair.getPrivate(), "BC");
        return new X509Certificate[]{entityCert, rootCert};
    }

    private X509Certificate createCertificateFromResourceFile(String resourcePath) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509" , "BC");
        File thalesCertificate = new File("bmth.crt");
        InputStream in = new FileInputStream(thalesCertificate);

        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);
        return certificate;
    }
}
