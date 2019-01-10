package com.thalesgroup.nl.trtdelft.ocsp;

import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.nio.file.Paths;

public interface TestConstants {

    /**checks vaidty period for 1 day*/

      int VALIDITY_PERIOD = 24 * 60 * 60 * 1000;

      /**Next update for OCSPResponse */
      int NEXT_UPDATE_PERIOD = 1000000;


      Path path  = Paths.get("C:\\Users\\milangelok\\IdeaProjects\\ocsp-test\\thales.der");
     String REAL_PEER_CERT = path.toString() ;

  final static String REVOKE_CERT = "C:\\Users\\milangelok\\IdeaProjects\\ocsp-test\\certRevoke.crt";
     final static String ROOT_CERT = "C:\\Users\\milangelok\\IdeaProjects\\ocsp-test\\bmth.crt";
}
