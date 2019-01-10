package com.thalesgroup.nl.trtdelft;

public enum RevocationStatus {
    GOOD("Good"), REVOKED("Revoked"), UNKNOWN("Unknown");

    private String message;


    //RevocationStatus Constryctir
    RevocationStatus(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
