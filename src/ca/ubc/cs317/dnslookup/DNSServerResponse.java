package ca.ubc.cs317.dnslookup;

import java.nio.ByteBuffer;

public class DNSServerResponse {
    private final ByteBuffer response;
    private final int transactionID;

    public DNSServerResponse(ByteBuffer response, int transactionID) {
        this.response = response;
        this.transactionID = transactionID;
    }

    public ByteBuffer getResponse() {
        return response;
    }

    public int getTransactionID() {
        return transactionID;
    }
}
