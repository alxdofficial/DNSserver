package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        // TODO (PART 1): Implement this
        DatagramPacket packet = new DatagramPacket(message, message.length, server, DEFAULT_DNS_PORT);
        //setup header
        int id = random.nextInt(0xffff);
//        System.out.println(String.format("0x%04X", id));

        //id
        message[0] = (byte) ((id & 0xff00) >> 8);message[1] = (byte) (id & 0x00ff);
        //1qr,4 opcode, 1AA,1TC,1RD,1RA, 3 Z, 4 r code
        message[2] = (byte) 0;message[3] = (byte) 0;
        //q count
        message[4] = (byte) 0;message[5] = (byte) 1;
        //a count
        message[6] = (byte) 0;message[7] = (byte) 0;
        //ns count
        message[8] = (byte) 0;message[9] = (byte) 0;
        //arcount
        message[10] = (byte) 0;message[11] = (byte) 0;

        int byteOffset = 12;
        //dns question
        List<String> nameClasses = breakHostnameIntoClass(node);
        for (String name : nameClasses) {
//            System.out.println(name);
            message[byteOffset] = (byte) name.length();
            byteOffset++;
            for (char c : name.toCharArray()) {
                message[byteOffset] = (byte) c;
                byteOffset++;
            }
        }
        //signal end of fqdn
        message[byteOffset] = (byte) 0; byteOffset++;
        //q type
        message[byteOffset] = (byte) 0; byteOffset++;message[byteOffset] = (byte) node.getType().getCode(); byteOffset++;
        //q class
        message[byteOffset] = (byte) 0; byteOffset++;message[byteOffset] = (byte) 1; byteOffset++;

//        printMessgae(message);

        socket.send(packet);
        //clear buffer for receive
        clearMessageBuffer(message);

        //receive response
        socket.receive(packet);
//        System.out.println("response: ");
//        printMessgae(packet.getData());

        return new DNSServerResponse(ByteBuffer.wrap(packet.getData()), id);
    }

    //breaks the hostname in dnsnode into domain name classes: for example, www.google.com will be broken
    //into string["www","google","com"]
    private static List<String> breakHostnameIntoClass(DNSNode node) {
        List<String> res = new ArrayList<>();
        String classname = "";
        for (int i = 0; i < node.getHostName().length();i++) {
            if (node.getHostName().charAt(i) == '.') {
                res.add(classname);
                classname = "";
            } else {
                classname += node.getHostName().charAt(i);
            }
        }
        res.add(classname);
        return res;
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        // TODO (PART 1): Implement this
        byte[] message = responseBuffer.array();

//        System.out.println("printing response in decode:");

        int index = 0;
        //check if transaction id is right (for sanity)
        if (message[0] == (byte) ((transactionID & 0xff00) >> 8) && message[1] == (byte) (transactionID & 0x00ff)) {
//            System.out.println("correct id: " + message[0] +" "+ message[1]);
            index += 2;
        }

        int answerOrNameServer = (message[index] & 0xf);
//        System.out.println("answer or nameserver: " + answerOrNameServer);
        index += 1;
        if ((message[index] & 0xf) != 0) {
            System.out.println("error " + (message[index] & 0xf));
        }
        index += 1; index += 2;

        //now we are at answer count in header
        int numAnswers = (message[index] << 8) + message[index + 1];
//        System.out.println("num a: " + numAnswers);
        index += 2;
        //now we are at ns count in header
        int numNameServers = (message[index] << 8) + message[index + 1];
//        System.out.println("num ns: " + numNameServers);
        index += 2; index += 2;

        //now we are at start of query name. we arent using the name for now, and also increment the index
        StringBuilder qName = new StringBuilder();
        index = traverseName(message,index,qName);

        index += 5;
//
//        printMessgae(message, index);

        //now we are at start of first answer
        //we will traverse every answer, and call helper function to create ResourceRecord instances according to whether
        //the answer is ns or a.
        Set<ResourceRecord> resourceRecordsToReturn = new HashSet<>();
//        printMessgae(message, index);
//
//        System.out.println(index);
        for (int i = 0; i < numAnswers + numNameServers; i++) {
            index = processAnswer(message, index, resourceRecordsToReturn);
        }

        for (ResourceRecord r : resourceRecordsToReturn) {
            if (verboseTracing) {
                verbosePrintResourceRecord(r,r.getType().getCode());
            }
            cache.addResult(r);
        }


        return resourceRecordsToReturn;
    }

    // read a dns answer starting from index, and create a resourcerecord to be added to the set. returns what the index should be incremented to.
    private static int processAnswer(byte[] message, int index, Set<ResourceRecord> set) {
        StringBuilder name = new StringBuilder();
//        System.out.println(index);
        if ((byte) message[index] ==(byte) 0xc0) {
            //compressed name
            int nameindex = message[index + 1];
            traverseName(message,nameindex, name);
            index += 3;
        } else {
            index = traverseName(message, index, name);
            index += 2;
        }
//        System.out.println("qname: "+ name);

        //now we are at type
        int type = message[index]; index+=2;
        //now we are at class
        int queryclass = message[index]; index++;
//        System.out.println("type: " + type + "     class: " + queryclass);
        //now we are at ttl
        int ttl = ((message[index]&0xff) << 24) + ((message[index + 1]&0xff) << 16) + ((message[index + 2] & 0xff)<<8) + (message[index+3]);
//        System.out.println("ttl: " + String.format("%08X", ttl));
        index += 4;

        //now we are at rdata length
        int rdatalength = ((message[index] & 0xff) << 8) +message[index + 1];
        index +=2;
        //we are now at the answer
        InetAddress internetAddress = null;
        StringBuilder nextNameServer = new StringBuilder();
        if (type == 1) {
            //ip answer

        } else if (type == 2) {
            //ns answer
            traverseName(message, index, nextNameServer);
//            System.out.println("next name server: " + nextNameServer);
            set.add(new ResourceRecord(name.toString(),RecordType.getByCode(type) ,ttl ,nextNameServer.toString() ));
        }

        index += rdatalength;
//        System.out.println(rdatalength);
        return index;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    private static void printMessgae(byte[] message, int highlightposition) {
        int column = 0;
        for (int i = 0; i < message.length;i++) {
            if (i == highlightposition) {
                System.out.print("HERE|");
            }
            System.out.print(String.format("%02X", message[i]));

            column++;
            if (column == 2) {
                System.out.print("\n");
                column = 0;
            }
        }
    }

    //clear byte buffer
    private static void clearMessageBuffer(byte[] buff) {
        Arrays.fill(buff, (byte) 0);
    }

    //does two things, traverse a name (including reading comrpession pointers) and stores it in stringbuilder, then decides what the next index shoul be
    private static int traverseName(byte[] message, int index, StringBuilder name) {
        int finalindex = index; //keep extra copy so we calculate correct next index

        //traversing the name
        int classNumber = message[index];
        while (classNumber != 0) {
            if (classNumber == (byte) 0xC0) {
                //we encountered a compression pointer, jump to new starting index
                index = message[index + 1];
                classNumber = message[index];
            } else {
                // read name normally
                index ++;
                for (int i = 0; i < classNumber; i++) {
                    name.append((char) message[index]);
                    index ++;
                }
                name.append(".");
                classNumber = message[index];
            }
        }
        name.deleteCharAt(name.length()-1);

        //calculate next index
        while (message[finalindex] != 0x0) {
            if (message[finalindex] == (byte) 0xc0) {
                finalindex += 2;
            }
            finalindex++;
//            finalindex += 2;
//            System.out.println(name);
        }
        return finalindex;
    }
}

