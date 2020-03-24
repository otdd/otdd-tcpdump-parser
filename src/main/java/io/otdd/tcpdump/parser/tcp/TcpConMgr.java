package io.otdd.tcpdump.parser.tcp;

import io.otdd.tcpdump.parser.testcase.TestCaseMgr;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

import java.net.Inet4Address;
import java.util.HashMap;
import java.util.Map;

public class TcpConMgr {

    private static final Logger LOGGER = LogManager.getLogger(TcpConMgr.class);

    private TestCaseMgr testCaseMgr;
    private String localIp;
    private int listeningPort;
    private Map<String, TcpConnection> connections;

    public TcpConMgr(int listeningPort, String localIp,TestCaseMgr testCaseMgr) {
        this.localIp = localIp;
        this.listeningPort = listeningPort;
        this.testCaseMgr =  testCaseMgr;
        connections  = new HashMap<String, TcpConnection>();
    }

    public TcpConnection getConnection(IpV4Packet ipV4Packet) {
        TcpPacket payload = (TcpPacket) ipV4Packet.getPayload();
        Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
        Inet4Address destAddr = ipV4Packet.getHeader().getDstAddr();

        String srcIp = srcAddr.getHostAddress();
        TcpPort srcPort = payload.getHeader().getSrcPort();
        String destIp = destAddr.getHostAddress();
        TcpPort dstPort = payload.getHeader().getDstPort();

        String localIp = "";
        int localPort;
        String peerIp = "";
        int peerPort;

        if (this.localIp.equals(srcIp)) {
            localIp = srcIp;
            localPort = srcPort.valueAsInt();
            peerIp = destIp;
            peerPort = dstPort.valueAsInt();
        } else if (this.localIp.equals(destIp)) {
            localIp = destIp;
            localPort = dstPort.valueAsInt();
            peerIp = srcIp;
            peerPort = srcPort.valueAsInt();
        } else {
            LOGGER.fatal("wrong srcIp or destIp. srcIp:{},destIp:{},localIp:{}", srcIp, destIp, localIp);
            return null;
        }

        String key = connKeyGenerate(localIp, localPort, peerIp, peerPort);
        TcpConnection conn = connections.get(key);
        if (conn == null) {
            boolean serverConnection = false;
            if (listeningPort == localPort) {
                serverConnection = true;
            }

            ConnDirection connDirection = ConnDirection.UNKNOWN;
            if (payload.getHeader().getSyn() && !payload.getHeader().getAck()) {
                connDirection = ConnDirection.OUTGOING;
                if (localIp.equals(destIp)) {
                    connDirection = ConnDirection.INCOMING;
                }
            }
            conn = new TcpConnection(localIp, localPort, peerIp, peerPort,
                    serverConnection, connDirection, testCaseMgr, this);
            connections.put(key, conn);
        }

        return conn;
    }

    public void removeConnection(TcpConnection conn) {
        String key = connKeyGenerate(conn.getLocalIp(), conn.getLocalPort(), conn.getPeerIp(), conn.getPeerPort());
        connections.remove(key);
    }

    public Map<String, TcpConnection> getConnections() {
        return connections;
    }

    private String connKeyGenerate(String localIp, int localPort, String peerIp, int peerPort) {
        return String.format("%s|%d|%s|%d", localIp, localPort, peerIp, peerPort);
    }
}
