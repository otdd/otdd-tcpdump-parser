package io.otdd.tcpdump.parser.tcp;

import io.otdd.tcpdump.parser.testcase.TestCaseMgr;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.packet.TcpPacket;

public class TcpConnection {

    private static final Logger LOGGER = LogManager.getLogger(TcpConnection.class);

    private static final long MAX_PACKET_LAG_TIME = 200;

    private String localIp;
    private int localPort;
    private String peerIp;
    private int peerPort;

    private boolean serverConnection;
    private ConnDirection connDirection = ConnDirection.UNKNOWN;

    private boolean finReceived;
    private boolean finSent;

    private long lastInDataTimestamp = -1;
    private long lastOutDataTimestamp = -1;

    private OneWayData inEntity;
    private OneWayData outEntity;

    private TestCaseMgr testCaseMgr;
    private TcpConMgr tcpConnMgr;
    
    private long expectedOutSeq = 0;
    private long ackedInSeq = 0;

    public TcpConnection(String localIp, int localPort, String peerIp, int peerPort, boolean serverConnection,
                         ConnDirection connDirection, TestCaseMgr testCaseMgr, TcpConMgr tcpConnMgr) {
        this.localIp = localIp;
        this.localPort = localPort;
        this.peerIp = peerIp;
        this.peerPort = peerPort;
        this.serverConnection = serverConnection;
        this.connDirection = connDirection;
        this.testCaseMgr = testCaseMgr;
        this.tcpConnMgr = tcpConnMgr;
    }

    public void addPacket(IpV4PacketWrapper wrapper) {
    	
        LOGGER.trace("packet added. localIp:{} localPort:{} peerIp:{} peerPort:{} serverConnection:{}",
                localIp, localPort, peerIp, peerPort, serverConnection);

        //in packet
        if (PacketUtil.getDstIp(wrapper.packet).equals(localIp)
                && PacketUtil.getDstPort(wrapper.packet) == localPort) {
        	
        	if(filterInPacket((TcpPacket) wrapper.packet.getPayload())){
        		LOGGER.warn("spurious retransmission in packet. packet index:"+wrapper.index);
        		return;
        	}
        	
            if (inEntity == null) {
                inEntity = new OneWayData(this);
            }
            inEntity.getAssociatedPackets().add(wrapper);

            TcpPacket payload = (TcpPacket) wrapper.packet.getPayload();
            
            if (payload.getPayload() != null) {

                lastInDataTimestamp = wrapper.timestamp;

                if (outEntity != null && outEntity.hasData()) {
                    onEntitySent();
                }

                if (!inEntity.hasData() && serverConnection) {
                    onSessionStart();
                }

                inEntity.setHasData(true);

            }

            if (payload.getHeader().getFin()) {
                if (inEntity != null && inEntity.hasData()) {
                    onEntityReceived();
                }
                inEntity = null;
                finReceived = true;
                processFin();
            }
        }

        else if (PacketUtil.getSrcIp(wrapper.packet).equals(localIp)
                && PacketUtil.getSrcPort(wrapper.packet) == localPort) {
        	
        	if(filterOutPacket((TcpPacket) wrapper.packet.getPayload())){
        		LOGGER.warn("tcp retransmission out packet. packet index:"+wrapper.index);
        		return;
        	}
        	
            if (outEntity == null) {
                outEntity = new OneWayData(this);
            }
            outEntity.getAssociatedPackets().add(wrapper);
            TcpPacket payload = (TcpPacket) wrapper.packet.getPayload();
            
            updateSeqs(payload);
            
            if (payload.getPayload() != null) {
                lastOutDataTimestamp = wrapper.timestamp;

                outEntity.setHasData(true);
                if (inEntity != null && inEntity.hasData()) {
                    onEntityReceived();
                }
            }

            if (payload.getHeader().getFin()) {
                if (outEntity != null && outEntity.hasData()) {
                    onEntitySent();
                }
                outEntity = null;
                finSent = true;
                processFin();
            }
        } else {
            LOGGER.fatal("packet is not valid for this connection! packet srcIp:{},srcPort:{},dstIp:{},dstPort:{}",
                    PacketUtil.getSrcIp(wrapper.packet), PacketUtil.getSrcPort(wrapper.packet),
                    PacketUtil.getDstIp(wrapper.packet), PacketUtil.getDstPort(wrapper.packet));
        }

    }

    /*
     * MAX_PACKET_LAG_TIME marks the end of entity.
     */
    public void onCurrentTimeChanged(long currentTimestamp) {

        if ((currentTimestamp - lastInDataTimestamp) > MAX_PACKET_LAG_TIME) {
            if (inEntity != null && inEntity.hasData()) {
                onEntityReceived();
            }
        }

        if ((currentTimestamp - lastOutDataTimestamp) > MAX_PACKET_LAG_TIME) {
            if (outEntity != null && outEntity.hasData()) {
                onEntitySent();
            }
        }
    }

    private void updateSeqs(TcpPacket payload) {
    	long ackedInSeq = payload.getHeader().getAcknowledgmentNumberAsLong();
        if(this.ackedInSeq<ackedInSeq){
        	this.ackedInSeq = ackedInSeq;
        }
        long seq = payload.getHeader().getSequenceNumberAsLong();
        long dataLen = 0;
        if (payload.getPayload() != null) {
        	dataLen = payload.getPayload().getRawData().length;
        }
        this.expectedOutSeq = seq+dataLen;
	}

	private boolean filterOutPacket(TcpPacket payload) {
    	long outSeq = payload.getHeader().getSequenceNumberAsLong();
    	if(expectedOutSeq>outSeq){
    		return true;
    	}
		return false;
	}

	private boolean filterInPacket(TcpPacket payload) {
    	long inSeq = payload.getHeader().getSequenceNumberAsLong();
    	if(this.ackedInSeq>inSeq){
    		return true;
    	}
		return false;
	}

	private void onSessionStart() {
        if (inEntity != null && inEntity.hasData()) {
            onEntityReceived();
        }
        if (outEntity != null && outEntity.hasData()) {
            onEntitySent();
        }
        testCaseMgr.onTestCaseStart(this);
    }

    private void onEntitySent() {
        testCaseMgr.onEntitySent(this, outEntity);
        outEntity = null;
    }

    private void onEntityReceived() {
        testCaseMgr.onEntityReceived(this, inEntity);
        inEntity = null;
    }

    private void processFin() {
        if (finReceived && finSent) {
            tcpConnMgr.removeConnection(this);
        }
    }

    @Override
    public String toString() {
        return "localIp:" + localIp + " localPort:" + localPort + " peerIp:" + peerIp +
                " peerPort:" + peerPort + " serverConnection:" + serverConnection + " connDirection:" + connDirection;
    }

    public String getLocalIp() {
        return localIp;
    }

    public int getLocalPort() {
        return localPort;
    }

    public String getPeerIp() {
        return peerIp;
    }

    public int getPeerPort() {
        return peerPort;
    }

    public boolean isServerConnection() {
        return serverConnection;
    }

    public ConnDirection getConnDirection() {
        return connDirection;
    }

}
