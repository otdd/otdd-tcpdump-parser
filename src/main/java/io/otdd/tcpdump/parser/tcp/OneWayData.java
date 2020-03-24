package io.otdd.tcpdump.parser.tcp;

import org.pcap4j.packet.TcpPacket;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

public class OneWayData {
    private TcpConnection conn;
    private long timestamp = -1L;
    private byte[] bytes;

    private boolean hasData = false;
    private boolean pshSent = false;

    private List<IpV4PacketWrapper> associatedPackets = new ArrayList<IpV4PacketWrapper>();

    private boolean hasExtractedBytes = false;

    public OneWayData(TcpConnection conn) {
        this.conn = conn;
    }

    public void sortPackets() {
        MyComparetor mc = new MyComparetor();
        try {
            associatedPackets.sort(mc);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void extractBytes() {
        if (hasExtractedBytes) {
            return;
        }
        hasExtractedBytes = true;

        removeNoneTcpPacket();
        sortPackets();
        remoteDuplicatePackets();
        
        int size = 0;
        for (IpV4PacketWrapper wrapper : this.associatedPackets) {
            TcpPacket payload = (TcpPacket) wrapper.packet.getPayload();
            if (payload.getPayload() != null) {
                size += payload.getPayload().getRawData().length;
            }
        }

        bytes = new byte[size];
        int copied = 0;
        for (IpV4PacketWrapper wrapper : this.associatedPackets) {
            TcpPacket payload = (TcpPacket) wrapper.packet.getPayload();
            if (payload.getPayload() != null) {
                if (timestamp == -1L) {
                    timestamp = wrapper.timestamp;
                }
                byte[] rawData = payload.getPayload().getRawData();
                System.arraycopy(rawData, 0, bytes, copied, rawData.length);
                copied += rawData.length;
            }
        }

    }

    private void removeNoneTcpPacket() {
    	Iterator<IpV4PacketWrapper> it = this.associatedPackets.iterator();
    	while(it.hasNext()){
    		IpV4PacketWrapper wrapper = it.next();
    		if (!(wrapper.packet.getPayload() instanceof TcpPacket)) {
                it.remove();
            }
    	}
	}

	private void remoteDuplicatePackets() {
    	Iterator<IpV4PacketWrapper> it = this.associatedPackets.iterator();
    	long currentSeq = -1;
    	int currentLen = 0;
    	while(it.hasNext()){
    		IpV4PacketWrapper wrapper = it.next();
    		TcpPacket payload = (TcpPacket) wrapper.packet.getPayload();
    		long seq = payload.getHeader().getSequenceNumberAsLong();
    		int len = payload.getRawData().length;
    		//retransmission
    		if(currentLen>0
    				&&currentLen==len
    				&&seq==currentSeq){
    			it.remove();
    		}
    		currentLen = len;
    		currentSeq = seq;
    	}
	}

    public TcpConnection getConn() {
        return conn;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public byte[] getBytes() {
        extractBytes();
        return bytes;
    }

    public boolean hasData() {
        return hasData;
    }

    public void setHasData(boolean hasData) {
        this.hasData = hasData;
    }

    public List<IpV4PacketWrapper> getAssociatedPackets() {
        return associatedPackets;
    }

    public boolean pshSent() {
        return pshSent;
    }

    class MyComparetor implements Comparator {
        public int compare(Object l, Object r) {
            IpV4PacketWrapper left = (IpV4PacketWrapper) l;
            IpV4PacketWrapper right = (IpV4PacketWrapper) r;

            TcpPacket leftPackt = (TcpPacket) left.packet.getPayload();
            TcpPacket rightPackt = (TcpPacket) right.packet.getPayload();

            if (leftPackt.getHeader().getSequenceNumberAsLong()
                    < rightPackt.getHeader().getSequenceNumberAsLong()) {
                return -1;
            } else if (leftPackt.getHeader().getSequenceNumberAsLong()
                    > rightPackt.getHeader().getSequenceNumberAsLong()) {
                return 1;
            }
            return 0;
        }
    }

    public String toString() {
        byte[] bytes = getBytes();
        return new String(bytes);
    }
}


