package io.otdd.tcpdump.parser.tcp;

import org.pcap4j.packet.IpV4Packet;

public class IpV4PacketWrapper {

    public int index;
    public IpV4Packet packet;

    //in milliseconds
    public long timestamp;

    public IpV4PacketWrapper(int index, IpV4Packet packet, long timestamp) {
        this.index = index;
        this.packet = packet;
        this.timestamp = timestamp;
    }
}
