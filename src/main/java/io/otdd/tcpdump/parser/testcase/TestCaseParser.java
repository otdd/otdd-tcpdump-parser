package io.otdd.tcpdump.parser.testcase;

import io.otdd.tcpdump.parser.tcp.IpV4PacketWrapper;
import io.otdd.tcpdump.parser.tcp.PacketUtil;
import io.otdd.tcpdump.parser.tcp.TcpConMgr;
import io.otdd.tcpdump.parser.tcp.TcpConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.io.EOFException;
import java.io.File;
import java.util.HashSet;
import java.util.Set;

public class TestCaseParser {

    private static final Logger LOGGER = LogManager.getLogger(TestCaseParser.class);

    private String localIp;
    private String module;
    private String protocol;
    private int listenPort;
    private Set<String> ignoreLocalPorts;
    private Set<String> ignoreRemoteIpPorts;
    private String otddServerHost;
    private int otddServerPort;

    public TestCaseParser(String moduleName, String protocol,
                          int listenPort,Set<String> ignoreLocalPorts,Set<String> ignoreRemoteIpPorts,
                          String otddServerHost,int otddServerPort){
        this.module = moduleName;
        this.protocol = protocol;
        this.listenPort = listenPort;
        this.ignoreLocalPorts = ignoreLocalPorts;
        if(this.ignoreLocalPorts == null){
            this.ignoreLocalPorts = new HashSet<String>();
        }
        this.ignoreRemoteIpPorts = ignoreRemoteIpPorts;
        if(this.ignoreRemoteIpPorts == null){
            this.ignoreRemoteIpPorts = new HashSet<String>();
        }
        this.otddServerHost = otddServerHost;
        this.otddServerPort = otddServerPort;
    }

    public boolean parseFile(File tcpdumpFile) {
        LOGGER.info("parsing file:{}", tcpdumpFile.getName());
        
        this.localIp = PacketUtil.determineLocalIp(tcpdumpFile);
        
        if(this.localIp==null){
            LOGGER.info("local ip can not be determined.", tcpdumpFile.getName());
        	return false;
        }

        TestCaseMgr testCaseMgr = new TestCaseMgr(this.module,this.protocol,
                this.otddServerHost,this.otddServerPort);
        TcpConMgr tcpConMgr = new TcpConMgr(listenPort,this.localIp,testCaseMgr);
        PcapHandle handle = null;
        try {
            handle = Pcaps.openOffline(tcpdumpFile.getAbsolutePath());
            int index = 0;
            while (true) {
                index++;
                Packet packet = null;
                long timestamp = -1L;
                try {
                    packet = handle.getNextPacketEx();
                    timestamp = handle.getTimestamp().getTime();
                }
                catch (EOFException e){//end of file.
                    break;
                }
                catch (Exception e) {
                    LOGGER.error(String.format("get packet timestamp fail,errMsg=%s，index=%d", e.toString(), index));
                    break;
                }

                if (packet == null) {
                    break;
                }

                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                if (ipV4Packet == null) {
                    continue;
                }

                Packet payload = ipV4Packet.getPayload();
                if (payload == null || !(payload instanceof TcpPacket)) {
                    continue;
                }

                IpV4PacketWrapper wrapper = new IpV4PacketWrapper(index, ipV4Packet, timestamp);
                addPacket(wrapper, tcpConMgr);
            }
        } catch (Exception e) {
            LOGGER.fatal("fail to open pcap file,file:{},errMsg:{}", tcpdumpFile.getName(), e.toString());
            e.printStackTrace();
            return false;
        } finally {
            if (handle != null) {
                handle.close();
            }
        }
        LOGGER.info("finished to process input file:{}", tcpdumpFile.getName());
        return true;
    }

	private void addPacket(IpV4PacketWrapper wrapper, TcpConMgr tcpConMgr) {
        if (ignored(wrapper.packet)) {
            return;
        }

        TcpConnection connection = tcpConMgr.getConnection(wrapper.packet);
        if (connection == null) {
            LOGGER.fatal("fail to get conn.");
            return;
        }
        for (TcpConnection conn : tcpConMgr.getConnections().values()) {
            conn.onCurrentTimeChanged(wrapper.timestamp);
        }

        connection.addPacket(wrapper);

    }
    
    private boolean ignored(IpV4Packet packet) {
		String srcIp = PacketUtil.getSrcIp(packet);
		int srcPort = PacketUtil.getSrcPort(packet);
		String dstIp = PacketUtil.getDstIp(packet);
		int dstPort = PacketUtil.getDstPort(packet);

		String connectSrcKey = srcIp+":" +srcPort;
		String connectDstKey = dstIp + ":" + dstPort;
		
		Set<String> ignoreLocalPorts = this.ignoreLocalPorts;
		Set<String> ignoreRemoteIpPorts = this.ignoreRemoteIpPorts;
		//out packet
		if(localIp.equals(srcIp)){
			if(ignoreLocalPorts.contains(srcPort+"")){
				return true;
			}
			if(ignoreRemoteIpPorts.contains(connectDstKey) || ignoreRemoteIpPorts.contains(dstPort+"") ||
					ignoreRemoteIpPorts.contains(dstIp)){
				return true;
			}
		}

		// in packet
		if(localIp.equals(dstIp)){
			if(ignoreLocalPorts.contains(dstPort+"")){
				return true;
			}
			if(ignoreRemoteIpPorts.contains(connectSrcKey) || ignoreRemoteIpPorts.contains(srcPort+"") ||
					ignoreRemoteIpPorts.contains(srcIp)){
				return true;
			}
		}
		return false;
	}

}
