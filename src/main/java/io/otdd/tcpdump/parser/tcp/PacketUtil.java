package io.otdd.tcpdump.parser.tcp;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.io.File;
import java.net.Inet4Address;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PacketUtil {

    public static String getSrcIp(IpV4Packet packet) {
        Inet4Address srcAddr = packet.getHeader().getSrcAddr();
        return srcAddr.getHostAddress();
    }

    public static int getSrcPort(IpV4Packet packet) {
        if (!(packet.getPayload() instanceof TcpPacket)) {
            return -1;
        }
        TcpPacket payload = (TcpPacket) packet.getPayload();
        return payload.getHeader().getSrcPort().valueAsInt();
    }

    public static String getDstIp(IpV4Packet packet) {
        Inet4Address destAddr = packet.getHeader().getDstAddr();
        return destAddr.getHostAddress();
    }

    public static int getDstPort(IpV4Packet packet) {
        if (!(packet.getPayload() instanceof TcpPacket)) {
            return -1;
        }
        TcpPacket payload = (TcpPacket) packet.getPayload();
        return payload.getHeader().getDstPort().valueAsInt();
    }

	public static String determineLocalIp(File tcpdumpFile) {
		PcapHandle handle = null;
		Set<IpPair> ipPairs = new HashSet<IpPair>();
        try {
            handle = Pcaps.openOffline(tcpdumpFile.getAbsolutePath());
            while (true) {
                Packet packet = null;
                try {
                    packet = handle.getNextPacketEx();
                } catch (Exception e) {
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
                if(((TcpPacket)payload).getPayload() == null){
                	continue;
                }
                		
                IpPair pair = new IpPair(getSrcIp(ipV4Packet),getDstIp(ipV4Packet));
                if(!ipPairs.contains(pair)){
                	ipPairs.add(pair);
                }
                
                // 5 pairs of ips are enough to determine the local ip.
                if(ipPairs.size()>5){
                	break;
                }
            }
        }
        catch(Exception e){
        	e.printStackTrace();
        }finally {
            if (handle != null) {
                handle.close();
            }
        }
        if(ipPairs.size()>1){
        	return getCommonIp(ipPairs);
        }
        return null;
	}
	
	private static String getCommonIp(Set<IpPair> ipPairs) {
		Map<String,Integer> ipCnt = new HashMap<String,Integer>();
		for(IpPair pair:ipPairs){
			Integer cnt = ipCnt.get(pair.getIp());
			if(cnt==null){
				cnt = 0;
			}
			cnt++;
			ipCnt.put(pair.getIp(),cnt);
			
			cnt = ipCnt.get(pair.getPeerIp());
			if(cnt==null){
				cnt = 0;
			}
			cnt++;
			ipCnt.put(pair.getPeerIp(),cnt);
		}
		
		String candidate = null;
		Integer maxCnt = 0;
		for(String ip: ipCnt.keySet()){
			if(ipCnt.get(ip)>maxCnt){
				maxCnt = ipCnt.get(ip);
				candidate = ip;
			}
		}
		return candidate;
	}

	static class IpPair implements Comparable<IpPair>{
		private String ip;
		private String peerIp;
		public IpPair(String ip,String peerIp){
			this.ip = ip;
			this.peerIp = peerIp;
		}
		public String getIp() {
			return ip;
		}
		public void setIp(String ip) {
			this.ip = ip;
		}
		public String getPeerIp() {
			return peerIp;
		}
		public void setPeerIp(String peerIp) {
			this.peerIp = peerIp;
		}
		public int compareTo(IpPair o) {
			if(this.ip.equals(o.getIp())&&this.peerIp.equals(o.getPeerIp())){
				return 0;
			}
			if(this.peerIp.equals(o.getIp())&&this.ip.equals(o.getPeerIp())){
				return 0;
			}
			return 1;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof IpPair){
				if(this.compareTo((IpPair)o) == 0){
					return true;
				}
			}
			return false;
		}
		
		@Override
		public int hashCode(){
			return 0;
		}
	}
	
	public static void main(String args[]){
		File tcpdumpFile = new File("/Users/yejie/Documents/tcpdumpfile_20170615100332.pcap");
		String ip = PacketUtil.determineLocalIp(tcpdumpFile);
		System.out.print(ip);
	}
}
