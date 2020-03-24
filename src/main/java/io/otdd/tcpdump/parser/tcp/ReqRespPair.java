package io.otdd.tcpdump.parser.tcp;

import io.otdd.tcpdump.parser.tcp.OneWayData;
import io.otdd.tcpdump.parser.tcp.TcpConnection;

public class ReqRespPair {

    private TcpConnection conn;

    private OneWayData request;
    private OneWayData response;

    public ReqRespPair(TcpConnection conn) {
        this.conn = conn;
    }

    public TcpConnection getConn() {
        return conn;
    }

    public OneWayData getRequest() {
        return request;
    }

    public void setRequest(OneWayData request) {
        this.request = request;
    }

    public OneWayData getResponse() {
        return response;
    }

    public void setResponse(OneWayData response) {
        this.response = response;
    }

    public String toString() {
        return "********* request *********\n" + getRequest() + "\n\n********* response *********\n" + getResponse() + "\n\n********* conn *********\n" + conn.toString();
    }
}
