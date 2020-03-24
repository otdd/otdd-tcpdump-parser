package io.otdd.tcpdump.parser.testcase;

import io.otdd.tcpdump.parser.tcp.ReqRespPair;

import java.util.ArrayList;
import java.util.List;

public class TestCase {

    private String testId;

    // the in-coming request and corresponding response.
    private ReqRespPair inbound = null;

    // the out-going request and corresponding response.
    private List<ReqRespPair> outbounds = new ArrayList<ReqRespPair>();

    public TestCase() {
        this.testId = TestIdGenerator.generateId();
    }

    public String getTestId() {
        return testId;
    }

    public ReqRespPair getInbound() {
        return inbound;
    }

	public void setInbound(ReqRespPair inbound) {
        this.inbound = inbound;
    }

    public List<ReqRespPair> getOutbounds() {
        return outbounds;
    }

    public String toString() {
        if (inbound == null) {
            return "test with no client request/response.";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("********* inbound request *********\n");
        sb.append(inbound.getRequest());
        for(ReqRespPair pair: outbounds){
            sb.append("\n********* outbound request *********\n");
            sb.append(pair.getRequest());
            sb.append("\n********* outbound response *********\n");
            sb.append(pair.getResponse());
        }
        sb.append("\n\n********* inbound response *********\n");
        sb.append(inbound.getResponse());
        return sb.toString();
    }

}
