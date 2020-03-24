package io.otdd.tcpdump.parser.testcase;

import com.google.gson.JsonObject;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.otdd.otddserver.OtddServerServiceGrpc;
import io.otdd.otddserver.SaveTestCaseReq;
import io.otdd.otddserver.SaveTestCaseReqOrBuilder;
import io.otdd.tcpdump.parser.tcp.ConnDirection;
import io.otdd.tcpdump.parser.tcp.OneWayData;
import io.otdd.tcpdump.parser.tcp.ReqRespPair;
import io.otdd.tcpdump.parser.tcp.TcpConnection;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.misc.BASE64Encoder;

public class TestCaseMgr {

	private static final Logger LOGGER = LogManager.getLogger();

	private TestCase current;
	boolean firstTestCaseDiscarded = false;
	private String module;
	private String protocol;
	private String otddServerHost;
	private int otddServerPort;
	private ManagedChannel channel;
	private OtddServerServiceGrpc.OtddServerServiceBlockingStub stub;

	public TestCaseMgr(String module,String protocol,String otddServerHost,int otddServerPort) {
		this.module = module;
		this.protocol = protocol;
		this.otddServerHost = otddServerHost;
		this.otddServerPort = otddServerPort;
		this.current = new TestCase();
		this.channel = ManagedChannelBuilder.forAddress(this.otddServerHost, this.otddServerPort).usePlaintext(true).build();
		this.stub = OtddServerServiceGrpc.newBlockingStub(this.channel);
	}

	public void onEntityReceived(TcpConnection conn, OneWayData entity) {

		if (conn.isServerConnection()) {
			current.setInbound(new ReqRespPair(conn));
			current.getInbound().setRequest(entity);
			return;
		}

		boolean found = false;
		for (ReqRespPair talk : current.getOutbounds()) {
			if (talk.getConn() == conn) { //must be the same conn object. intentionally not to use equals() method.
				found = true;
				if (talk.getResponse() == null) {
					talk.setResponse(entity);
				}
			}
		}

		if (!found) {
			if (conn.getConnDirection().ordinal() == ConnDirection.INCOMING.ordinal()) {
				LOGGER.warn("received inbound request on none server connection, packets discarded. conn:" + conn);
				return;
			}
			if (conn.getConnDirection().ordinal() == ConnDirection.OUTGOING.ordinal()) {
				ReqRespPair talk = new ReqRespPair(conn);
				talk.setResponse(entity);
				current.getOutbounds().add(talk);
			} else {
				LOGGER.warn("resp has no req, but is not outbound conn, "
						+ "won't be considered a TYPE_SERVER_GREETING talk, packets discarded. conn:" + conn);
				return;
			}
		}
	}

	public void onEntitySent(TcpConnection conn, OneWayData entity) {
		LOGGER.debug("entity sent. size:{}, on conn:{}", entity.getBytes().length, conn.toString());

		if (conn.isServerConnection()) {
			if (current.getInbound() == null) {
				LOGGER.error("current.inbound is null when sent inbound response. "
						+ "this often occurs at the file's begining, can be ignored.");
				current.setInbound(new ReqRespPair(conn));
			}

			current.getInbound().setResponse(entity);

		} else {
			/*
			 * to deals with this scenario:
			 * server listens on 8000, but there is another irrelevant service listen on another port, such as a ftp service.
			 * when the service sends back data, these will be: serverConnection=false, incommingConnection = true.
			 */
			if (conn.getConnDirection().ordinal() == ConnDirection.INCOMING.ordinal()) {
				LOGGER.warn("sent inbound-response on none server connection, packets discarded. conn:" + conn);
				return;
			}

			ReqRespPair talk = new ReqRespPair(conn);
			talk.setRequest(entity);
			current.getOutbounds().add(talk);
		}
	}

	public void onTestCaseStart(TcpConnection tcpConnection) {
		if (current != null) {
			//discard the first test case because the tcpdump packets may be truncated at the begining.
			if(!firstTestCaseDiscarded){
				firstTestCaseDiscarded = true;
			}
			else{
				System.out.println("save test: "+ current);
				JSONObject testcase = new JSONObject();
				testcase.put("module",this.module);
				testcase.put("protocol",this.protocol);
				JSONObject inbound = new JSONObject();
				BASE64Encoder encoder = new BASE64Encoder();
				if(current.getInbound().getRequest()!=null&&current.getInbound().getRequest().getBytes().length>0) {
					inbound.put("req", encoder.encode(current.getInbound().getRequest().getBytes()).replace("\r", "").replace("\n", ""));
					inbound.put("req_time", current.getInbound().getRequest().getTimestamp());
				}
				if(current.getInbound().getResponse()!=null&&current.getInbound().getResponse().getBytes().length>0) {
					inbound.put("resp", encoder.encode(current.getInbound().getResponse().getBytes()).replace("\r", "").replace("\n", ""));
					inbound.put("resp_time", current.getInbound().getResponse().getTimestamp());
				}
				testcase.put("inbound",inbound);
				JSONArray outbounds = new JSONArray();
				for(ReqRespPair out:current.getOutbounds()){
					JSONObject outbound = new JSONObject();
					if(out.getRequest()!=null&&out.getRequest().getBytes().length>0) {
						outbound.put("req", encoder.encode(out.getRequest().getBytes()).replace("\r", "").replace("\n", ""));
						outbound.put("req_time",out.getRequest().getTimestamp());
					}
					if(out.getResponse()!=null&&out.getResponse().getBytes().length>0) {
						outbound.put("resp", encoder.encode(out.getResponse().getBytes()).replace("\r", "").replace("\n", ""));
						outbound.put("resp_time",out.getResponse().getTimestamp());
					}
					outbounds.add(outbound);
				}
				testcase.put("outbound",outbounds);
				SaveTestCaseReq req = SaveTestCaseReq.newBuilder().setTestCase(testcase.toString()).build();
				this.stub.saveTestCase(req);
			}
		}
		current = new TestCase();
		LOGGER.info(String.format("testcase start, id=%s", current.getTestId()));
	}

}
