package io.otdd.tcpdump.parser.testcase;

import java.util.UUID;

public class TestIdGenerator {
	public static String generateId(){
		String tmp = UUID.randomUUID().toString();
		String tmpSec = ""+System.currentTimeMillis();
		String sessionId = tmp.substring(0,tmp.length()>8?8:tmp.length()) + "-" + tmpSec.subSequence(tmpSec.length()-5, tmpSec.length());
		return sessionId;
	}
}
