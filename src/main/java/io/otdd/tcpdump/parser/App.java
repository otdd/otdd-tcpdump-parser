package io.otdd.tcpdump.parser;

import io.otdd.tcpdump.parser.testcase.TestCaseParser;
import org.apache.commons.cli.*;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

public class App {
    public static void main(String args[]){

        Options options = new Options();

        Option moduleName = new Option(null, "moduleName", true, "the module name");
        moduleName.setRequired(true);
        options.addOption(moduleName);

        Option protocol = new Option(null, "protocol", true, "the module's protocol");
        protocol.setRequired(true);
        options.addOption(protocol);

        Option tcpdumpFile = new Option(null, "tcpdumpFile", true, "the tcpdump file path");
        tcpdumpFile.setRequired(true);
        options.addOption(tcpdumpFile);

        Option listenPort = new Option(null, "listenPort", true, "the module's listen port");
        listenPort.setRequired(true);
        options.addOption(listenPort);

        Option ignoreLocalPorts = new Option(null, "ignoreLocalPorts", true, "data to these local ports will be discarded");
        ignoreLocalPorts.setRequired(false);
        options.addOption(ignoreLocalPorts);

        Option ignoreRemoteIpPorts = new Option(null, "ignoreRemoteIpPorts", true, "data to these remote ip:ports will be discarded");
        ignoreRemoteIpPorts.setRequired(false);
        options.addOption(ignoreRemoteIpPorts);

        Option otddHost = new Option(null, "otddHost", true, "the otdd server's grpc host");
        otddHost.setRequired(true);
        options.addOption(otddHost);

        Option otddPort = new Option(null, "otddPort", true, "the otdd server's grpc port");
        otddPort.setRequired(true);
        options.addOption(otddPort);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);

            String moduleNameValue = cmd.getOptionValue("moduleName");
            String protocolValue = cmd.getOptionValue("protocol");
            String tcpdumpFileValue = cmd.getOptionValue("tcpdumpFile");
            String listenPortValue = cmd.getOptionValue("listenPort");
            String ignoreLocalPortsValue = cmd.getOptionValue("ignoreLocalPorts");
            String ignoreRemoteIpPortsValue = cmd.getOptionValue("ignoreRemoteIpPorts");
            String otddHostValue = cmd.getOptionValue("otddHost");
            String otddPortValue = cmd.getOptionValue("otddPort");

            System.out.println("moduleNameValue:"+moduleNameValue);
            System.out.println("protocolValue:"+protocolValue);
            System.out.println("tcpdumpFileValue:"+tcpdumpFileValue);
            System.out.println("listenPortValue:"+listenPortValue);
            System.out.println("ignoreLocalPortsValue:"+ignoreLocalPortsValue);
            System.out.println("ignoreRemoteIpPortsValue:"+ignoreRemoteIpPortsValue);
            System.out.println("otddHostValue:"+otddHostValue);
            System.out.println("otddPortValue:"+otddPortValue);

            Set<String> ignoreLocalPortsSet = new HashSet<>();
            Set<String> ignoreRemoteIpPortsSet = new HashSet<>();
            if(ignoreLocalPortsValue!=null){
                String tmp[] = ignoreLocalPortsValue.split(",");
                for(String s:tmp){
                    ignoreLocalPortsSet.add(s.trim());
                }
            }
            if(ignoreRemoteIpPortsValue!=null){
                String tmp[] = ignoreRemoteIpPortsValue.split(",");
                for(String s:tmp){
                    ignoreRemoteIpPortsSet.add(s.trim());
                }
            }
            TestCaseParser testCaseParser = new TestCaseParser(moduleNameValue,protocolValue,
                    Integer.parseInt(listenPortValue),ignoreLocalPortsSet,ignoreRemoteIpPortsSet,
                    otddHostValue,Integer.parseInt(otddPortValue));
            File file = new File(tcpdumpFileValue);
            testCaseParser.parseFile(file);
            System.out.println("ended to parse tcpdump file:"+tcpdumpFileValue);

        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("java -jar otdd-tcpdump-parser.jar", options);
            System.exit(1);
        }

    }
}
