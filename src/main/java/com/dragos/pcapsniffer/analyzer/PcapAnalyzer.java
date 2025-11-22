package com.dragos.pcapsniffer.analyzer;

import com.dragos.pcapsniffer.model.PacketStatistics;
import com.dragos.pcapsniffer.parser.EthernetFrameParser;
import com.dragos.pcapsniffer.parser.IPv4PacketParser;
import com.dragos.pcapsniffer.parser.TcpPacketParser;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Analyzes PCAP files and extracts packet information
 */
public class PcapAnalyzer {
    private static final Logger LOGGER = LoggerFactory.getLogger(PcapAnalyzer.class);

    private final EthernetFrameParser ethernetFrameParser;
    private final IPv4PacketParser ipV4PacketParser;
    private final TcpPacketParser tcpPacketParser;
    private final StatisticsReporter statisticsReporter;

    public PcapAnalyzer() {
        this.ethernetFrameParser = new EthernetFrameParser();
        this.ipV4PacketParser = new IPv4PacketParser();
        this.tcpPacketParser = new TcpPacketParser();
        this.statisticsReporter = new StatisticsReporter();
    }

    public void analyze(String pcapFilePath) throws PcapNativeException {
        Map<String, List<EthernetPacket>> protocolHistogram = new HashMap<>();
        PacketStatistics statistics = new PacketStatistics();

        try (PcapHandle handle = Pcaps.openOffline(pcapFilePath)) {
            LOGGER.info("-------------PCAP Analysis Started-------------");
            analyzePackets(handle, statistics, protocolHistogram);
            LOGGER.info("-------------PCAP Analysis Finished-------------");
        } catch (NotOpenException e) {
            LOGGER.error("An error occurred during packet processing", e);
            throw new PcapNativeException("Failed to process packets", e);
        }

        statisticsReporter.printStatistics(statistics, protocolHistogram);
    }

    private void analyzePackets(PcapHandle handle, PacketStatistics statistics,
                                Map<String, List<EthernetPacket>> protocolHistogram) throws NotOpenException {
        EthernetPacket ethernetPacket = (EthernetPacket) handle.getNextPacket();
        Timestamp startTimestamp = handle.getTimestamp();

        while (ethernetPacket != null) {
            LOGGER.info("<FRAME BEGIN>");
            processEthernetFrame(ethernetPacket, statistics, protocolHistogram);
            ethernetPacket = (EthernetPacket) handle.getNextPacket();
        }

        Timestamp endTimestamp = handle.getTimestamp();
        int totalTimeInSeconds = endTimestamp.getSeconds() - startTimestamp.getSeconds();
        statistics.setTotalTimeInSeconds(totalTimeInSeconds);
    }

    private void processEthernetFrame(EthernetPacket ethernetPacket, PacketStatistics statistics,
                                     Map<String, List<EthernetPacket>> protocolHistogram) {
        ethernetFrameParser.parse(ethernetPacket);
        statistics.incrementEthernetFrames();

        if (ethernetPacket.getPayload() instanceof IpV4Packet ipV4Packet) {
            ipV4PacketParser.parse(ipV4Packet);
            statistics.incrementIPv4Packets();

            if (ipV4Packet.getPayload() instanceof TcpPacket tcpPacket) {
                tcpPacketParser.parse(tcpPacket);
                LOGGER.info("</FRAME END>");
                statistics.addPacketSize(ethernetPacket.length());
                statistics.incrementTCPPackets();
            }
        }

        addToProtocolHistogram(ethernetPacket, protocolHistogram);
    }

    private void addToProtocolHistogram(EthernetPacket ethernetPacket,
                                       Map<String, List<EthernetPacket>> protocolHistogram) {
        EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
        String protocolType = ethernetHeader.getType().name();
        
        protocolHistogram.computeIfAbsent(protocolType, k -> new ArrayList<>()).add(ethernetPacket);
    }
}
