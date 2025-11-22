package com.dragos.pcapsniffer.analyzer;

import com.dragos.pcapsniffer.model.PacketStatistics;
import org.pcap4j.packet.EthernetPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * Reports statistics about analyzed packets
 */
public class StatisticsReporter {
    private static final Logger LOGGER = LoggerFactory.getLogger(StatisticsReporter.class);

    public void printStatistics(PacketStatistics stats, Map<String, List<EthernetPacket>> protocolHistogram) {
        LOGGER.info("-------------PCAP Analysis Stats-------------");
        LOGGER.info("\ttotal time: {} seconds", stats.getTotalTimeInSeconds());
        LOGGER.info("\ttotal Ethernet frames: {}", stats.getTotalEthernetFrames());
        LOGGER.info("\ttotal IPV4 packets: {}", stats.getTotalIPv4Packets());
        LOGGER.info("\ttotal TCP packets: {}", stats.getTotalTCPPackets());
        LOGGER.info("\ttotal size: {} bytes", stats.getTotalPacketSize());
        LOGGER.info("\taverage package size: {} bytes", stats.getAveragePacketSize());
        LOGGER.info("\taverage packet per second (pps): {}", stats.getPacketsPerSecond());
        LOGGER.info("\taverage bytes per second: {}", stats.getBytesPerSecond());
        LOGGER.info("\taverage bits per second: {}", stats.getBitsPerSecond());

        printProtocolHistogram(protocolHistogram);
    }

    private void printProtocolHistogram(Map<String, List<EthernetPacket>> protocolHistogram) {
        for (Map.Entry<String, List<EthernetPacket>> entry : protocolHistogram.entrySet()) {
            String protocolType = entry.getKey();
            List<EthernetPacket> packetsPerProtocol = entry.getValue();
            LOGGER.info("\tFor protocol {} we have {} packets", protocolType, packetsPerProtocol.size());
        }
    }
}
