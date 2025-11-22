package com.dragos.pcapsniffer.analyzer;

import com.dragos.pcapsniffer.model.PacketStatistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.*;

class StatisticsReporterTest {

    private StatisticsReporter reporter;

    @BeforeEach
    void setUp() {
        reporter = new StatisticsReporter();
    }

    @Test
    void shouldPrintStatistics() {
        PacketStatistics stats = new PacketStatistics();
        stats.incrementEthernetFrames();
        stats.incrementIPv4Packets();
        stats.incrementTCPPackets();
        stats.addPacketSize(1000);
        stats.setTotalTimeInSeconds(10);

        Map<String, List<EthernetPacket>> histogram = new HashMap<>();
        List<EthernetPacket> packets = new ArrayList<>();
        packets.add(mock(EthernetPacket.class));
        histogram.put("IPV4", packets);

        // Should not throw any exception
        reporter.printStatistics(stats, histogram);
    }

    @Test
    void shouldHandleEmptyHistogram() {
        PacketStatistics stats = new PacketStatistics();
        Map<String, List<EthernetPacket>> histogram = new HashMap<>();

        // Should not throw any exception
        reporter.printStatistics(stats, histogram);
    }

    @Test
    void shouldHandleMultipleProtocols() {
        PacketStatistics stats = new PacketStatistics();
        Map<String, List<EthernetPacket>> histogram = new HashMap<>();
        
        List<EthernetPacket> ipv4Packets = new ArrayList<>();
        ipv4Packets.add(mock(EthernetPacket.class));
        ipv4Packets.add(mock(EthernetPacket.class));
        histogram.put("IPV4", ipv4Packets);
        
        List<EthernetPacket> arpPackets = new ArrayList<>();
        arpPackets.add(mock(EthernetPacket.class));
        histogram.put("ARP", arpPackets);

        // Should not throw any exception
        reporter.printStatistics(stats, histogram);
    }
}
