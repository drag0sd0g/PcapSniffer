package com.dragos.pcapsniffer.parser;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.EtherType;

import static org.mockito.Mockito.*;

class EthernetFrameParserTest {

    private EthernetFrameParser parser;

    @BeforeEach
    void setUp() {
        parser = new EthernetFrameParser();
    }

    @Test
    void shouldParseEthernetFrame() {
        // Create a minimal mock Ethernet packet
        EthernetPacket packet = mock(EthernetPacket.class);
        when(packet.length()).thenReturn(100);
        when(packet.getRawData()).thenReturn(new byte[60]);

        // Should not throw any exception
        parser.parse(packet);

        verify(packet).length();
        verify(packet).getRawData();
    }

    @Test
    void shouldHandleMinimalRawData() {
        EthernetPacket packet = mock(EthernetPacket.class);
        when(packet.length()).thenReturn(14);
        when(packet.getRawData()).thenReturn(new byte[20]); // Minimum Ethernet frame size

        // Should not throw any exception
        parser.parse(packet);
    }
}
