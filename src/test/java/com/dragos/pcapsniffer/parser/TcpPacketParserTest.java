package com.dragos.pcapsniffer.parser;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.TcpPacket;

import static org.mockito.Mockito.*;

class TcpPacketParserTest {

    private TcpPacketParser parser;

    @BeforeEach
    void setUp() {
        parser = new TcpPacketParser();
    }

    @Test
    void shouldParseTcpPacket() {
        TcpPacket packet = mock(TcpPacket.class);
        when(packet.getRawData()).thenReturn(new byte[60]);

        // Should not throw any exception
        parser.parse(packet);

        verify(packet).getRawData();
    }

    @Test
    void shouldHandleMinimalRawData() {
        TcpPacket packet = mock(TcpPacket.class);
        when(packet.getRawData()).thenReturn(new byte[20]); // Minimum TCP header size

        // Should not throw any exception
        parser.parse(packet);
    }

    @Test
    void shouldHandleTcpFlags() {
        TcpPacket packet = mock(TcpPacket.class);
        // Create raw data with TCP flags set
        byte[] rawData = new byte[60];
        // Set some TCP flags in the data offset and flags field
        rawData[12] = (byte) 0x50; // Data offset
        rawData[13] = (byte) 0x18; // ACK and PSH flags
        
        when(packet.getRawData()).thenReturn(rawData);

        // Should not throw any exception
        parser.parse(packet);

        verify(packet).getRawData();
    }
}
