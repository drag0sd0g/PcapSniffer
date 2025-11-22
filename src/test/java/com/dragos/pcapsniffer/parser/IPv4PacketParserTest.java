package com.dragos.pcapsniffer.parser;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

import static org.mockito.Mockito.*;

class IPv4PacketParserTest {

    private IPv4PacketParser parser;

    @BeforeEach
    void setUp() {
        parser = new IPv4PacketParser();
    }

    @Test
    void shouldParseIPv4Packet() {
        IpV4Packet packet = mock(IpV4Packet.class);
        IpV4Packet.IpV4Header header = mock(IpV4Packet.IpV4Header.class);
        
        when(packet.getHeader()).thenReturn(header);
        when(packet.getRawData()).thenReturn(new byte[60]);
        when(header.getProtocol()).thenReturn(IpNumber.TCP);
        when(header.getVersion()).thenReturn(IpVersion.IPV4);
        when(header.getIhl()).thenReturn((byte) 5);
        when(header.getFragmentOffset()).thenReturn((short) 0);
        when(header.getDontFragmentFlag()).thenReturn(true);
        when(header.getMoreFragmentFlag()).thenReturn(false);
        when(header.getReservedFlag()).thenReturn(false);

        // Should not throw any exception
        parser.parse(packet);

        verify(packet, atLeastOnce()).getHeader();
        verify(packet).getRawData();
    }

    @Test
    void shouldHandleMinimalRawData() {
        IpV4Packet packet = mock(IpV4Packet.class);
        IpV4Packet.IpV4Header header = mock(IpV4Packet.IpV4Header.class);
        
        when(packet.getHeader()).thenReturn(header);
        when(packet.getRawData()).thenReturn(new byte[20]); // Minimum IPv4 header size

        // Should not throw any exception
        parser.parse(packet);
    }
}
