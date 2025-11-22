package com.dragos.pcapsniffer.parser;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses and logs IPv4 packet information
 */
public class IPv4PacketParser {
    private static final Logger LOGGER = LoggerFactory.getLogger(IPv4PacketParser.class);

    private static final int IPV4_TOTAL_LENGTH_OFFSET = 2;
    private static final int IPV4_IDENTIFICATION_OFFSET = 4;
    private static final int IPV4_TTL_OFFSET = 8;
    private static final int IPV4_HEADER_CHECKSUM_OFFSET = 10;
    private static final int IPV4_SRC_ADDR_OFFSET = 12;
    private static final int IPV4_DST_ADDR_OFFSET = 16;

    public void parse(IpV4Packet ipV4Packet) {
        LOGGER.info("\t-----IPV4 LEVEL-----");
        IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
        byte[] ipv4RawData = ipV4Packet.getRawData();
        LOGGER.info("\t\tIPv4 Header Source Address " + ByteArrays.getInet4Address(ipv4RawData, IPV4_SRC_ADDR_OFFSET));
        LOGGER.info("\t\tIPv4 Header Destination Address " + ByteArrays.getInet4Address(ipv4RawData, IPV4_DST_ADDR_OFFSET));
        LOGGER.info("\t\tHeader checksum " + ByteArrays.getShort(ipv4RawData, IPV4_HEADER_CHECKSUM_OFFSET));
        LOGGER.info("\t\tIdentification " + ByteArrays.getShort(ipv4RawData, IPV4_IDENTIFICATION_OFFSET));
        LOGGER.info("\t\tTTL " + ByteArrays.getByte(ipv4RawData, IPV4_TTL_OFFSET));
        LOGGER.info("\t\tTotal Length " + ByteArrays.getShort(ipv4RawData, IPV4_TOTAL_LENGTH_OFFSET));
        LOGGER.info("\t\tProtocol " + ipV4Header.getProtocol());
        LOGGER.info("\t\tVersion " + ipV4Header.getVersion());
        LOGGER.info("\t\tTOS " + ipV4Header.getTos());
        LOGGER.info("\t\tIHL " + ipV4Header.getIhl());
        LOGGER.info("\t\tFragment Offset: " + ipV4Header.getFragmentOffset());
        LOGGER.info("\t\tDon't Fragment Flag: " + ipV4Header.getDontFragmentFlag());
        LOGGER.info("\t\tMore Fragment Flag: " + ipV4Header.getMoreFragmentFlag());
        LOGGER.info("\t\tReserved Flag " + ipV4Header.getReservedFlag());
    }
}
