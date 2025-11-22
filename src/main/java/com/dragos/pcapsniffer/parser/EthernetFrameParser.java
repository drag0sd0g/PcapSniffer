package com.dragos.pcapsniffer.parser;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses and logs Ethernet frame information
 */
public class EthernetFrameParser {
    private static final Logger LOGGER = LoggerFactory.getLogger(EthernetFrameParser.class);

    private static final int ETHERNET_DESTINATION_ADDRESS_OFFSET = 0;
    private static final int ETHERNET_SOURCE_ADDRESS_OFFSET = 6;
    private static final int ETHERNET_TYPE_OFFSET = 12;

    public void parse(EthernetPacket ethernetPacket) {
        LOGGER.info("\t-----ETHERNET LEVEL-----");
        LOGGER.info("packet length " + ethernetPacket.length());
        byte[] ethernetFrameRawData = ethernetPacket.getRawData();
        LOGGER.info("\t\tEthernet Destination Address: " + ByteArrays.getMacAddress(ethernetFrameRawData, ETHERNET_DESTINATION_ADDRESS_OFFSET));
        LOGGER.info("\t\tEthernet Source Address: " + ByteArrays.getMacAddress(ethernetFrameRawData, ETHERNET_SOURCE_ADDRESS_OFFSET));
        LOGGER.info("\t\tEthernet Type: " + ByteArrays.getShort(ethernetFrameRawData, ETHERNET_TYPE_OFFSET));
    }
}
