package com.dragos.pcapsniffer.parser;

import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses and logs TCP packet information
 */
public class TcpPacketParser {
    private static final Logger LOGGER = LoggerFactory.getLogger(TcpPacketParser.class);

    private static final int TCP_SOURCE_PORT_OFFSET = 0;
    private static final int TCP_DESTINATION_PORT_OFFSET = 2;
    private static final int TCP_SEQUENCE_NUMBER_OFFSET = 4;
    private static final int TCP_ACKNOWLEDGEMENT_NUMBER_OFFSET = 8;
    private static final int TCP_DATA_OFFSET_RESERVED_FLAGS_OFFSET = 12;
    private static final int TCP_WINDOW_SIZE_OFFSET = 14;
    private static final int TCP_CHECKSUM_OFFSET = 16;
    private static final int TCP_URGENT_POINTER_OFFSET = 18;

    public void parse(TcpPacket tcpPacket) {
        LOGGER.info("\t-----TCP LEVEL-----");
        byte[] rawData = tcpPacket.getRawData();
        LOGGER.info("\t\tSource Port: " + Short.valueOf(ByteArrays.getShort(rawData, TCP_SOURCE_PORT_OFFSET)));
        LOGGER.info("\t\tDestination Port: " + Short.valueOf(ByteArrays.getShort(rawData, TCP_DESTINATION_PORT_OFFSET)));
        LOGGER.info("\t\tSequence Number: " + ByteArrays.getInt(rawData, TCP_SEQUENCE_NUMBER_OFFSET));
        LOGGER.info("\t\tAcknowledgment Number: " + ByteArrays.getInt(rawData, TCP_ACKNOWLEDGEMENT_NUMBER_OFFSET));
        short dataOffsetAndReservedAndFlags = ByteArrays.getShort(rawData, TCP_DATA_OFFSET_RESERVED_FLAGS_OFFSET);
        LOGGER.info("\t\tData Offset: " + (byte) ((dataOffsetAndReservedAndFlags & '\uf000') >> 12));
        LOGGER.info("\t\tReserved: " + (byte) ((dataOffsetAndReservedAndFlags & 4032) >> 6));
        LOGGER.info("\t\tURG: " + ((dataOffsetAndReservedAndFlags & 32) != 0));
        LOGGER.info("\t\tACK: " + ((dataOffsetAndReservedAndFlags & 16) != 0));
        LOGGER.info("\t\tPSH: " + ((dataOffsetAndReservedAndFlags & 8) != 0));
        LOGGER.info("\t\tRST: " + ((dataOffsetAndReservedAndFlags & 4) != 0));
        LOGGER.info("\t\tSYN: " + ((dataOffsetAndReservedAndFlags & 2) != 0));
        LOGGER.info("\t\tFIN: " + ((dataOffsetAndReservedAndFlags & 1) != 0));
        LOGGER.info("\t\tWindow size: " + ByteArrays.getShort(rawData, TCP_WINDOW_SIZE_OFFSET));
        LOGGER.info("\t\tChecksum: " + ByteArrays.getShort(rawData, TCP_CHECKSUM_OFFSET));
        LOGGER.info("\t\tUrgent Pointer: " + ByteArrays.getShort(rawData, TCP_URGENT_POINTER_OFFSET));
    }
}
