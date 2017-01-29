package com.nomura.pcapsniffer;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by Dragos Dogaru on 08/12/2016
 */
public class Main {

    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

    //ETHERNET FRAME OFFSETS
    private static final int ETHERNET_HEADER_TYPE_OFFSET = 0;
    private static final int ETHERNET_SOURCE_ADDRESS_OFFSET = 6;
    private static final int ETHERNET_DESTINATION_ADDRESS_OFFSET = 12;

    //IPV4 HEADER OFFSETS
    private static final int IPV4_TOTAL_LENGTH_OFFSET = 2;
    private static final int IPV4_IDENTIFICATION_OFFSET = 4;
    private static final int IPV4_TTL_OFFSET = 8;
    private static final int IPV4_HEADER_CHECKSUM_OFFSET = 10;
    private static final int IPV4_SRC_ADDR_OFFSET = 12;
    private static final int IPV4_DST_ADDR_OFFSET = 16;

    //TCP HEADER OFFSETS
    private static final int TCP_SOURCE_PORT_OFFSET = 0;
    private static final int TCP_DESTINATION_PORT_OFFSET = 2;
    private static final int TCP_SEQUENCE_NUMBER_OFFSET = 4;
    private static final int TCP_ACKNOWLEDGEMENT_NUMBER_OFFSET = 8;
    private static final int TCP_DATA_OFFSET_RESERVED_FLAGS_OFFSET = 12;
    private static final int TCP_WINDOW_SIZE_OFFSET = 14;
    private static final int TCP_CHECKSUM_OFFSET = 16;
    private static final int TCP_URGENT_POINTER_OFFSET = 18;


    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            LOGGER.error("must provide .pcap file as argument");
            System.exit(1);
        }
        Map<String, List<EthernetPacket>> protocolHistogram = new HashMap<>();
        PcapHandle handle = null;
        try { //open pcap file
            handle = Pcaps.openOffline(args[0]);
        } catch (PcapNativeException pne) { //if exception occurs print error and exit
            LOGGER.error("cannot open pcap file. Exiting", pne);
            System.exit(1);
        }
        try {
            long totalTCPPackets = 0;
            long totalEthernetFrames = 0;
            long totalIPV4Packets = 0;
            long totalPacketSize = 0;
            LOGGER.info("-------------PCAP Analysis Started-------------");
            EthernetPacket ethernetPacket = (EthernetPacket) handle.getNextPacket();
            Timestamp startTimestamp = handle.getTimestamp();
            while (ethernetPacket != null) { // loop through all packets
                LOGGER.info("<FRAME BEGIN>");
                //Get Ethernet level details
                parseEthernetFrame(ethernetPacket);
                if (ethernetPacket.getPayload() instanceof IpV4Packet) {
                    // Get IPV4 payload and IPV header details
                    IpV4Packet ipV4Packet = (IpV4Packet) ethernetPacket.getPayload();
                    parseIPV4Packet(ipV4Packet);
                    totalIPV4Packets++;
                    if (ipV4Packet.getPayload() instanceof TcpPacket) {
                        //Get TCP payload and header details
                        TcpPacket tcpPacket = (TcpPacket) ipV4Packet.getPayload();
                        parseTCPPacket(tcpPacket);
                        LOGGER.info("</FRAME END>");
                        totalPacketSize += ethernetPacket.length();
                        totalTCPPackets++;
                    }
                }
                totalEthernetFrames++;
                EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
                ethernetPacket = (EthernetPacket) handle.getNextPacket(); //move on to the next ethernet frame
                //Add packet to protocol-keyed histogram
                List<EthernetPacket> packetsForProtocol = protocolHistogram.get(ethernetHeader.getType().name());
                if (packetsForProtocol == null) {
                    packetsForProtocol = new ArrayList<>();
                    packetsForProtocol.add(ethernetPacket);
                } else {
                    packetsForProtocol.add(ethernetPacket);
                }
                protocolHistogram.put(ethernetHeader.getType().name(), packetsForProtocol);
                //NOTE: since histogram is keyed by the ethernet layer's "type" parameter and we only get IPV4's for this pcap file, there will only be one element in this map
            }
            Timestamp endTimestamp = handle.getTimestamp();
            int totalTimeInSeconds = endTimestamp.getSeconds() - startTimestamp.getSeconds();
            //print stats + histogram
            calculateAndPrintStats(totalTimeInSeconds, totalEthernetFrames, totalIPV4Packets, totalTCPPackets, totalPacketSize, protocolHistogram);
        } catch (NotOpenException e) {
            LOGGER.error("an error occurred during packet processing", e);
        } finally {
            handle.close(); //close resources
            LOGGER.info("-------------PCAP Analysis Finished-------------");
        }
    }

    private static void parseEthernetFrame(EthernetPacket ethernetPacket) {
        LOGGER.info("\t-----ETHERNET LEVEL-----");
        LOGGER.info("packet length " + ethernetPacket.length());
        byte[] ethernetFrameRawData = ethernetPacket.getRawData();
        LOGGER.info("\t\tEthernet header type: " + ByteArrays.getMacAddress(ethernetFrameRawData, ETHERNET_HEADER_TYPE_OFFSET));
        LOGGER.info("\t\tEthernet header Source Address: " + ByteArrays.getMacAddress(ethernetFrameRawData, ETHERNET_SOURCE_ADDRESS_OFFSET));
        LOGGER.info("\t\tEthernet header Destination Address: " + ByteArrays.getShort(ethernetFrameRawData, ETHERNET_DESTINATION_ADDRESS_OFFSET));
    }

    private static void parseIPV4Packet(IpV4Packet ipV4Packet) {
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

    private static void parseTCPPacket(TcpPacket tcpPacket) {
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

    private static void calculateAndPrintStats(int totalTimeInSeconds, long totalEthernetFrames, long totalIPV4Packets,
                                               long totalTCPPackets, long totalPacketSize, Map<String, List<EthernetPacket>> protocolHistogram) {
        LOGGER.info("-------------PCAP Analysis Stats-------------");
        LOGGER.info("\ttotal time: " + totalTimeInSeconds + " seconds");
        LOGGER.info("\ttotal Ethernet frames: " + totalEthernetFrames);
        LOGGER.info("\ttotal IPV4 packets: " + totalIPV4Packets);
        LOGGER.info("\ttotal TCP packets: " + totalTCPPackets);
        LOGGER.info("\ttotal size: " + totalPacketSize + " bytes");
        LOGGER.info("\taverage package size: " + ((double) totalPacketSize / totalTCPPackets) + " bytes");
        LOGGER.info("\taverage packet per second (pps): " + ((double) totalTCPPackets / totalTimeInSeconds));
        double averageBytesPerSecond = (double) totalPacketSize / totalTimeInSeconds;
        LOGGER.info("\taverage bytes per second: " + averageBytesPerSecond);
        LOGGER.info("\taverage bits per second: " + (averageBytesPerSecond * 8));
        for (Map.Entry<String, List<EthernetPacket>> histogramEntry : protocolHistogram.entrySet()) {
            String protocolType = histogramEntry.getKey();
            List<EthernetPacket> packetsPerProtocol = histogramEntry.getValue();
            LOGGER.info("\tFor protocol " + protocolType + " we have " + packetsPerProtocol.size() + " packets");
        }

    }
}
