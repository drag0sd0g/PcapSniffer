package com.dragos.pcapsniffer.model;

/**
 * Holds statistics about analyzed packets
 */
public class PacketStatistics {
    private long totalEthernetFrames;
    private long totalIPv4Packets;
    private long totalTCPPackets;
    private long totalPacketSize;
    private int totalTimeInSeconds;

    public PacketStatistics() {
        this.totalEthernetFrames = 0;
        this.totalIPv4Packets = 0;
        this.totalTCPPackets = 0;
        this.totalPacketSize = 0;
        this.totalTimeInSeconds = 0;
    }

    public void incrementEthernetFrames() {
        this.totalEthernetFrames++;
    }

    public void incrementIPv4Packets() {
        this.totalIPv4Packets++;
    }

    public void incrementTCPPackets() {
        this.totalTCPPackets++;
    }

    public void addPacketSize(long size) {
        this.totalPacketSize += size;
    }

    public void setTotalTimeInSeconds(int seconds) {
        this.totalTimeInSeconds = seconds;
    }

    public long getTotalEthernetFrames() {
        return totalEthernetFrames;
    }

    public long getTotalIPv4Packets() {
        return totalIPv4Packets;
    }

    public long getTotalTCPPackets() {
        return totalTCPPackets;
    }

    public long getTotalPacketSize() {
        return totalPacketSize;
    }

    public int getTotalTimeInSeconds() {
        return totalTimeInSeconds;
    }

    public double getAveragePacketSize() {
        return totalTCPPackets > 0 ? (double) totalPacketSize / totalTCPPackets : 0.0;
    }

    public double getPacketsPerSecond() {
        return totalTimeInSeconds > 0 ? (double) totalTCPPackets / totalTimeInSeconds : 0.0;
    }

    public double getBytesPerSecond() {
        return totalTimeInSeconds > 0 ? (double) totalPacketSize / totalTimeInSeconds : 0.0;
    }

    public double getBitsPerSecond() {
        return getBytesPerSecond() * 8;
    }
}
