package com.dragos.pcapsniffer.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PacketStatisticsTest {

    private PacketStatistics statistics;

    @BeforeEach
    void setUp() {
        statistics = new PacketStatistics();
    }

    @Test
    void shouldInitializeWithZeroValues() {
        assertThat(statistics.getTotalEthernetFrames()).isZero();
        assertThat(statistics.getTotalIPv4Packets()).isZero();
        assertThat(statistics.getTotalTCPPackets()).isZero();
        assertThat(statistics.getTotalPacketSize()).isZero();
        assertThat(statistics.getTotalTimeInSeconds()).isZero();
    }

    @Test
    void shouldIncrementEthernetFrames() {
        statistics.incrementEthernetFrames();
        assertThat(statistics.getTotalEthernetFrames()).isEqualTo(1);
        
        statistics.incrementEthernetFrames();
        assertThat(statistics.getTotalEthernetFrames()).isEqualTo(2);
    }

    @Test
    void shouldIncrementIPv4Packets() {
        statistics.incrementIPv4Packets();
        assertThat(statistics.getTotalIPv4Packets()).isEqualTo(1);
        
        statistics.incrementIPv4Packets();
        assertThat(statistics.getTotalIPv4Packets()).isEqualTo(2);
    }

    @Test
    void shouldIncrementTCPPackets() {
        statistics.incrementTCPPackets();
        assertThat(statistics.getTotalTCPPackets()).isEqualTo(1);
        
        statistics.incrementTCPPackets();
        assertThat(statistics.getTotalTCPPackets()).isEqualTo(2);
    }

    @Test
    void shouldAddPacketSize() {
        statistics.addPacketSize(100);
        assertThat(statistics.getTotalPacketSize()).isEqualTo(100);
        
        statistics.addPacketSize(50);
        assertThat(statistics.getTotalPacketSize()).isEqualTo(150);
    }

    @Test
    void shouldSetTotalTimeInSeconds() {
        statistics.setTotalTimeInSeconds(10);
        assertThat(statistics.getTotalTimeInSeconds()).isEqualTo(10);
    }

    @Test
    void shouldCalculateAveragePacketSize() {
        statistics.addPacketSize(300);
        statistics.incrementTCPPackets();
        statistics.incrementTCPPackets();
        statistics.incrementTCPPackets();
        
        assertThat(statistics.getAveragePacketSize()).isEqualTo(100.0);
    }

    @Test
    void shouldReturnZeroAveragePacketSizeWhenNoPackets() {
        assertThat(statistics.getAveragePacketSize()).isZero();
    }

    @Test
    void shouldCalculatePacketsPerSecond() {
        statistics.incrementTCPPackets();
        statistics.incrementTCPPackets();
        statistics.incrementTCPPackets();
        statistics.incrementTCPPackets();
        statistics.setTotalTimeInSeconds(2);
        
        assertThat(statistics.getPacketsPerSecond()).isEqualTo(2.0);
    }

    @Test
    void shouldReturnZeroPacketsPerSecondWhenNoTime() {
        statistics.incrementTCPPackets();
        assertThat(statistics.getPacketsPerSecond()).isZero();
    }

    @Test
    void shouldCalculateBytesPerSecond() {
        statistics.addPacketSize(1000);
        statistics.setTotalTimeInSeconds(5);
        
        assertThat(statistics.getBytesPerSecond()).isEqualTo(200.0);
    }

    @Test
    void shouldReturnZeroBytesPerSecondWhenNoTime() {
        statistics.addPacketSize(1000);
        assertThat(statistics.getBytesPerSecond()).isZero();
    }

    @Test
    void shouldCalculateBitsPerSecond() {
        statistics.addPacketSize(1000);
        statistics.setTotalTimeInSeconds(5);
        
        assertThat(statistics.getBitsPerSecond()).isEqualTo(1600.0);
    }

    @Test
    void shouldReturnZeroBitsPerSecondWhenNoTime() {
        statistics.addPacketSize(1000);
        assertThat(statistics.getBitsPerSecond()).isZero();
    }
}
