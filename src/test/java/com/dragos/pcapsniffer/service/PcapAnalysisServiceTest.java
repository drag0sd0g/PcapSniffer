package com.dragos.pcapsniffer.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class PcapAnalysisServiceTest {

    private PcapAnalysisService service;

    @BeforeEach
    void setUp() {
        service = new PcapAnalysisService();
    }

    @Test
    void shouldReturnFalseForNullFilePath() {
        assertThat(service.analyzePcapFile(null)).isFalse();
    }

    @Test
    void shouldReturnFalseForEmptyFilePath() {
        assertThat(service.analyzePcapFile("")).isFalse();
        assertThat(service.analyzePcapFile("   ")).isFalse();
    }

    @Test
    void shouldReturnFalseForNonExistentFile() {
        assertThat(service.analyzePcapFile("/non/existent/file.pcap")).isFalse();
    }

    @Test
    void shouldReturnFalseForDirectory(@TempDir Path tempDir) {
        assertThat(service.analyzePcapFile(tempDir.toString())).isFalse();
    }

    @Test
    void shouldReturnFalseForUnreadableFile(@TempDir Path tempDir) throws IOException {
        Path unreadableFile = tempDir.resolve("unreadable.pcap");
        Files.createFile(unreadableFile);
        File file = unreadableFile.toFile();
        file.setReadable(false);
        
        assertThat(service.analyzePcapFile(unreadableFile.toString())).isFalse();
        
        // Cleanup
        file.setReadable(true);
    }

    @Test
    void shouldReturnFalseForInvalidPcapFile(@TempDir Path tempDir) throws IOException {
        Path invalidPcapFile = tempDir.resolve("invalid.pcap");
        Files.writeString(invalidPcapFile, "This is not a valid PCAP file");
        
        assertThat(service.analyzePcapFile(invalidPcapFile.toString())).isFalse();
    }

    @Test
    void shouldValidateValidFile(@TempDir Path tempDir) throws IOException {
        // Create a file (even though it's not a valid PCAP, it passes file validation)
        Path validFile = tempDir.resolve("test.pcap");
        Files.createFile(validFile);
        
        // The file exists and is readable, but will fail PCAP parsing
        assertThat(service.analyzePcapFile(validFile.toString())).isFalse();
    }
}
