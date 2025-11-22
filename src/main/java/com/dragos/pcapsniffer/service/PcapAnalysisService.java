package com.dragos.pcapsniffer.service;

import com.dragos.pcapsniffer.analyzer.PcapAnalyzer;
import org.pcap4j.core.PcapNativeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * Service layer for PCAP analysis operations
 */
public class PcapAnalysisService {
    private static final Logger LOGGER = LoggerFactory.getLogger(PcapAnalysisService.class);
    private final PcapAnalyzer analyzer;

    public PcapAnalysisService() {
        this.analyzer = new PcapAnalyzer();
    }

    /**
     * Analyzes a PCAP file
     * 
     * @param pcapFilePath Path to the PCAP file
     * @return true if analysis was successful, false otherwise
     */
    public boolean analyzePcapFile(String pcapFilePath) {
        if (!validatePcapFile(pcapFilePath)) {
            return false;
        }

        try {
            analyzer.analyze(pcapFilePath);
            return true;
        } catch (PcapNativeException e) {
            LOGGER.error("Cannot open or process pcap file: {}", pcapFilePath, e);
            return false;
        }
    }

    private boolean validatePcapFile(String pcapFilePath) {
        if (pcapFilePath == null || pcapFilePath.trim().isEmpty()) {
            LOGGER.error("PCAP file path must not be null or empty");
            return false;
        }

        File file = new File(pcapFilePath);
        if (!file.exists()) {
            LOGGER.error("PCAP file does not exist: {}", pcapFilePath);
            return false;
        }

        if (!file.isFile()) {
            LOGGER.error("Path is not a file: {}", pcapFilePath);
            return false;
        }

        if (!file.canRead()) {
            LOGGER.error("Cannot read PCAP file: {}", pcapFilePath);
            return false;
        }

        return true;
    }
}
