package com.dragos.pcapsniffer.cli;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static org.assertj.core.api.Assertions.assertThat;

class PcapSnifferCommandTest {

    @Test
    void shouldReturnErrorCodeForMissingFile() {
        PcapSnifferCommand command = new PcapSnifferCommand();
        CommandLine cmd = new CommandLine(command);
        
        int exitCode = cmd.execute("/non/existent/file.pcap");
        
        assertThat(exitCode).isEqualTo(1);
    }

    @Test
    void shouldShowHelpMessage() {
        PcapSnifferCommand command = new PcapSnifferCommand();
        CommandLine cmd = new CommandLine(command);
        
        int exitCode = cmd.execute("--help");
        
        assertThat(exitCode).isZero();
    }

    @Test
    void shouldShowVersionMessage() {
        PcapSnifferCommand command = new PcapSnifferCommand();
        CommandLine cmd = new CommandLine(command);
        
        int exitCode = cmd.execute("--version");
        
        assertThat(exitCode).isZero();
    }

    @Test
    void shouldAcceptVerboseFlag() {
        PcapSnifferCommand command = new PcapSnifferCommand();
        CommandLine cmd = new CommandLine(command);
        
        int exitCode = cmd.execute("--verbose", "/non/existent/file.pcap");
        
        assertThat(exitCode).isEqualTo(1);
    }

    @Test
    void shouldAcceptShortVerboseFlag() {
        PcapSnifferCommand command = new PcapSnifferCommand();
        CommandLine cmd = new CommandLine(command);
        
        int exitCode = cmd.execute("-v", "/non/existent/file.pcap");
        
        assertThat(exitCode).isEqualTo(1);
    }
}
