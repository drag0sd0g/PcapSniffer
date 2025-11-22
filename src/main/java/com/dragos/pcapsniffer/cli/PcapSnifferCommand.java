package com.dragos.pcapsniffer.cli;

import com.dragos.pcapsniffer.service.PcapAnalysisService;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.concurrent.Callable;

/**
 * Command-line interface for PcapSniffer
 */
@Command(
    name = "pcapsniffer",
    mixinStandardHelpOptions = true,
    version = "PcapSniffer 2.0.0",
    description = "Analyzes PCAP files and extracts network packet information",
    headerHeading = "%n",
    synopsisHeading = "%nUsage:%n",
    descriptionHeading = "%nDescription:%n%n",
    parameterListHeading = "%nParameters:%n",
    optionListHeading = "%nOptions:%n",
    footer = "%nDeveloped by Dragos Dogaru"
)
public class PcapSnifferCommand implements Callable<Integer> {

    @Parameters(
        index = "0",
        description = "Path to the PCAP file to analyze",
        paramLabel = "<pcap-file>"
    )
    private String pcapFilePath;

    @Option(
        names = {"-v", "--verbose"},
        description = "Enable verbose output"
    )
    private boolean verbose;

    @Override
    public Integer call() {
        PcapAnalysisService service = new PcapAnalysisService();
        boolean success = service.analyzePcapFile(pcapFilePath);
        return success ? 0 : 1;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new PcapSnifferCommand()).execute(args);
        System.exit(exitCode);
    }
}
