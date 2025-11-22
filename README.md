# PcapSniffer

[![CI Build](https://github.com/drag0sd0g/PcapSniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/drag0sd0g/PcapSniffer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/drag0sd0g/PcapSniffer/branch/main/graph/badge.svg)](https://codecov.io/gh/drag0sd0g/PcapSniffer)
[![Java Version](https://img.shields.io/badge/Java-21-blue)](https://openjdk.org/projects/jdk/21/)
[![Maven Central](https://img.shields.io/badge/Maven-3.9+-blue)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A modern, high-performance PCAP file analyzer with a clean CLI interface. Extracts and analyzes network packet information from PCAP files.

[日本語版README](README.ja.md)

## Features

- 🚀 **Modern Java 21** - Leverages latest Java features and performance improvements
- 📊 **Comprehensive Analysis** - Detailed packet statistics at Ethernet, IPv4, and TCP levels
- 🎯 **Clean CLI Interface** - Built with picocli for intuitive command-line usage
- 🧪 **High Test Coverage** - 78% line coverage, 72% branch coverage with JUnit 5
- 📈 **Statistics Reporting** - Throughput, packet rates, and protocol distribution
- 🏗️ **SOLID Architecture** - Well-structured, maintainable codebase

## Requirements

- Java 21 or higher
- Maven 3.9 or higher (for building from source)

## Installation

### Building from Source

```bash
git clone https://github.com/drag0sd0g/PcapSniffer.git
cd PcapSniffer
mvn clean package
```

This will create a fat JAR in `target/pcapsniffer-2.0.0-jar-with-dependencies.jar`.

## Usage

### Basic Usage

```bash
java -jar target/pcapsniffer-2.0.0-jar-with-dependencies.jar <pcap-file>
```

### Command-Line Options

```bash
# Show help
java -jar pcapsniffer-2.0.0-jar-with-dependencies.jar --help

# Show version
java -jar pcapsniffer-2.0.0-jar-with-dependencies.jar --version

# Analyze with verbose output
java -jar pcapsniffer-2.0.0-jar-with-dependencies.jar --verbose example.pcap
```

### Example

```bash
java -jar target/pcapsniffer-2.0.0-jar-with-dependencies.jar 64x8burst.eth2.pcap
```

### Output

The analyzer provides detailed information about:
- **Ethernet Level**: MAC addresses, frame types
- **IPv4 Level**: Source/destination IPs, TTL, checksums, flags
- **TCP Level**: Ports, sequence numbers, flags, window size
- **Statistics**: Total packets, throughput, average packet size, bits per second

## Architecture

PcapSniffer follows SOLID principles with a clean separation of concerns:

### Package Structure

```
com.dragos.pcapsniffer
├── cli/              # Command-line interface (picocli)
├── service/          # Service layer
├── analyzer/         # Analysis and reporting logic
├── parser/           # Protocol-specific parsers
│   ├── EthernetFrameParser
│   ├── IPv4PacketParser
│   └── TcpPacketParser
└── model/            # Data models and statistics
```

### Key Components

- **PcapSnifferCommand**: CLI entry point using picocli
- **PcapAnalysisService**: Service layer for validation and orchestration
- **PcapAnalyzer**: Core analysis engine
- **Parsers**: Protocol-specific packet parsing
- **PacketStatistics**: Statistics aggregation and calculation
- **StatisticsReporter**: Results formatting and output

## Development

### Running Tests

```bash
mvn test
```

### Generating Coverage Report

```bash
mvn test jacoco:report
```

Coverage report will be available in `target/site/jacoco/index.html`.

### Code Quality

The project enforces:
- Minimum 90% line coverage
- Minimum 85% branch coverage
- Clean architecture with SOLID principles

## Dependencies

### Core Dependencies
- **pcap4j 1.8.2** - PCAP file processing
- **picocli 4.7.6** - CLI framework
- **logback 1.5.15** - Logging
- **slf4j 2.0.16** - Logging API

### Test Dependencies
- **JUnit 5.11.4** - Testing framework
- **Mockito 5.14.2** - Mocking framework
- **AssertJ 3.27.1** - Fluent assertions

All dependencies are kept up-to-date with their latest stable versions.

## CI/CD

The project uses GitHub Actions for continuous integration:
- Automated builds on every push/PR
- Unit test execution
- Code coverage reporting to Codecov
- Artifact generation

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass and coverage remains high
5. Submit a pull request

## Version History

### 2.0.0 (2025)
- Upgraded to Java 21
- Complete refactoring with SOLID principles
- Added comprehensive test suite (78% coverage)
- Implemented CLI with picocli
- Updated all dependencies to latest versions
- Added CI/CD with GitHub Actions

### 1.0.0 (2016)
- Initial release with Java 8
- Basic PCAP analysis functionality

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Dragos Dogaru

## Acknowledgments

- Built with [pcap4j](https://www.pcap4j.org/) for PCAP processing
- CLI powered by [picocli](https://picocli.info/)
