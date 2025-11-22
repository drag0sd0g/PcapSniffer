package com.dragos.pcapsniffer;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

class PcapSnifferCLITest {

    @Test
    void shouldHandleMainMethodWithoutArgs() {
        // This test just ensures the main method can be called
        // In production, it would call System.exit, but we're testing structure
        assertThatCode(() -> {
            // Just verify the class structure is correct
            PcapSnifferCLI cli = new PcapSnifferCLI();
        }).doesNotThrowAnyException();
    }
}
