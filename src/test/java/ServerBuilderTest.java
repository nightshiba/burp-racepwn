import burp.model.Server;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;

import java.net.MalformedURLException;

import static org.junit.jupiter.api.Assertions.assertThrows;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ServerBuilderTest {
    private Server.ServerBuilder serverBuilder;

    @BeforeAll
    private void prepareIt() {
        serverBuilder = new Server.ServerBuilder();
    }

    @Test
    public void testBuildFromDefaultSettings() throws MalformedURLException {
        serverBuilder.build();
    }

    @Test
    public void testPortNegative() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setPort(-1));
    }

    @Test
    public void testPortOutOfRange() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setPort(4522132));
    }

    @Test
    public void testPortNull() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setPort(null));
    }

    @Test
    public void testIpInvalidFormat() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setHost("2555..0.1.1"));
    }

    @Test
    public void testHostInvalidFormat() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setHost("google."));
    }

    @Test
    public void testHostInvalidCharacters() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setHost("google'.com"));
    }

    @Test
    public void testProtocolExtraSlashes() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setProtocol("http://"));
    }

    @Test
    public void testProtocolInvalidFormat() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setProtocol("'http"));
    }

    @Test
    public void testProtocolUnusual() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setProtocol("ftp"));
    }

    @Test
    public void testPathNull() {
        assertThrows(IllegalArgumentException.class, () -> serverBuilder.setPath(null));
    }

    @Test
    public void testValidSetters() throws MalformedURLException {
        serverBuilder.setProtocol("https");
        serverBuilder.setName("name");
        serverBuilder.setHost("host.com");
        serverBuilder.setPath("/directory/file?param=123");
        serverBuilder.setPort(1234);
        serverBuilder.build();
    }
}