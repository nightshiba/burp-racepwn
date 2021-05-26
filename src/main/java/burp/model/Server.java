package burp.model;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.locks.ReentrantLock;

public class Server {
    private final URL url;
    private final ReentrantLock lock;
    private byte[] response;
    private String name;
    private Integer id;

    private Server(String name, URL url) {
        this.name = name;
        this.url = url;
        response = new byte[0];
        lock = new ReentrantLock();
    }

    /**
     * Gets the server's nickname.
     *
     * @return A string representing the server's user-specified nickname.
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the server's nickname.
     *
     * @param name A string representing the server's user-specified nickname.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets the server's unique identifier.
     *
     * @return An Integer representing the server's unique identifier.
     */
    public Integer getId() {
        return id;
    }

    /**
     * Sets the server's unique identifier.
     *
     * @param id An Integer representing the server's unique identifier.
     */
    public void setId(Integer id) {
        if (this.id == null) {
            this.id = id;
        }
    }

    /**
     * Gets the server's URL.
     *
     * @return An <code>URL</code> object representing the server's URL.
     */
    public URL getURL() {
        return url;
    }

    /**
     * Gets the server's mutex.
     *
     * @return A <code>ReentrantLock</code> representing the server's availability.
     */
    public ReentrantLock getLock() {
        return lock;
    }

    /**
     * Gets the server's response.
     *
     * @return A raw byte array representing the last response received.
     */
    public byte[] getResponse() {
        return response;
    }

    /**
     * Sets the server's response.
     *
     * @param response A raw byte array representing the last response received.
     */
    public void setResponse(byte[] response) {
        this.response = response;
    }

    @Override
    public String toString() {
        return name;
    }

    public static class ServerBuilder {
        private static final String IP_ADDRESS_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$";
        private static final String HOSTNAME_REGEX = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$";
        private static final Integer MIN_PORT = 1;
        private static final Integer MAX_PORT = 65535;
        private static final String PROTOCOL_REGEX = "https?|tcp";
        private static final URL DEFAULT_URL = RacePwnSettings.rPwnDefaultURL;

        private String name = RacePwnSettings.RACE_PWN_NAME;
        private String protocol = DEFAULT_URL.getProtocol();
        private String host = DEFAULT_URL.getHost();
        private Integer port = DEFAULT_URL.getPort();
        private String path = DEFAULT_URL.getPath();


        /**
         * This method is used to build Server object using parameters that were passed before.
         *
         * @return <code>Server</code> instance based on current configuration state.
         */
        public Server build() throws MalformedURLException {
            return new Server(name, new URL(protocol, host, port, path));
        }

        /**
         * Gets the server's nickname.
         *
         * @return A string representing the server's user-specified nickname.
         */
        public String getName() {
            return name;
        }


        /**
         * Sets the server's nickname.
         *
         * @param name A string representing the server's user-specified nickname.
         * @throws IllegalArgumentException Indicates that name is null.
         */
        public void setName(String name) throws IllegalArgumentException {
            if (name == null) {
                throw new IllegalArgumentException("Invalid name parameter.");
            }
            this.name = name;
        }

        /**
         * Gets the server's protocol.
         *
         * @return A string representing the server's protocol.
         */
        public String getProtocol() {
            return protocol;
        }

        /**
         * Sets the server's URL protocol.
         *
         * @param protocol A string representing the server's protocol.
         * @throws IllegalArgumentException Indicates that protocol is not an http/https/tcp or is null.
         */
        public void setProtocol(String protocol) throws IllegalArgumentException {
            if (protocol == null || !protocol.matches(PROTOCOL_REGEX)) {
                throw new IllegalArgumentException("Invalid protocol parameter.");
            }
            this.protocol = protocol;
        }

        /**
         * Gets the server's hostname.
         *
         * @return A string representing the server's host.
         */
        public String getHost() {
            return host;
        }

        /**
         * Sets the server's URL host.
         *
         * @param host A string representing the server's host.
         * @throws IllegalArgumentException Indicates that host is not a valid hostname of a URL.
         */
        public void setHost(String host) throws IllegalArgumentException {
            if (host == null || host.isEmpty() || !(host.matches(IP_ADDRESS_REGEX) || host.matches(HOSTNAME_REGEX))) {
                throw new IllegalArgumentException("Invalid host parameter.");
            }
            this.host = host;
        }

        /**
         * Gets the server's endpoint port.
         *
         * @return An integer representing the server's endpoint port.
         */
        public Integer getPort() {
            return port;
        }

        /**
         * Sets the server's endpoint URL port.
         *
         * @param port An integer representing the server's endpoint port.
         * @throws IllegalArgumentException Indicates that port is not a number or is out of 1-65535 range.
         */
        public void setPort(Integer port) throws IllegalArgumentException {
            if (port == null || port < MIN_PORT || port > MAX_PORT) {
                throw new IllegalArgumentException("Port parameter is out of range.");
            }
            this.port = port;
        }

        /**
         * Gets the server's endpoint URL path.
         *
         * @return A string representing the server's endpoint path.
         */
        public String getPath() {
            return path;
        }

        /**
         * Sets the server's endpoint URL path.
         *
         * @param path A string representing the server's endpoint path.
         * @throws IllegalArgumentException Indicates that path is null.
         */
        public void setPath(String path) throws IllegalArgumentException {
            if (path == null) {
                throw new IllegalArgumentException("Invalid path parameter.");
            }
            this.path = path;
        }
    }
}
