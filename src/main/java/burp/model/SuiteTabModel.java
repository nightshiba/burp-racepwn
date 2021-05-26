package burp.model;

import burp.app.client.HttpRacePwnClient;

import java.util.*;

public class SuiteTabModel {
    private static final Integer NO_SERVER = -1;
    private static final Integer FIRST_SERVER_ID = 1;
    private final SortedMap<Integer, Server> servers = new TreeMap<>();
    private Integer activeServerID = NO_SERVER;
    private HttpRacePwnClient client;


    /**
     * Gets HttpRacePwnClient to use for communication.
     *
     * @return A HttpRacePwnClient that will be used to send requests to the RacePWN server.
     */
    public HttpRacePwnClient getClient() {
        return client;
    }

    /**
     * Sets HttpRacePwnClient to use for communication.
     *
     * @param client A HttpRacePwnClient that will be used to send requests to the RacePWN server.
     */
    public void setClient(HttpRacePwnClient client) {
        this.client = client;
    }

    /**
     * Gets server using it's identifier.
     *
     * @return A <code>Server</code> class instance.
     */
    public Server getServerByID(int serverID) {
        return servers.get(serverID);
    }

    /**
     * Gets actual server identifier.
     *
     * @return An Integer representing the current RacePWN server identifier to be used.
     */
    public Integer getActiveServerID() {
        return activeServerID;
    }

    /**
     * Sets actual server identifier.
     *
     * @param activeServerID An Integer representing the current RacePWN server identifier to be used.
     */
    public void setActiveServerID(int activeServerID) {
        this.activeServerID = activeServerID;
    }

    /**
     * Gets server in use.
     *
     * @return An active <code>Server</code> class instance.
     */
    public Server getActiveServer() {
        return servers.get(activeServerID);
    }

    /**
     * Adds a new server to the server list.
     *
     * @param server A <code>Server</code> class instance to be added.
     * @return An Integer representing the identifier of the added server.
     */
    public int addServer(Server server) {
        int newServerID;
        try {
            newServerID = servers.lastKey() + 1;
            if (server.getName().isEmpty()) {
                server.setName("New server #" + newServerID);
            }
        } catch (NoSuchElementException e) {
            newServerID = FIRST_SERVER_ID;
        }
        server.setId(newServerID);
        servers.put(newServerID, server);
        return newServerID;
    }

    /**
     * Removes a server from the server list.
     *
     * @param serverID An Integer representing the identifier of the server to be deleted.
     * @throws IllegalArgumentException Indicates that server with specified serverID is in use or it is a last server in the server list.
     */
    public void removeServer(int serverID) throws IllegalArgumentException {
        if (servers.size() == 1) {
            throw new IllegalArgumentException("You cannot remove last server.");
        }

        if (servers.get(serverID).getLock().isLocked()) {
            throw new IllegalArgumentException("You cannot remove server while it is in use.");
        }
    }

    /**
     * Gets actual server list.
     *
     * @return A mapping between server identifiers and <code>Server</code> class objects.
     */
    public SortedMap<Integer, Server> getServerList() {
        return servers;
    }
}
