package burp.app.controllers;

import burp.*;
import burp.app.client.HttpRacePwnClient;
import burp.app.client.tasks.AttackTask;
import burp.model.*;
import burp.ui.SuiteTab;

import javax.swing.*;
import java.net.MalformedURLException;
import java.util.SortedMap;

public class SuiteTabController implements AttackResultCallback {
    final private SuiteTabModel suiteTabModel;
    final private IBurpExtender burpExtender;
    final private IBurpExtenderCallbacks callbacks;
    final private IExtensionHelpers helpers;
    private SuiteTab suiteTab;

    /** Creates a controller of Burp Tab GUI. It uses an HTTP RacePwn client to communicate with a RacePWN server.
     * @throws MalformedURLException Indicates that default server settings are invalid.
     */
    public SuiteTabController(SuiteTabModel suiteTabModel, IBurpExtender burpExtender, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) throws MalformedURLException {
        this.suiteTabModel = suiteTabModel;
        this.burpExtender = burpExtender;
        this.helpers = helpers;
        this.callbacks = callbacks;

        // init default settings
        suiteTabModel.setClient(HttpRacePwnClient.getInstance(callbacks, helpers));
        createNewActiveServer(new Server.ServerBuilder().build());
    }


    /**
     * This method is used to add a new active server.
     *
     * @param server The <code>Server</code> instance to be added to the server list and used as an active server.
     */
    public void createNewActiveServer(Server server) {
        // automatically show a new server in the "Attack" panel
        changeActiveServer(suiteTabModel.addServer(server));
    }

    /**
     * This method is used to delete server using it's identifier.
     *
     * @param serverID The identifier of <code>Server</code> instance.
     */
    public void removeServer(int serverID) throws IllegalArgumentException {
        suiteTabModel.removeServer(serverID);
    }

    /**
     * This method is used to change active server which will be used to execute requests.
     *
     * @param serverID The identifier of existing <code>Server</code> instance.
     */
    public void changeActiveServer(int serverID) {
        suiteTabModel.setActiveServerID(serverID);
    }

    /**
     * Gets an active server.
     *
     * @return The <code>Server</code> instance representing an active server.
     */
    public Server getActiveServer() {
        return suiteTabModel.getActiveServer();
    }


    /** Sets a response for a server with the specified identifier.
     * @param serverID The identifier of existing <code>Server</code> instance.
     * @param response A byte array representing a response.
     */
    public synchronized void setServerResponse(int serverID, byte[] response) {
        suiteTabModel.getServerByID(serverID).setResponse(response);
        SwingUtilities.invokeLater(() -> suiteTab.setResponseDataMessage(response, false));
    }

    /**
     * This method is used to send built <code>RequestConfig</code> to selected <code>Server</code>.
     *
     * @param attackRequest The racepwn config string in JSON format.
     */
    public void sendRequest(AttackRequest attackRequest) {
        new AttackTask(suiteTabModel.getClient(), suiteTabModel.getActiveServer(), suiteTabModel.getActiveServerID(), attackRequest, this).start();
    }

    /**
     * Gets a server list.
     *
     * @return The <code>Server</code> instance representing an active server.
     */
    public SortedMap<Integer, Server> getServerList() {
        return suiteTabModel.getServerList();
    }

    /**
     * Gets a response for selected log request.
     *
     * @return A byte array representing a response.
     */
    public byte[] getSelectedResponse() {
        return new byte[0];
    }

    /**
     * Sets a Suite Tab UI.
     *
     * @param suiteTab The <code>JPanel</code> object that will be displayed in the main Burp Suite window.
     */
    public void setUI(SuiteTab suiteTab) {
        this.suiteTab = suiteTab;
    }
}
