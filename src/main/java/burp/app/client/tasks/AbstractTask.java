package burp.app.client.tasks;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.app.client.HttpRacePwnClient;
import burp.model.AttackRequest;
import burp.model.Server;

public abstract class AbstractTask extends Thread {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final HttpRacePwnClient client;
    private final Server server;
    private final AttackRequest attackRequest;

    /**
     * Initializes a task wrapper for sending <code>AttackRequest</code> requests.
     *
     * @param client        A HTTP request client which based on Burp callbacks and helpers.
     * @param server        A server class represents RacePWN endpoint data.
     * @param attackRequest An attack request containing JSON RacePWN configuration.
     */
    protected AbstractTask(HttpRacePwnClient client, Server server, AttackRequest attackRequest) {
        helpers = client.getHelpers();
        callbacks = client.getCallbacks();
        this.client = client;
        this.server = server;
        this.attackRequest = attackRequest;
    }


    /**
     * This method should implement main task functionality with the help of other <code>AbstractTask</code> methods.
     */
    abstract void communicate();

    @Override
    public void run() {
        if (!server.getLock().tryLock()) {
            return;
        }

        try {
            communicate();
        } finally {
            server.getLock().unlock();
        }
    }


    /**
     * @param response The raw response bytes.
     * @return A string representing response body.
     */
    protected final String parseBody(byte[] response) throws NullPointerException {
        String responseString = bytesToString(response);
        int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
        return responseString.substring(bodyOffset);
    }

    protected final String bytesToString(byte[] bytes) {
        return helpers.bytesToString(bytes);
    }

    protected IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    protected IExtensionHelpers getHelpers() {
        return helpers;
    }

    protected HttpRacePwnClient getClient() {
        return client;
    }

    protected Server getServer() {
        return server;
    }

    protected AttackRequest getAttackRequest() {
        return attackRequest;
    }
}
