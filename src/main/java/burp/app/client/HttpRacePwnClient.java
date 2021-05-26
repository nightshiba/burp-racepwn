package burp.app.client;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HttpRacePwnClient {
    private final Logger LOGGER = Logger.getLogger(HttpRacePwnClient.class.getName());
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private static HttpRacePwnClient singleInstance = null;

    /**
     * Creates a request client that utilises Burp's callbacks and helpers to send HTTP requests.
     */
    private HttpRacePwnClient(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.helpers = helpers;
        this.callbacks = callbacks;
    }

    public static HttpRacePwnClient getInstance(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers)
    {
        if (singleInstance == null) {
            singleInstance = new HttpRacePwnClient(callbacks, helpers);
        }

        return singleInstance;
    }

    /**
     * This method is used to send multiple requests to a single host using Racepwn server.
     *
     * @param attackRequestConfig An attack request configuration to execute.
     * @param url                 An <code>URL</code> object that contains server's URI.
     * @return A byte array response describing the result of attack request.
     */
    public byte[] sendAttackRequest(String attackRequestConfig, URL url) {
        LOGGER.log(Level.FINER, "Building an attack request. Server {0} with the body:\n{1}.", new Object[]{url.toString(), attackRequestConfig});
        byte[] request = helpers.buildHttpMessage(getHeaders(url.getHost(), url.getPort(), url.getPath()), helpers.stringToBytes(attackRequestConfig));
        LOGGER.log(Level.FINE, "Sending an attack request.");
        byte[] response = callbacks.makeHttpRequest(url.getHost(), url.getPort(), false, request);
        LOGGER.log(Level.FINE, "Received a response.");
        LOGGER.log(Level.FINER, "Returning a response body:\n{0}", response == null ? "null" : helpers.bytesToString(response));
        return response;
    }

    private static List<String> getHeaders(String host, Integer port, String path) {
        // TODO use Burp's addParameter
        List<String> headers = new ArrayList<>();
        headers.add("POST " + path + " HTTP/1.1");
        headers.add("Host: " + host + ":" + port.toString());

        return headers;
    }

    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
}
