package burp.app.client.tasks;

import burp.BurpExtender;
import burp.app.client.HttpRacePwnClient;
import burp.model.AttackRequest;
import burp.model.AttackResultCallback;
import burp.model.Server;
import org.json.JSONArray;

import java.util.logging.Level;
import java.util.logging.Logger;


public class AttackTask extends AbstractTask {
    private static final Logger LOGGER = Logger.getLogger(AttackTask.class.getName());
    private final AttackResultCallback callback;
    private final int activeServerID;

    public AttackTask(HttpRacePwnClient client, Server server, int activeServerID, AttackRequest attackRequest, AttackResultCallback callback) {
        super(client, server, attackRequest);
        this.callback = callback;
        this.activeServerID = activeServerID;
    }

    @Override
    void communicate() {
        LOGGER.log(Level.FINE, "Processing {0} request", AttackTask.class.getSimpleName());
        LOGGER.log(Level.FINER, "Sending request to the server with URL: {0}", super.getServer().getURL());
        byte[] response;
        try {
            response = super.getClient().sendAttackRequest(super.getAttackRequest().getJsonConfig(), super.getServer().getURL());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Server connection error."); // TODO it does not work, cannot find any way to detect it
            return;
        }
        JSONArray responseJSON;
        try {
            LOGGER.log(Level.FINER, "Got response:\n{0}", bytesToString(response));
            String parsedBody = parseBody(response); // TODO add all responses to the log using callback
            responseJSON = new JSONArray(parsedBody);
            // TODO call dialog error message if [{"responses":[{"response":"\u0000"}]}]
            callback.setServerResponse(activeServerID, response);
            LOGGER.log(Level.FINE, "Processed {0} request", AttackTask.class.getSimpleName());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error while parsing response body.", e);
        }
    }
}
