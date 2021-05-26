package burp.model;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RacePwnSettings {
    private RacePwnSettings() {}

    private static final Logger LOGGER = Logger.getLogger(RacePwnSettings.class.getName());
    public static final String TAB_NAME = "Racepwn";
    public static final String EXTENSION_NAME = "RacePWN";
    public static final String RACE_PWN_NAME = "Local RacePWN server";
    public static final String RACE_PWN_DEFAULT_SERVER = "http://127.0.0.1:3337/race";
    public static URL rPwnDefaultURL = null;

    static {
        try {
            rPwnDefaultURL = new URL(RACE_PWN_DEFAULT_SERVER);
        } catch (MalformedURLException e) {
            LOGGER.log(Level.WARNING, "Invalid default server URL.", e);
        }
    }
}
