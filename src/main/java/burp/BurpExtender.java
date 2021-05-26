package burp;

import burp.app.controllers.SuiteTabController;
import burp.model.RacePwnSettings;
import burp.model.SuiteTabModel;
import burp.ui.SuiteTab;

import javax.swing.*;
import java.util.logging.*;

public class BurpExtender implements IBurpExtender {
    private static final Logger LOGGER = Logger.getLogger(BurpExtender.class.getName());
    private static BurpExtender extender;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    /**
     * This method is used to set <code>Logger</code> to send info to stdout and error message to Burp's alerts.
     *
     * @param callbacks A set of callback methods that can be used by extensions to perform various actions within Burp.
     */
    private static void setLoggerHandlers(IBurpExtenderCallbacks callbacks) {
        // Setup logging to the Burp's console
        Handler burpConsoleHandler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (getFormatter() == null) {
                    setFormatter(new SimpleFormatter());
                }

                try {
                    String message = getFormatter().format(record);
                    if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                        callbacks.printError(message);
                    } else {
                        callbacks.printOutput(message);
                    }
                } catch (Exception exception) {
                    reportError(null, exception, ErrorManager.FORMAT_FAILURE);
                }
            }

            @Override
            public void close() throws SecurityException {
            }

            @Override
            public void flush() {
            }
        };

        LOGGER.addHandler(burpConsoleHandler);
    }

    /**
     * This method is used to retrieve an extension instance.
     *
     * @return An <code>IBurpExtender</code> object representing an extension.
     */
    public static BurpExtender getInstance() {
        return extender;
    }

    /**
     * This method is used to retrieve extension helpers,
     * which extensions can use to assist with various common tasks that arise for Burp extensions.
     *
     * @return An <code>IExtensionHelpers</code> object containing helper methods.
     */
    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    /**
     * This method is invoked when the extension is loaded.
     * It registers an instance of the IBurpExtenderCallbacks interface,
     * providing methods that may be invoked by the extension to perform various actions.
     *
     * @param callbacks An <code>IBurpExtenderCallbacks</code> object.
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        extender = this;
        callbacks.setExtensionName(RacePwnSettings.EXTENSION_NAME);
        setLoggerHandlers(callbacks);
        // Ignore too detailed logs
        //LOGGER.setLevel(Level.FINE);

        // Suite Tab
        SuiteTabModel suiteTabModel = new SuiteTabModel();
        try {
            SuiteTabController suiteTabController = new SuiteTabController(suiteTabModel, this, callbacks, helpers);
            SwingUtilities.invokeLater(() -> {
                SuiteTab suiteTab = new SuiteTab(suiteTabController, callbacks, helpers);
                callbacks.addSuiteTab(suiteTab);
                LOGGER.log(Level.INFO, "{0} has been loaded.", RacePwnSettings.EXTENSION_NAME);
            });
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, RacePwnSettings.EXTENSION_NAME + " cannot be loaded.", e);
        }
    }
}
