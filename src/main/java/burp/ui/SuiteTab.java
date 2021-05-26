package burp.ui;

import burp.*;
import burp.app.controllers.SuiteTabController;
import burp.model.RacePwnSettings;

import javax.swing.*;
import java.awt.*;
import java.util.logging.Level;
import java.util.logging.Logger;


public class SuiteTab extends JPanel implements ITab {
    private static final Logger LOGGER = Logger.getLogger(SuiteTab.class.getName());
    private final SuiteTabController suiteTabController;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    private final JTabbedPane extensionTabs;
    private final AttackTab attackTab;
    private final ServersTab serversTab;



    /**
     * Creates GUI components and handles logic for the extension tab.
     */
    public SuiteTab(SuiteTabController suiteTabController, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        suiteTabController.setUI(this);
        this.suiteTabController = suiteTabController;
        this.callbacks = callbacks;
        this.helpers = helpers;

        extensionTabs = new JTabbedPane();
        serversTab = new ServersTab(suiteTabController);
        attackTab = new AttackTab(suiteTabController, callbacks, helpers, serversTab.getActiveAttackServerList());
        initUI();

        callbacks.customizeUiComponent(this);
    }


    private void initUI() {
        LOGGER.log(Level.FINE, "Initializing a GUI.");
        extensionTabs.add("Attack", attackTab.getUiComponent());
        extensionTabs.add("Servers", serversTab.getUiComponent());
        this.add(extensionTabs);
    }

    /**
     * Sets the editor message in the Attack tab.
     *
     * @param message   A string representing the attack request/response.
     * @param isRequest A boolean that is true if the request message will be passed otherwise false.
     */
    public void setResponseDataMessage(byte[] message, boolean isRequest) {
        LOGGER.log(Level.FINEST, "Updating message in the {0} editor with:\n{1}", new Object[]{isRequest ? "request" : "response", helpers.bytesToString(message)});
        attackTab.setResponseDataMessage(message, isRequest);
    }

    @Override
    public String getTabCaption() {
        return RacePwnSettings.TAB_NAME;
    }

    @Override
    public Component getUiComponent() {
        return extensionTabs;
    }
}
