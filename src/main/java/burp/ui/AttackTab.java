package burp.ui;

import burp.*;
import burp.app.controllers.SuiteTabController;
import burp.model.AttackRequest;
import burp.model.Server;

import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AttackTab extends AbstractTab implements IMessageEditorController {
    private static final Logger LOGGER = Logger.getLogger(SuiteTab.class.getName());
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final SuiteTabController suiteTabController;
    private final AttackRequest.RequestBuilder requestBuilder;
    // Attack tab components
    private final JPanel attackTabComponent;
    private final JComboBox<Server> activeAttackServerInput;

    private JTextField hostInput;
    private JTextField portInput;
    private JCheckBox httpsInput;

    private ButtonGroup attackModeButtonGroup;
    private JTextField requestCountInput;
    private JTextField requestDelayInput;
    private JTextField requestLastChunkSizeInput;

    private IMessageEditor requestDataViewer;
    private IMessageEditor responseDataViewer;
    private IHttpService httpService = null; // TODO update from "Send to RacePwn"

    public AttackTab(SuiteTabController suiteTabController, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, JComboBox<Server> activeAttackServerList) {
        super(suiteTabController);
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.suiteTabController = suiteTabController;
        this.activeAttackServerInput = activeAttackServerList;

        requestBuilder = new AttackRequest.RequestBuilder();
        attackTabComponent = initAttackTab();
    }

    @Override
    public Component getUiComponent() {
        return attackTabComponent;
    }


    private JPanel initAttackHeaderPane() {
        JPanel headerPane = new JPanel(new BorderLayout());

        JPanel attackTargetPane = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JLabel targetTitle = new JLabel("Attack Target");
        customizeTitleComponent(targetTitle, 0);
        JLabel hostLabel = new JLabel("Host:");
        hostInput = new JTextField("", 30);
        hostInput.setMaximumSize(new Dimension(hostInput.getWidth(), hostInput.getPreferredSize().height));
        JLabel portLabel = new JLabel("Port:");
        portInput = new JTextField("", 10);
        portInput.setMaximumSize(new Dimension(portInput.getWidth(), portInput.getPreferredSize().height));
        httpsInput = new JCheckBox("Use HTTPS");
        addHttpServiceUpdatesListener(hostInput);
        addHttpServiceUpdatesListener(portInput);
        addHttpServiceUpdatesListener(httpsInput);
        activeAttackServerInput.addActionListener(actionEvent -> suiteTabController.changeActiveServer(((Server) activeAttackServerInput.getSelectedItem()).getId()));

        attackTargetPane.add(Box.createHorizontalStrut(40));
        attackTargetPane.add(targetTitle);
        attackTargetPane.add(Box.createHorizontalStrut(20));
        attackTargetPane.add(hostLabel);
        attackTargetPane.add(hostInput);
        attackTargetPane.add(portLabel);
        attackTargetPane.add(portInput);
        attackTargetPane.add(httpsInput);
        attackTargetPane.add(Box.createHorizontalStrut(40));
        attackTargetPane.add(activeAttackServerInput);

        headerPane.add(initRequestButtonPane(), BorderLayout.LINE_START);
        headerPane.add(attackTargetPane, BorderLayout.LINE_END);
        return headerPane;
    }

    private JPanel initAttackTab() {
        JPanel attackTab = new JPanel(new BorderLayout());

        JPanel controlPane = new JPanel();
        controlPane.setLayout(new BoxLayout(controlPane, BoxLayout.PAGE_AXIS));

        JPanel configurationBodyPane = initBodyPane();

        JLabel configurationTitle = new JLabel("Configuration");
        JPanel configurationHeaderPane = initTitlePane(configurationTitle);

        JPanel attackModePane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel attackModeTitle = new JLabel("Attack mode:");
        attackModeButtonGroup = new ButtonGroup();
        JRadioButton parallelAttackModeButton = new JRadioButton("Parallel");
        parallelAttackModeButton.setActionCommand("parallel");
        parallelAttackModeButton.setSelected(true);
        addAttackSettingsUpdatesListener(parallelAttackModeButton);
        JRadioButton pipelineAttackModeButton = new JRadioButton("Pipeline");
        pipelineAttackModeButton.setActionCommand("pipeline");
        addAttackSettingsUpdatesListener(pipelineAttackModeButton);
        for (Enumeration<AbstractButton> buttons = attackModeButtonGroup.getElements(); buttons.hasMoreElements(); ) {
            AbstractButton button = buttons.nextElement();
            button.setSelected(button.getActionCommand().equals(requestBuilder.getType()));
        }
        attackModeButtonGroup.add(parallelAttackModeButton);
        attackModeButtonGroup.add(pipelineAttackModeButton);
        attackModePane.add(attackModeTitle);
        attackModePane.add(parallelAttackModeButton);
        attackModePane.add(pipelineAttackModeButton);

        JPanel requestCountPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel requestCountTitle = new JLabel("Request count:");
        requestCountInput = new JTextField(String.valueOf(requestBuilder.getCount()), 10);
        addAttackSettingsUpdatesListener(requestCountInput);
        requestCountPane.add(requestCountTitle);
        requestCountPane.add(requestCountInput);

        JPanel requestDelayPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel requestDelayTitle = new JLabel("Request delay (µs):");
        requestDelayInput = new JTextField(String.valueOf(requestBuilder.getDelayTimeUsec()), 10);
        requestDelayPane.add(requestDelayTitle);
        requestDelayPane.add(requestDelayInput);

        JPanel lastChunkSizePane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel lastChunkSizeTitle = new JLabel("Last request chunk size:");
        requestLastChunkSizeInput = new JTextField(String.valueOf(requestBuilder.getLastChunkSize()), 10);
        lastChunkSizePane.add(lastChunkSizeTitle);
        lastChunkSizePane.add(requestLastChunkSizeInput);


        configurationBodyPane.add(attackModePane);
        configurationBodyPane.add(requestCountPane);
        configurationBodyPane.add(requestDelayPane);
        configurationBodyPane.add(lastChunkSizePane);

        controlPane.add(initAttackHeaderPane());
        controlPane.add(getCustomizedHeaderSeparator());
        controlPane.add(configurationHeaderPane);
        controlPane.add(configurationBodyPane);


        JPanel editorPane = new JPanel(new GridLayout(1, 2));
        requestDataViewer = callbacks.createMessageEditor(this, true);
        responseDataViewer = callbacks.createMessageEditor(this, false);
        requestDataViewer.setMessage(new byte[0], true);
        responseDataViewer.setMessage(new byte[0], false);
        editorPane.add(requestDataViewer.getComponent());
        editorPane.add(responseDataViewer.getComponent());

        attackTab.add(controlPane, BorderLayout.PAGE_START);
        attackTab.add(editorPane, BorderLayout.CENTER);
        return attackTab;
    }

    private JPanel initRequestButtonPane() {
        JPanel sendRequestPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        sendRequestPane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JButton sendRequestButton = new JButton("Send");
        sendRequestButton.addActionListener(actionEvent -> startAttack());
        sendRequestPane.add(sendRequestButton);

        return sendRequestPane;
    }


    private void startAttack() {
        LOGGER.log(Level.FINE, "Called start attack request.");

        byte[] requestData = getRequest();

        if (requestData == null) {
            LOGGER.log(Level.FINEST, "Received a bad request with zero data.");
            showErrorMessageDialog("Invalid request data.");
            return;
        }

        String requestDataString = helpers.bytesToString(requestData);

        try {
            updateHttpService();
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.FINEST, "Cannot create HTTP Service using specified target parameters.");
            showErrorMessageDialog("Invalid attack target parameters.");
            return;
        }

        LOGGER.log(Level.FINE, "Building request JSON config.");
        requestBuilder.setData(requestDataString);
        requestBuilder.setPort(httpService.getPort());
        requestBuilder.setHost(httpService.getHost());
        requestBuilder.setProtocol(httpService.getProtocol());

        try {
            updateAttackSettings();
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.FINEST, "Cannot create server URL from HTTP Service.");
            showErrorMessageDialog(e.getMessage()); // TODO .replaceFirst(".*Error text", "Custom text"));
        }

        AttackRequest attackRequest = requestBuilder.build();
        suiteTabController.sendRequest(attackRequest);
    }

    /**
     * Sets the editor message.
     *
     * @param message   A string representing the attack request/response.
     * @param isRequest A boolean that is true if the request message will be passed otherwise false.
     */
    public void setResponseDataMessage(byte[] message, boolean isRequest) {
        responseDataViewer.setMessage(message, isRequest);
    }

    private synchronized void updateHttpService() throws IllegalArgumentException {
        LOGGER.log(Level.FINEST, "Updating Burp's HttpService.");
        httpService = helpers.buildHttpService(hostInput.getText(), Integer.parseInt(portInput.getText()), httpsInput.isSelected());
    }

    private synchronized void updateAttackSettings() throws IllegalArgumentException {
        LOGGER.log(Level.FINEST, "Updating attack settings in the Attack tab.");
        if (attackModeButtonGroup.getSelection() != null) {
            requestBuilder.setType(attackModeButtonGroup.getSelection().getActionCommand());
        }
        requestBuilder.setCount(requestCountInput.getText());
        requestBuilder.setDelayTimeUsec(requestDelayInput.getText());
        requestBuilder.setLastChunkSize(requestLastChunkSizeInput.getText());
    }

    private void addHttpServiceUpdatesListener(JComponent component) {
        component.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(final FocusEvent evt) {
                try {
                    updateHttpService();
                } catch (IllegalArgumentException ignored) {
                }
            }
        });
    }

    private void addAttackSettingsUpdatesListener(JComponent component) {
        component.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(final FocusEvent evt) {
                try {
                    updateAttackSettings();
                } catch (IllegalArgumentException ignored) {
                }
            }
        });
    }


    /**
     * This method is used to retrieve a <code>HttpService</code> object with details about the target HTTP service.
     *
     * @return The HTTP service.
     */
    @Override
    public IHttpService getHttpService() {
        if (httpService == null) {
            LOGGER.log(Level.FINEST, "Got an attempt to use editor with an empty HttpService.");
            showErrorMessageDialog("Invalid target parameters.");
        }
        return httpService;
    }

    /**
     * This method is used to retrieve a request that will be sent by the chosen <code>Server</code>.
     *
     * @return The request bytes to be sent during the attack.
     */
    @Override
    public byte[] getRequest() {
        return requestDataViewer.getMessage();
    }

    /**
     * This method is used to retrieve a last attack result for the chosen <code>Server</code>.
     *
     * @return The response bytes containing attack results.
     */
    @Override
    public byte[] getResponse() {
        return suiteTabController.getActiveServer().getResponse();
    }

}
