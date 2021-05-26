package burp.ui;

import burp.app.controllers.SuiteTabController;
import burp.model.Server;

import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.net.MalformedURLException;
import java.util.Objects;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServersTab extends AbstractTab {
    private static final Logger LOGGER = Logger.getLogger(SuiteTab.class.getName());
    private final SuiteTabController suiteTabController;
    // Servers tab components
    private final JPanel serversTabComponent;

    private Server.ServerBuilder newServerBuilder;
    private final JTextField newServerName = new JTextField("", 20);
    private final JTextField newServerProtocol = new JTextField("", 3);
    private final JTextField newServerHost = new JTextField("", 10);
    private final JTextField newServerPort = new JTextField("", 5);
    private final JTextField newServerPath = new JTextField("", 5);

    private final JComboBox<Server> activeReviewServerList;
    private final JComboBox<Server> activeAttackServerList;


    private JLabel serverURL;
    private JLabel serverName;

    public ServersTab(SuiteTabController suiteTabController) {
        super(suiteTabController);
        this.suiteTabController = suiteTabController;
        Vector<Server> serverList = new Vector<>(getServerList());
        activeReviewServerList = new JComboBox<>(serverList);
        activeAttackServerList = new JComboBox<>(serverList);
        serversTabComponent = initServersTab();
    }

    @Override
    public Component getUiComponent() {
        return serversTabComponent;
    }

    public JComboBox<Server> getActiveAttackServerList() {
        return activeAttackServerList;
    }

    private JPanel initServersHeaderPane() {
        JPanel headerPane = new JPanel(new BorderLayout());

        JPanel selectReviewServerPane = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        selectReviewServerPane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JLabel selectReviewServerTitle = new JLabel("Select server to review:");
        activeReviewServerList.addActionListener(actionEvent ->
                updateReviewServerSettings((Server) Objects.requireNonNull(activeReviewServerList.getSelectedItem())));

        selectReviewServerPane.add(selectReviewServerTitle);
        selectReviewServerPane.add(Box.createHorizontalStrut(10));
        selectReviewServerPane.add(activeReviewServerList);

        headerPane.add(selectReviewServerPane, BorderLayout.LINE_END);
        return headerPane;
    }

    private JPanel initServersTab() {
        JPanel serversTab = new JPanel(new BorderLayout());
        JPanel headerPane = new JPanel();
        headerPane.setLayout(new BoxLayout(headerPane, BoxLayout.PAGE_AXIS));
        headerPane.add(initServersHeaderPane());
        headerPane.add(getCustomizedHeaderSeparator());

        JPanel bodyPane = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JPanel reviewServerPane = initBodyPane();
        JLabel reviewServerTitle = new JLabel("Review current server settings");
        JPanel reviewServerTitlePane = initTitlePane(reviewServerTitle);

        JPanel serverNamePane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel serverNameTitle = new JLabel("Name:");
        serverName = new JLabel();
        serverNamePane.add(serverNameTitle);
        serverNamePane.add(Box.createHorizontalStrut(10));
        serverNamePane.add(serverName);
        JPanel serverUrlPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel serverUrlTitle = new JLabel("URL:");
        serverURL = new JLabel();
        serverUrlPane.add(serverUrlTitle);
        serverUrlPane.add(Box.createHorizontalStrut(10));
        serverUrlPane.add(serverURL);
        updateReviewServerSettings(suiteTabController.getActiveServer());
        JButton deleteServerButton = new JButton("Delete current server");
        deleteServerButton.addActionListener(actionEvent -> deleteServer());

        reviewServerPane.add(reviewServerTitlePane);
        reviewServerPane.add(serverNamePane);
        reviewServerPane.add(serverUrlPane);
        reviewServerPane.add(deleteServerButton);


        JPanel editServerListPane = initBodyPane();
        JLabel editServerListTitle = new JLabel("Add a new server");
        JPanel editServerListTitlePane = initTitlePane(editServerListTitle);
        newServerBuilder = new Server.ServerBuilder();
        JPanel newServerPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        resetNewServerParameters();
        addNewServerParameterUpdatesListener(newServerName);
        addNewServerParameterUpdatesListener(newServerProtocol);
        addNewServerParameterUpdatesListener(newServerHost);
        addNewServerParameterUpdatesListener(newServerPort);
        addNewServerParameterUpdatesListener(newServerPath);
        JButton createServerButton = new JButton("Create");
        createServerButton.addActionListener(actionEvent -> createServer());


        editServerListPane.add(editServerListTitlePane);
        editServerListPane.add(newServerName);
        newServerPane.add(newServerProtocol);
        newServerPane.add(newServerHost);
        newServerPane.add(new JLabel(":"));
        newServerPane.add(newServerPort);
        newServerPane.add(new JLabel("/"));
        newServerPane.add(newServerPath);
        editServerListPane.add(newServerPane);
        editServerListPane.add(createServerButton);

        bodyPane.add(reviewServerPane);
        bodyPane.add(editServerListPane);

        serversTab.add(headerPane, BorderLayout.PAGE_START);
        serversTab.add(bodyPane, BorderLayout.CENTER);
        return serversTab;
    }


    private synchronized void createServer() {
        try {
            updateNewServerParameters();
            suiteTabController.createNewActiveServer(newServerBuilder.build());
            resetNewServerParameters();

            Server createdServer = suiteTabController.getActiveServer();
            activeAttackServerList.addItem(createdServer);
            activeAttackServerList.setSelectedItem(createdServer);
            //activeReviewServerList.addItem(createdServer); TODO use it later for server log adding
            activeReviewServerList.setSelectedItem(createdServer);
            newServerBuilder = new Server.ServerBuilder(); // reset builder
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.FINEST, "Error while building a new server.", e);
            showErrorMessageDialog(e.getMessage());
        } catch (MalformedURLException e) {
            LOGGER.log(Level.FINEST, "Cannot create server URL with the specified parameters.", e);
            showErrorMessageDialog("Error while parsing server URL.");
        }
    }


    private synchronized void deleteServer() {
        try {
            Server server = (Server) Objects.requireNonNull(activeReviewServerList.getSelectedItem());
            suiteTabController.removeServer(server.getId());

            activeAttackServerList.removeItem(server);
            activeReviewServerList.removeItem(server);
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.FINEST, "Error while deleting a server.", e);
            showErrorMessageDialog(e.getMessage());
        }
    }



    private synchronized void updateNewServerParameters() throws IllegalArgumentException {
        newServerBuilder.setName(newServerName.getText());
        newServerBuilder.setProtocol(newServerProtocol.getText());
        newServerBuilder.setHost(newServerHost.getText());
        newServerBuilder.setPort(Integer.parseInt(newServerPort.getText()));
        newServerBuilder.setPath("/" + newServerPath.getText());
    }



    private synchronized void resetNewServerParameters() {
        LOGGER.log(Level.FINEST, "Resetting server parameters in the Servers tab.");
        newServerName.setText("");
        newServerProtocol.setText(newServerBuilder.getProtocol());
        newServerHost.setText(newServerBuilder.getHost());
        newServerPort.setText(String.valueOf(newServerBuilder.getPort()));
        newServerPath.setText(newServerBuilder.getPath().substring(1));
    }

    private synchronized void updateReviewServerSettings(Server reviewServer) {
        LOGGER.log(Level.FINEST, "Updating server review parameters in the Servers tab.");
        serverName.setText(reviewServer.getName());
        serverURL.setText(reviewServer.getURL().toString());
    }

    private void addNewServerParameterUpdatesListener(JComponent component) {
        component.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(final FocusEvent evt) {
                try {
                    updateNewServerParameters();
                } catch (IllegalArgumentException ignored) {
                }
            }
        });
    }
}
