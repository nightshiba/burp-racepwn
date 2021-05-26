package burp.ui;

import burp.app.controllers.SuiteTabController;
import burp.model.RacePwnSettings;
import burp.model.Server;

import java.util.List;
import javax.swing.*;
import java.awt.*;
import java.util.Collections;
import java.util.Vector;

public abstract class AbstractTab {
    private final SuiteTabController suiteTabController;

    public AbstractTab(SuiteTabController suiteTabController) {
        this.suiteTabController = suiteTabController;
    }

    abstract public Component getUiComponent();

    /**
     * Renders error message dialog with the specified text.
     *
     * @param description A string describing the error.
     */
    protected void showErrorMessageDialog(String description) {
        JOptionPane.showMessageDialog(new JFrame(), description, RacePwnSettings.TAB_NAME + " error message", JOptionPane.ERROR_MESSAGE);
    }

    protected static void customizeTitleComponent(JLabel title, int fontIncrease) {
        Font configurationTitleFont = title.getFont();
        title.setFont(configurationTitleFont.deriveFont(Font.BOLD, configurationTitleFont.getSize() + fontIncrease));
        title.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
    }

    protected static JSeparator getCustomizedHeaderSeparator() {
        JSeparator headerSeparator = new JSeparator();
        headerSeparator.setForeground(new Color(100, 100, 100));
        headerSeparator.setBackground(new Color(100, 100, 100));
        return headerSeparator;
    }


    protected JPanel initTitlePane(JLabel title) {
        JPanel titlePane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        customizeTitleComponent(title, 2);
        titlePane.add(title);

        return titlePane;
    }

    protected JPanel initBodyPane() {
        JPanel bodyPane = new JPanel();
        bodyPane.setLayout(new BoxLayout(bodyPane, BoxLayout.PAGE_AXIS));
        bodyPane.setBorder(BorderFactory.createEmptyBorder(0, 30, 0, 0));
        return bodyPane;
    }

    protected List<Server> getServerList() {
        return Collections.unmodifiableList(new Vector<> (suiteTabController.getServerList().values()));
    }
}
