package com.primavera.wsclient.demo;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileFilter;

public class WSDemoWizardFrame
  extends JFrame
{
    //~ Static fields/initializers -----------------------------------------------------------------

    private static final long serialVersionUID = 1L;
    private static final String APP_TITLE = "Primavera P6 Web Services Demo";
    private static final String ERROR_TITLE = APP_TITLE;

    private static final String CARD_CONNECTION_INFO = "ConnectionInfo";
    private static final int CONNECTION_CARD = 0;

    private static final String CARD_AUTHENTICATION_TYPE = "AuthenticationType";
    private static final int AUTHENTICATION_CARD = 1;

    private static final String CARD_PROTECTION_TYPE = "ProtectionType";
    private static final int PROTECTION_CARD = 2;

    private static final String CARD_SAML_TYPE = "SAMLType";
    private static final int SAML_CARD = 3;

    private static final String CARD_ENCRYPTION_INFO = "EncryptionSettings";
    private static final int ENCRYPTION_CARD = 4;

    private static final String CARD_DEMO_INFO = "DemoInfo";
    private static final int DEMO_CARD = 5;

    private static final String CARD_STATUS = "Status";
    private static final int STATUS_CARD = 6;

    // Other constants
    private static final Border s_defaultCardBorder = new EmptyBorder(20, 10, 10, 10);
    private static final int s_horizontalStrutWidth = 10;
    private static final int s_verticalStrutHeight = 10;
    private static final int s_pnlMinimumHeight = 25;

    //~ Instance fields ----------------------------------------------------------------------------
    /** Components */
    private JCheckBox chkSamlSigned;
    private JTextField txtSamlKeystore;
    private JButton btnSamlBrowse;
    private JComboBox combSamlExtension;
    private JPasswordField txtSamlKeystorePass;
    private JTextField txtSamlAlias;
    private JPasswordField txtSamlKeyPass;
    private JComboBox combEncExtension;
    private JTextField txtFieldEncFile;
    private JTextField txtFieldSamlTokenFile;
    private JPasswordField txtFieldKeystorePass;
    private JTextField txtFieldCertAlias;
    private JCheckBox chkEncInbound;
    private JTextField txtfldUserName;
    private JPasswordField txtfldPassword;
    private JTextField txtfldHostName;
    private JTextField txtfldSamlIssuer;
    private JLabel lblSamlIssuer;
    private JLabel samlTokenFileLabel;
    private JTextField txtfldPort;
    private JCheckBox chkUseSSL;
    private JTextField txtfldProjectId;
    private JRadioButton rbtnAuthTypeSAML11;
    private JRadioButton rbtnAuthTypeSAML20;
    private JRadioButton rdbtnAuthTypeCookie;
    private JRadioButton rdbtnAuthTypeToken;
    private JCheckBox chkEncEnabled;
    private JCheckBox chkSigEnabled;
    private JCheckBox chkPerformExport;
    private JLabel lblExportSaveTo;
    private JTextField txtfldExportSaveTo;
    private JButton btnBrowse;
    private JButton btnEncBrowse;
    private JButton btnSamlTokenBrowse;
    private JButton btnSamlTokenDownload;
    private JCheckBox chkAsync;
    private JTextArea txtareaStatus;
    private JButton btnBack;
    private JButton btnNext;
    private JButton btnCancel;
    private JPanel pnlCards;
    private List<String> cards = new ArrayList<String>();
    private int iCurrentCard = 0;
    private PrintStream m_progressStream;
    private static final String HTTP = "HTTP://";
    private static final String HTTPS = "HTTPS://";

    //~ Constructors -------------------------------------------------------------------------------

    WSDemoWizardFrame()
    {
        setTitle(APP_TITLE);
        setResizable(true);
        cards.add(CARD_CONNECTION_INFO);
        cards.add(CARD_AUTHENTICATION_TYPE);
        cards.add(CARD_PROTECTION_TYPE);
        cards.add(CARD_SAML_TYPE);
        cards.add(CARD_ENCRYPTION_INFO);
        cards.add(CARD_DEMO_INFO);
        cards.add(CARD_STATUS);
        initComponents();
        init();
        setDefaultDemoInfo();
    }

    //~ Methods ------------------------------------------------------------------------------------

    private void init()
    {
        btnBack.setEnabled(false);
        iCurrentCard = 0;
        showCard(iCurrentCard);
    }

    private void initComponents()
    {
        pnlCards = new JPanel();
        pnlCards.setLayout(new CardLayout());
        pnlCards.setPreferredSize(new Dimension(450, 290));
        pnlCards.setMaximumSize(new Dimension(450, 290));

        // Initialize cards
        initConnectionInfoCard();
        initAuthenticationTypeCard();
        initProtectionCard();
        initSAMLCard();
        initEncryptionInfoCard();
        initDemoInfoCard();
        initStatusCard();

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(pnlCards, BorderLayout.NORTH);

        // General controls
        {
            btnBack = new JButton("Previous");
            btnBack.setMnemonic('V');
            btnNext = new JButton("Next");
            btnNext.setMnemonic('N');
            btnCancel = new JButton("Cancel");

            // Add ActionListeners to buttons
            btnBack.addActionListener(new ActionListener()
                {
                    public void actionPerformed(ActionEvent e)
                    {
                        backButtonActionPerformed(e);
                    }
                });
            btnNext.addActionListener(new ActionListener()
                {
                    public void actionPerformed(ActionEvent e)
                    {
                        nextButtonActionPerformed(e);
                    }
                });
            btnCancel.addActionListener(new ActionListener()
                {
                    public void actionPerformed(ActionEvent e)
                    {
                        cancelButtonActionPerformed(e);
                    }
                });

            JPanel pnlSouth = new JPanel();
            pnlSouth.setBorder(new EmptyBorder(0, 5, 5, 5));
            ((FlowLayout)pnlSouth.getLayout()).setAlignment(FlowLayout.RIGHT);
            pnlSouth.add(btnBack);
            pnlSouth.add(btnNext);
            pnlSouth.add(btnCancel);
            getRootPane().setDefaultButton(btnNext);
            sizeUniformly(btnBack, new JComponent[] {btnNext, btnCancel});
            getContentPane().add(pnlSouth, BorderLayout.SOUTH);
        }

        setResizable(false);
        pack();
        setLocationRelativeTo(null);
    }

    private void initConnectionInfoCard()
    {
        txtfldUserName = new JTextField();
        txtfldPassword = new JPasswordField();
        txtfldHostName = new JTextField();
        txtfldSamlIssuer = new JTextField();
        txtfldPort = new JTextField();

        JPanel pnlCardCenter = new JPanel();
        pnlCardCenter.setBorder(s_defaultCardBorder);
        pnlCardCenter.setLayout(new BoxLayout(pnlCardCenter, BoxLayout.Y_AXIS));

        JPanel pnlUserName = new JPanel();
        pnlUserName.setLayout(new BoxLayout(pnlUserName, BoxLayout.X_AXIS));
        pnlUserName.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel lblUserName = new JLabel("User name:");
        lblUserName.setDisplayedMnemonic('U');
        lblUserName.setLabelFor(txtfldUserName);
        pnlUserName.add(lblUserName);
        pnlUserName.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlUserName.add(txtfldUserName);
        pnlCardCenter.add(pnlUserName);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlPassword = new JPanel();
        pnlPassword.setLayout(new BoxLayout(pnlPassword, BoxLayout.X_AXIS));
        pnlPassword.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel lblPassword = new JLabel("Password:");
        lblPassword.setDisplayedMnemonic('P');
        lblPassword.setLabelFor(txtfldPassword);
        pnlPassword.add(lblPassword);
        pnlPassword.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlPassword.add(txtfldPassword);
        pnlCardCenter.add(pnlPassword);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlHostName = new JPanel();
        pnlHostName.setLayout(new BoxLayout(pnlHostName, BoxLayout.X_AXIS));
        pnlHostName.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel lblHostName = new JLabel("Host name:");
        lblHostName.setDisplayedMnemonic('H');
        lblHostName.setLabelFor(txtfldHostName);
        pnlHostName.add(lblHostName);
        pnlHostName.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlHostName.add(txtfldHostName);
        pnlCardCenter.add(pnlHostName);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlPort = new JPanel();
        pnlPort.setLayout(new BoxLayout(pnlPort, BoxLayout.X_AXIS));
        pnlPort.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel lblPort = new JLabel("Port:");
        lblPort.setDisplayedMnemonic('o');
        lblPort.setLabelFor(txtfldPort);
        pnlPort.add(lblPort);
        pnlPort.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlPort.add(txtfldPort);
        chkUseSSL = new JCheckBox("Use SSL");
        pnlPort.add(chkUseSSL);
        pnlCardCenter.add(pnlPort);
        pnlCardCenter.add(Box.createVerticalStrut(Integer.MAX_VALUE));
        sizeUniformly(lblUserName, new JComponent[] {lblPassword, lblHostName, lblPort});
        pnlCards.add(pnlCardCenter, CARD_CONNECTION_INFO);
    }

    private void initAuthenticationTypeCard()
    {
        JPanel pnlCardCenter = new JPanel();
        pnlCardCenter.setBorder(s_defaultCardBorder);
        pnlCardCenter.setLayout(new BoxLayout(pnlCardCenter, BoxLayout.Y_AXIS));

        JPanel pnlPrompt = new JPanel();
        pnlPrompt.setLayout(new BoxLayout(pnlPrompt, BoxLayout.X_AXIS));
        pnlPrompt.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel lblAuthType = new JLabel("Authentication and session management");
        pnlPrompt.add(lblAuthType);
        pnlPrompt.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlPrompt);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight * 2));

        rdbtnAuthTypeToken = new JRadioButton("Use UsernameToken Profile for authentication");
        rdbtnAuthTypeCookie = new JRadioButton("Use HTTP cookies for session management");
        rbtnAuthTypeSAML11 = new JRadioButton("Use SAML 1.1 for authentication");
        rbtnAuthTypeSAML20 = new JRadioButton("Use SAML 2.0 for authentication");

        ButtonGroup btnGroup = new ButtonGroup();
        btnGroup.add(rdbtnAuthTypeToken);
        btnGroup.add(rdbtnAuthTypeCookie);
        btnGroup.add(rbtnAuthTypeSAML11);
        btnGroup.add(rbtnAuthTypeSAML20);

        JPanel pnlToken = new JPanel();
        pnlToken.setLayout(new BoxLayout(pnlToken, BoxLayout.X_AXIS));
        pnlToken.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlToken.add(rdbtnAuthTypeToken);
        pnlToken.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlToken);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlSAML11 = new JPanel();
        pnlSAML11.setLayout(new BoxLayout(pnlSAML11, BoxLayout.X_AXIS));
        pnlSAML11.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlSAML11.add(rbtnAuthTypeSAML11);
        pnlSAML11.add(Box.createHorizontalGlue());

        pnlCardCenter.add(pnlSAML11);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlSAML20 = new JPanel();
        pnlSAML20.setLayout(new BoxLayout(pnlSAML20, BoxLayout.X_AXIS));
        pnlSAML20.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlSAML20.add(rbtnAuthTypeSAML20);
        pnlSAML20.add(Box.createHorizontalGlue());

        pnlCardCenter.add(pnlSAML20);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlCookie = new JPanel();
        pnlCookie.setLayout(new BoxLayout(pnlCookie, BoxLayout.X_AXIS));
        pnlCookie.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlCookie.add(rdbtnAuthTypeCookie);
        pnlCookie.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlCookie);
        pnlCardCenter.add(Box.createVerticalGlue());
        pnlCards.add(pnlCardCenter, CARD_AUTHENTICATION_TYPE);
    }

    private void initProtectionCard()
    {
        txtFieldSamlTokenFile = new JTextField();
        
        JPanel pnlCardCenter = new JPanel();
        pnlCardCenter.setBorder(s_defaultCardBorder);
        pnlCardCenter.setLayout(new BoxLayout(pnlCardCenter, BoxLayout.Y_AXIS));

        JPanel pnlHeader = new JPanel();
        pnlHeader.setLayout(new BoxLayout(pnlHeader, BoxLayout.X_AXIS));
        pnlHeader.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel lblProtectionType = new JLabel("Secure message protection options");
        pnlHeader.add(lblProtectionType);
        pnlHeader.add(Box.createHorizontalGlue());

        pnlCardCenter.add(pnlHeader);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight * 2));

        chkEncEnabled = new JCheckBox("Enable encryption (UsernameToken or SAML)");
        JPanel pnlEncEnabled = new JPanel();
        pnlEncEnabled.setLayout(new BoxLayout(pnlEncEnabled, BoxLayout.X_AXIS));
        pnlEncEnabled.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlEncEnabled.add(chkEncEnabled);
        pnlEncEnabled.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlEncEnabled);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));
        
        chkSigEnabled = new JCheckBox("Enable signing (UsernameToken or SAML)");
        JPanel pnlSigEnabled = new JPanel();
        pnlSigEnabled.setLayout(new BoxLayout(pnlSigEnabled, BoxLayout.X_AXIS));
        pnlSigEnabled.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlSigEnabled.add(chkSigEnabled);
        pnlSigEnabled.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlSigEnabled);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        chkSamlSigned = new JCheckBox("Sign SAML Token (SAML Only)");
        JPanel signedSAML = new JPanel();
        signedSAML.setLayout(new BoxLayout(signedSAML, BoxLayout.X_AXIS));
        signedSAML.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        signedSAML.add(chkSamlSigned);
        signedSAML.add(Box.createHorizontalGlue());

        pnlCardCenter.add(signedSAML);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));
        
        JPanel pnlSamlIssuer = new JPanel();
        pnlSamlIssuer.setLayout(new BoxLayout(pnlSamlIssuer, BoxLayout.X_AXIS));
        pnlSamlIssuer.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        lblSamlIssuer = new JLabel("SAML Issuer:");
        lblSamlIssuer.setDisplayedMnemonic('I');
        lblSamlIssuer.setLabelFor(txtfldSamlIssuer);
        String toolTip = "The issuer of the SAML Token. Must match P6 Admin Settings for WebServices/SAML Tokens/Issuer"; 
        lblSamlIssuer.setToolTipText(toolTip);
        txtfldSamlIssuer.setToolTipText(toolTip);
        
        pnlSamlIssuer.add(lblSamlIssuer);
        pnlSamlIssuer.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlSamlIssuer.add(txtfldSamlIssuer);
        pnlCardCenter.add(pnlSamlIssuer);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));
        
        JPanel pnlSamlButton = new JPanel();
        pnlSamlButton.setLayout(new BoxLayout(pnlSamlButton, BoxLayout.X_AXIS));
        btnSamlTokenDownload = new JButton("Download Saml Token..");
        btnSamlTokenDownload.setMnemonic('D');
        btnSamlTokenDownload.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                String tokenDownloadSuffix = "/p6ws/downloadtoken";
                String hostname = txtfldHostName.getText().trim();
                int port = Integer.parseInt(txtfldPort.getText());
                boolean bUseSSL = chkUseSSL.isSelected();
                String url = makeHttpURLString(hostname, port, tokenDownloadSuffix, bUseSSL);
                try
                {
                    openWebpage(new URL(url).toURI());
                }
                catch (Exception e1)
                {
                    JOptionPane.showMessageDialog(WSDemoWizardFrame.this, e1.getMessage(), ERROR_TITLE, JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        pnlSamlButton.add(btnSamlTokenDownload);
        pnlCardCenter.add(pnlSamlButton);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));
        
        JPanel pnlSamlFile = new JPanel();
        pnlSamlFile.setLayout(new BoxLayout(pnlSamlFile, BoxLayout.X_AXIS));
        pnlSamlFile.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        samlTokenFileLabel = new JLabel("SAML token file: ");
        samlTokenFileLabel.setDisplayedMnemonic('S');
        samlTokenFileLabel.setLabelFor(txtFieldSamlTokenFile);

        btnSamlTokenBrowse = new JButton("Browse...");
        btnSamlTokenBrowse.setMnemonic('B');
        btnSamlTokenBrowse.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                browseSamlTokenFileActionPerformed(e, txtFieldSamlTokenFile);
            }
        });

        
       
        
        pnlSamlFile.add(samlTokenFileLabel);
        pnlSamlFile.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlSamlFile.add(txtFieldSamlTokenFile);
        pnlSamlFile.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlSamlFile.add(btnSamlTokenBrowse);
        pnlCardCenter.add(pnlSamlFile);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));
        

       
        
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));
        pnlCardCenter.add(Box.createVerticalStrut(Integer.MAX_VALUE));
        

        pnlCards.add(pnlCardCenter, CARD_PROTECTION_TYPE);
    }

    
    private String makeHttpURLString(String hostname, int port, String suffix, boolean bUseSSL)
    {
        StringBuilder sb = new StringBuilder(bUseSSL ? HTTPS : HTTP);
        sb.append(hostname).append(":").append(port).append(suffix);

        return sb.toString();
    }
    
    private void initSAMLCard()
    {
        txtSamlKeystore = new JTextField();
        combSamlExtension = new JComboBox(new String[] {"JKS"});
        txtSamlKeystorePass = new JPasswordField();
        txtSamlAlias = new JTextField();
        txtSamlKeyPass = new JPasswordField();

        JPanel pnlCardCenter = new JPanel();
        pnlCardCenter.setBorder(s_defaultCardBorder);
        pnlCardCenter.setLayout(new BoxLayout(pnlCardCenter, BoxLayout.Y_AXIS));

        JPanel pnlSamlFile = new JPanel();
        pnlSamlFile.setLayout(new BoxLayout(pnlSamlFile, BoxLayout.X_AXIS));
        pnlSamlFile.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel keystoreFileLabel = new JLabel("SAML keystore file: ");
        keystoreFileLabel.setDisplayedMnemonic('K');
        keystoreFileLabel.setLabelFor(txtSamlKeystore);

        btnSamlBrowse = new JButton("Browse...");
        btnSamlBrowse.setMnemonic('B');
        btnSamlBrowse.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                browseEncryptionFileActionPerformed(e, txtSamlKeystore);
            }
        });

        pnlSamlFile.add(keystoreFileLabel);
        pnlSamlFile.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlSamlFile.add(txtSamlKeystore);
        pnlSamlFile.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlSamlFile.add(btnSamlBrowse);

        pnlCardCenter.add(pnlSamlFile);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlKeystoreExt = new JPanel();
        pnlKeystoreExt.setLayout(new BoxLayout(pnlKeystoreExt, BoxLayout.X_AXIS));
        pnlKeystoreExt.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel keystoreExtLabel = new JLabel("SAML keystore type: ");
        keystoreExtLabel.setDisplayedMnemonic('t');
        keystoreExtLabel.setLabelFor(combSamlExtension);

        combSamlExtension.setEditable(true);
        pnlKeystoreExt.add(keystoreExtLabel);
        pnlKeystoreExt.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlKeystoreExt.add(combSamlExtension);
        pnlKeystoreExt.add(Box.createHorizontalStrut(Integer.MAX_VALUE));
        pnlCardCenter.add(pnlKeystoreExt);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlKeystorePass = new JPanel();
        pnlKeystorePass.setLayout(new BoxLayout(pnlKeystorePass, BoxLayout.X_AXIS));
        pnlKeystorePass.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel keystorePassLabel = new JLabel("SAML keystore password: ");
        keystorePassLabel.setDisplayedMnemonic('p');
        keystorePassLabel.setLabelFor(txtSamlKeystorePass);

        pnlKeystorePass.add(keystorePassLabel);
        pnlKeystorePass.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlKeystorePass.add(txtSamlKeystorePass);

        pnlCardCenter.add(pnlKeystorePass);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlSamlAlias = new JPanel();
        pnlSamlAlias.setLayout(new BoxLayout(pnlSamlAlias, BoxLayout.X_AXIS));
        pnlSamlAlias.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel keyAliasLabel = new JLabel("SAML private key alias: ");
        keyAliasLabel.setDisplayedMnemonic('a');
        keyAliasLabel.setLabelFor(txtSamlAlias);

        pnlSamlAlias.add(keyAliasLabel);
        pnlSamlAlias.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlSamlAlias.add(txtSamlAlias);

        pnlCardCenter.add(pnlSamlAlias);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlKeyPass = new JPanel();
        pnlKeyPass.setLayout(new BoxLayout(pnlKeyPass, BoxLayout.X_AXIS));
        pnlKeyPass.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel keyPassLabel = new JLabel("SAML private key pass: ");
        keyPassLabel.setDisplayedMnemonic('r');
        keyPassLabel.setLabelFor(txtSamlKeyPass);

        pnlKeyPass.add(keyPassLabel);
        pnlKeyPass.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlKeyPass.add(txtSamlKeyPass);

        pnlCardCenter.add(pnlKeyPass);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        pnlCardCenter.add(Box.createVerticalStrut(Integer.MAX_VALUE));
        sizeUniformly(keystorePassLabel, new JComponent[]
            {
                keyAliasLabel, keyPassLabel, keystoreExtLabel, keystoreFileLabel
            });
        pnlCards.add(pnlCardCenter, CARD_SAML_TYPE);
    }

    private void initEncryptionInfoCard()
    {
        txtFieldEncFile = new JTextField();
        combEncExtension = new JComboBox(new String[] {"JKS"});
        txtFieldKeystorePass = new JPasswordField();
        txtFieldCertAlias = new JTextField();
        chkEncInbound = new JCheckBox("Inbound encryption enabled (or: outbound enabled on server)");

        JPanel pnlCardCenter = new JPanel();
        pnlCardCenter.setBorder(s_defaultCardBorder);
        pnlCardCenter.setLayout(new BoxLayout(pnlCardCenter, BoxLayout.Y_AXIS));

        JPanel pnlEncFile = new JPanel();
        pnlEncFile.setLayout(new BoxLayout(pnlEncFile, BoxLayout.X_AXIS));
        pnlEncFile.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel keystoreFileLabel = new JLabel("Keystore file: ");
        keystoreFileLabel.setDisplayedMnemonic('K');
        keystoreFileLabel.setLabelFor(txtFieldEncFile);
        btnEncBrowse = new JButton("Browse...");
        btnEncBrowse.setMnemonic('B');
        btnEncBrowse.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                browseEncryptionFileActionPerformed(e, txtFieldEncFile);
            }
        });

        pnlEncFile.add(keystoreFileLabel);
        pnlEncFile.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlEncFile.add(txtFieldEncFile);
        pnlEncFile.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlEncFile.add(btnEncBrowse);
        pnlCardCenter.add(pnlEncFile);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlKeystoreExt = new JPanel();
        pnlKeystoreExt.setLayout(new BoxLayout(pnlKeystoreExt, BoxLayout.X_AXIS));
        pnlKeystoreExt.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel keystoreExtLabel = new JLabel("Keystore type: ");
        keystoreExtLabel.setDisplayedMnemonic('t');
        keystoreExtLabel.setLabelFor(combEncExtension);
        combEncExtension.setEditable(true);
        pnlKeystoreExt.add(keystoreExtLabel);
        pnlKeystoreExt.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlKeystoreExt.add(combEncExtension);
        pnlKeystoreExt.add(Box.createHorizontalStrut(Integer.MAX_VALUE));
        pnlCardCenter.add(pnlKeystoreExt);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlKeystorePass = new JPanel();
        pnlKeystorePass.setLayout(new BoxLayout(pnlKeystorePass, BoxLayout.X_AXIS));
        pnlKeystorePass.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel keystorePassLabel = new JLabel("Keystore password: ");
        keystorePassLabel.setDisplayedMnemonic('p');
        keystorePassLabel.setLabelFor(txtFieldKeystorePass);
        pnlKeystorePass.add(keystorePassLabel);
        pnlKeystorePass.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlKeystorePass.add(txtFieldKeystorePass);
        pnlCardCenter.add(pnlKeystorePass);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlCertAlias = new JPanel();
        pnlCertAlias.setLayout(new BoxLayout(pnlCertAlias, BoxLayout.X_AXIS));
        pnlCertAlias.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel certAliasLabel = new JLabel("Certificate alias: ");
        certAliasLabel.setDisplayedMnemonic('C');
        certAliasLabel.setLabelFor(txtFieldCertAlias);
        pnlCertAlias.add(certAliasLabel);
        pnlCertAlias.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlCertAlias.add(txtFieldCertAlias);
        pnlCardCenter.add(pnlCertAlias);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlInboundEnabled = new JPanel();
        pnlInboundEnabled.setLayout(new BoxLayout(pnlInboundEnabled, BoxLayout.X_AXIS));
        pnlInboundEnabled.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlInboundEnabled.add(chkEncInbound);
        pnlInboundEnabled.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlInboundEnabled);

        pnlCardCenter.add(Box.createVerticalStrut(Integer.MAX_VALUE));
        sizeUniformly(keystorePassLabel, new JComponent[]
            {
                keystoreExtLabel, keystoreFileLabel, certAliasLabel
            });
        pnlCards.add(pnlCardCenter, CARD_ENCRYPTION_INFO);
    }

    private void initDemoInfoCard()
    {
        txtfldProjectId = new JTextField();
        chkPerformExport = new JCheckBox("Perform XML export");
        lblExportSaveTo = new JLabel(" Save to:");
        txtfldExportSaveTo = new JTextField();
        btnBrowse = new JButton("Browse...");
        chkAsync = new JCheckBox("Invoke asynchronously");
        btnBrowse.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    browsePerformExportActionPerformed(e);
                }
            });
        chkPerformExport.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    checkboxPerformExportActionPerformed(e);
                }
            });

        JPanel pnlCardCenter = new JPanel();
        pnlCardCenter.setBorder(s_defaultCardBorder);
        pnlCardCenter.setLayout(new BoxLayout(pnlCardCenter, BoxLayout.Y_AXIS));

        JPanel pnlProjectId = new JPanel();
        pnlProjectId.setLayout(new BoxLayout(pnlProjectId, BoxLayout.X_AXIS));
        pnlProjectId.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));

        JLabel lblProjectId = new JLabel(" Project Id:");
        lblProjectId.setDisplayedMnemonic('I');
        lblProjectId.setLabelFor(txtfldProjectId);
        pnlProjectId.add(lblProjectId);
        pnlProjectId.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlProjectId.add(txtfldProjectId);
        pnlCardCenter.add(pnlProjectId);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight * 2));

        JPanel pnlPerformExport = new JPanel();
        pnlPerformExport.setLayout(new BoxLayout(pnlPerformExport, BoxLayout.X_AXIS));
        chkPerformExport.setMnemonic('E');
        pnlPerformExport.add(chkPerformExport);
        pnlPerformExport.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlPerformExport);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlSaveTo = new JPanel();
        pnlSaveTo.setLayout(new BoxLayout(pnlSaveTo, BoxLayout.X_AXIS));
        pnlSaveTo.setMinimumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlSaveTo.add(Box.createHorizontalStrut(s_horizontalStrutWidth * 3));
        pnlSaveTo.add(lblExportSaveTo);
        lblExportSaveTo.setDisplayedMnemonic('t');
        lblExportSaveTo.setLabelFor(txtfldExportSaveTo);
        pnlSaveTo.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        pnlSaveTo.add(txtfldExportSaveTo);
        pnlSaveTo.add(Box.createHorizontalStrut(s_horizontalStrutWidth));
        btnBrowse.setMnemonic('r');
        pnlSaveTo.add(btnBrowse);
        pnlCardCenter.add(pnlSaveTo);
        pnlCardCenter.add(Box.createVerticalStrut(s_verticalStrutHeight));

        JPanel pnlAsync = new JPanel();
        pnlAsync.setLayout(new BoxLayout(pnlAsync, BoxLayout.X_AXIS));
        pnlAsync.add(Box.createHorizontalStrut(s_horizontalStrutWidth * 3));
        chkAsync.setMnemonic('a');
        pnlAsync.add(chkAsync);
        pnlAsync.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlAsync);
        pnlCardCenter.add(Box.createVerticalStrut(Integer.MAX_VALUE));
        pnlCards.add(pnlCardCenter, CARD_DEMO_INFO);
    }

    private void initStatusCard()
    {
        txtareaStatus = new JTextArea();

        JPanel pnlCardCenter = new JPanel();
        pnlCardCenter.setBorder(s_defaultCardBorder);
        pnlCardCenter.setLayout(new BoxLayout(pnlCardCenter, BoxLayout.Y_AXIS));

        JPanel pnlStatus = new JPanel();
        pnlStatus.setLayout(new BoxLayout(pnlStatus, BoxLayout.X_AXIS));
        pnlStatus.setMaximumSize(new Dimension(Integer.MAX_VALUE, s_pnlMinimumHeight));
        pnlStatus.add(new JLabel("Status:"));
        pnlStatus.add(Box.createHorizontalGlue());
        pnlCardCenter.add(pnlStatus);
        pnlCardCenter.add(Box.createVerticalStrut(5));
        txtareaStatus.setEditable(false);

        JScrollPane scrollPane = new JScrollPane(txtareaStatus);
        txtareaStatus.setAutoscrolls(true);
        scrollPane.setAutoscrolls(true);
        pnlCardCenter.add(scrollPane);
        m_progressStream = new PrintStream(new TextAreaOutputStream(txtareaStatus));
        pnlCards.add(pnlCardCenter, CARD_STATUS);
    }

    private void showCard(int iCard)
    {
        btnBack.setText("Back");
        if (iCard == DEMO_CARD)
        {
            btnNext.setText("Start");
            btnNext.setMnemonic('S');
        }
        else if (iCard == STATUS_CARD)
        {
            btnNext.setText("Finish");
            btnNext.setMnemonic('F');
        }
        else
        {
            btnNext.setText("Next");
            btnNext.setMnemonic('N');
        }

        if (iCard == PROTECTION_CARD)
        {
            if (rdbtnAuthTypeToken.isSelected())
            {
                chkSamlSigned.setEnabled(false);
                txtfldSamlIssuer.setEnabled(false);
                lblSamlIssuer.setEnabled(false);
                
                btnSamlTokenBrowse.setEnabled(false);
                txtFieldSamlTokenFile.setEnabled(false);
                samlTokenFileLabel.setEnabled(false);
                
                btnSamlTokenDownload.setEnabled(false);
                
            }
            else if(rbtnAuthTypeSAML20.isSelected())
            {
                chkSamlSigned.setEnabled(false);
                txtfldSamlIssuer.setEnabled(false);
                lblSamlIssuer.setEnabled(false);
                
                btnSamlTokenBrowse.setEnabled(true);
                txtFieldSamlTokenFile.setEnabled(true);
                samlTokenFileLabel.setEnabled(true);
                
                chkSamlSigned.setSelected(true);
                
                btnSamlTokenDownload.setEnabled(true);
            }
            else
            {
                chkSamlSigned.setEnabled(true);
                txtfldSamlIssuer.setEnabled(true);
                lblSamlIssuer.setEnabled(true);
                
                btnSamlTokenBrowse.setEnabled(false);
                txtFieldSamlTokenFile.setEnabled(false);
                samlTokenFileLabel.setEnabled(false);
                
                btnSamlTokenDownload.setEnabled(false);
                
            }
        }

        CardLayout cl = (CardLayout)(pnlCards.getLayout());
        cl.show(pnlCards, cards.get(iCard));
    }

    private void setAuthenticationType(int authMode)
    {
        if (authMode == WSDemo.USERNAME_TOKEN_MODE)
        {
            rdbtnAuthTypeToken.setSelected(true);
        }
        else if (authMode == WSDemo.SAML_11_MODE)
        {
            rbtnAuthTypeSAML11.setSelected(true);
        }
        else if (authMode == WSDemo.SAML_20_MODE)
        {
            rbtnAuthTypeSAML20.setSelected(true);
        }
        else
        {
            rdbtnAuthTypeCookie.setSelected(true);
        }
    }

    private int getAuthenticationType()
    {
        if (rdbtnAuthTypeToken.isSelected())
        {
            return WSDemo.USERNAME_TOKEN_MODE;
        }
        else if (rdbtnAuthTypeCookie.isSelected())
        {
            return WSDemo.COOKIE_MODE;
        }
        else if (rbtnAuthTypeSAML11.isSelected())
        {
            return WSDemo.SAML_11_MODE;
        }
        else
        {
            return WSDemo.SAML_20_MODE;
        }
    }

    private void setPerformExport(boolean flag)
    {
        lblExportSaveTo.setEnabled(flag);
        chkAsync.setEnabled(flag);
        txtfldExportSaveTo.setEnabled(flag);
        btnBrowse.setEnabled(flag);
    }

    private static void sizeUniformly(JComponent mainComponent, JComponent[] otherComponents)
    {
        Dimension dim = mainComponent.getPreferredSize();

        for (int i = 0; i < otherComponents.length; i++)
        {
            JComponent comp = otherComponents[i];
            comp.setMinimumSize(dim);
            comp.setMaximumSize(dim);
            comp.setPreferredSize(dim);
        }
    }

    private void backButtonActionPerformed(ActionEvent e)
    {
        if (iCurrentCard == DEMO_CARD)
        {
            if (rdbtnAuthTypeCookie.isSelected())
            {
                iCurrentCard -= 3;
            }
            else if((rbtnAuthTypeSAML20.isSelected()) && (!chkEncEnabled.isSelected() && !chkSigEnabled.isSelected()))
            {
                iCurrentCard -= 2;
            }
            else if((rbtnAuthTypeSAML20.isSelected()) && (chkEncEnabled.isSelected() || chkSigEnabled.isSelected()))
            {
                iCurrentCard--;
                showCard(iCurrentCard);
                return;
            }
            else if (!chkEncEnabled.isSelected() && !chkSigEnabled.isSelected())
            {
                iCurrentCard--;

                if (!chkSamlSigned.isSelected() || rdbtnAuthTypeToken.isSelected())
                {
                    iCurrentCard--;
                }
            }
        }
        else if (iCurrentCard == ENCRYPTION_CARD)
        {
            if((rbtnAuthTypeSAML20.isSelected()))
            {
                iCurrentCard--;
            }
            if (!chkSamlSigned.isSelected() || rdbtnAuthTypeToken.isSelected())
            {
                iCurrentCard--;
            }
        }
        else if (iCurrentCard == AUTHENTICATION_CARD)
        {
            btnBack.setEnabled(false);
        }

        iCurrentCard--;
        showCard(iCurrentCard);
    }

    private void nextButtonActionPerformed(ActionEvent e)
    {
        if (iCurrentCard == CONNECTION_CARD)
        {
            try
            {
                validateConnectionInfo();
            }
            catch (Exception ex)
            {
                JOptionPane.showMessageDialog(this, ex.getMessage(), ERROR_TITLE, JOptionPane.ERROR_MESSAGE);

                return;
            }

            btnBack.setEnabled(true);
        }
        else if (iCurrentCard == AUTHENTICATION_CARD)
        {
            if (rdbtnAuthTypeCookie.isSelected())
            {
                iCurrentCard += 3;
            }
        }
        else if (iCurrentCard == PROTECTION_CARD)
        {
            if ((chkEncEnabled.isSelected() || chkSigEnabled.isSelected()) && (!chkSamlSigned.isSelected() || rdbtnAuthTypeToken.isSelected()))
            {
               iCurrentCard++;
            }
            else if ((!chkEncEnabled.isSelected() || !chkSigEnabled.isSelected()) && (!chkSamlSigned.isSelected() || rdbtnAuthTypeToken.isSelected()))
            {
                iCurrentCard += 2;
            }
            else if((rbtnAuthTypeSAML20.isSelected()) && (!chkEncEnabled.isSelected() && !chkSigEnabled.isSelected()))
            {
                iCurrentCard+= 2;
            }
            else if((rbtnAuthTypeSAML20.isSelected()) && (chkEncEnabled.isSelected() || chkSigEnabled.isSelected()))
            {
                iCurrentCard++;
            }
        }
        else if (iCurrentCard == SAML_CARD)
        {
            try
            {
                validateSAMLSigningInfo();
            }
            catch (Exception ex)
            {
                JOptionPane.showMessageDialog(this, ex.getMessage(), ERROR_TITLE, JOptionPane.ERROR_MESSAGE);

                return;
            }

            if (!chkEncEnabled.isSelected() && !chkSigEnabled.isSelected())
            {
                iCurrentCard += 1;
            }
        }
        else if (iCurrentCard == ENCRYPTION_CARD)
        {
            try
            {
                validateEncryptionInfo();
            }
            catch (Exception ex)
            {
                JOptionPane.showMessageDialog(this, ex.getMessage(), ERROR_TITLE, JOptionPane.ERROR_MESSAGE);

                return;
            }
        }
        else if (iCurrentCard == DEMO_CARD)
        {
            try
            {
                validateDemoInfo();

                WSDemo.DemoInfo demoInfo = getDemoInfo();
                demoInfo.saveToPropertiesFile();
            }
            catch (Exception ex)
            {
                JOptionPane.showMessageDialog(this, ex.getMessage(), ERROR_TITLE, JOptionPane.ERROR_MESSAGE);

                return;
            }

            btnNext.setEnabled(false);
            btnBack.setEnabled(false);
            txtareaStatus.setText("");

            final PrintStream ps = m_progressStream;
            new Thread()
                {
                    @Override
                    public void run()
                    {
                        ps.println(" ----------------------------- ");
                        ps.println(" -- Begin WS Demo -- ");
                        ps.println(" ----------------------------- ");
                        ps.println();

                        WSDemo.DemoInfo demoInfo = getDemoInfo();
                        WSDemo demo = new WSDemo(demoInfo, ps);
                        demo.run();
                        btnNext.setEnabled(true);
                        btnBack.setEnabled(true);
                        btnCancel.setEnabled(false);

                        ps.println();
                        ps.println(" ----------------------------- ");
                        ps.println(" --- End WS Demo --- ");
                        ps.println(" ----------------------------- ");
                        ps.println();
                    }
                }.start();
        }
        else if (iCurrentCard == STATUS_CARD)
        {
            System.exit(0);
        }

        iCurrentCard++;
        showCard(iCurrentCard);
    }

    private void cancelButtonActionPerformed(ActionEvent e)
    {
        System.exit(0);
    }

    private void browseEncryptionFileActionPerformed(ActionEvent e, JTextField targetField)
    {
        JFileChooser fc = new JFileChooser(getDirectory(txtFieldEncFile.getText()));
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fc.setSelectedFile(new File(targetField.getText()));

        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION)
        {
            String filepath = fc.getSelectedFile().getAbsolutePath();
            targetField.setText(filepath);
        }
    }
    
    
    private void browseSamlTokenFileActionPerformed(ActionEvent e, JTextField targetField)
    {
        JFileChooser fc = new JFileChooser(getDirectory(txtFieldSamlTokenFile.getText()));
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fc.setSelectedFile(new File(targetField.getText()));
        
        
        FileFilter xmlFileFilter = new FileFilter()
        {
            @Override
            public boolean accept(File f)
            {
                final String filename = f.getAbsolutePath();

                return (f.isDirectory() || filename.endsWith(WSDemo.XML));
                
            }

            @Override
            public String getDescription()
            {
                return "XML File (.xml)";
            }
        };
        fc.addChoosableFileFilter(xmlFileFilter);
        fc.setFileFilter(xmlFileFilter);

        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION)
        {
            String filepath = fc.getSelectedFile().getAbsolutePath();
            targetField.setText(filepath);
        }
    }

    private void browsePerformExportActionPerformed(ActionEvent e)
    {
        JFileChooser fc = new JFileChooser(getDirectory(txtfldExportSaveTo.getText()));
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fc.setSelectedFile(new File(txtfldExportSaveTo.getText()));

        FileFilter xmlFileFilter = new FileFilter()
        {
            @Override
            public boolean accept(File f)
            {
                final String filename = f.getAbsolutePath();

                if (f.isDirectory() || filename.endsWith(WSDemo.XML))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }

            @Override
            public String getDescription()
            {
                return "XML File (.xml)";
            }
        };

        FileFilter zipFileFilter = new FileFilter()
        {
            @Override
            public boolean accept(File f)
            {
                final String filename = f.getAbsolutePath();

                if (f.isDirectory() || filename.endsWith(WSDemo.ZIP))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }

            @Override
            public String getDescription()
            {
                return "ZIP File (.zip)";
            }
        };

        FileFilter gzipFileFilter = new FileFilter()
        {
            @Override
            public boolean accept(File f)
            {
                final String filename = f.getAbsolutePath();

                if (f.isDirectory() || filename.endsWith(WSDemo.GZIP))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }

            @Override
            public String getDescription()
            {
                return "GZIP File (.gz)";
            }
        };

        fc.addChoosableFileFilter(xmlFileFilter);
        fc.addChoosableFileFilter(zipFileFilter);
        fc.addChoosableFileFilter(gzipFileFilter);
        fc.setFileFilter(xmlFileFilter);

        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION)
        {
            String filepath = fc.getSelectedFile().getAbsolutePath();

            if (fc.getFileFilter() == xmlFileFilter)
            {
                if (!filepath.endsWith(WSDemo.XML))
                {
                    filepath = filepath + WSDemo.XML;
                }
            }
            else if (fc.getFileFilter() == zipFileFilter)
            {
                if (!filepath.endsWith(WSDemo.ZIP))
                {
                    filepath = filepath + WSDemo.ZIP;
                }
            }
            else if (fc.getFileFilter() == gzipFileFilter)
            {
                if (!filepath.endsWith(WSDemo.GZIP))
                {
                    filepath = filepath + WSDemo.GZIP;
                }
            }

            txtfldExportSaveTo.setText(filepath);
        }
    }

    private void checkboxPerformExportActionPerformed(ActionEvent e)
    {
        boolean flag = chkPerformExport.isSelected();
        setPerformExport(flag);
    }

    private void setDefaultDemoInfo()
    {
        WSDemo.DemoInfo defaultInfo = WSDemo.DemoInfo.DEFAULT_INFO;
        txtfldUserName.setText(defaultInfo.username);
        txtfldPassword.setText(defaultInfo.password);
        txtfldHostName.setText(defaultInfo.hostname);
        txtfldPort.setText(Integer.toString(defaultInfo.port));
        chkUseSSL.setSelected(defaultInfo.bUseSSL);
        txtfldProjectId.setText(defaultInfo.projectId);
        setAuthenticationType(defaultInfo.authMode);
        chkPerformExport.setSelected(defaultInfo.bPerformExport);
        setPerformExport(defaultInfo.bPerformExport);
        txtFieldEncFile.setText("keystore.jks");
        txtFieldCertAlias.setText(defaultInfo.certAlias);
        txtFieldKeystorePass.setText(defaultInfo.keystorePass);
        chkEncInbound.setSelected(defaultInfo.encInbound);
        chkEncEnabled.setSelected(defaultInfo.encEnabled);
        chkSigEnabled.setSelected(defaultInfo.sigEnabled);

        chkSamlSigned.setSelected(defaultInfo.samlSigned);
        txtSamlKeystore.setText("keystore.jks");
        txtSamlAlias.setText(defaultInfo.samlAlias);
        txtSamlKeystorePass.setText(defaultInfo.samlKeystorepass);
        txtSamlKeyPass.setText(defaultInfo.samlKeypass);
        this.txtfldSamlIssuer.setText(defaultInfo.samlIssuer);

        if (defaultInfo.saveTo != null)
        {
            txtfldExportSaveTo.setText(defaultInfo.saveTo.getAbsolutePath());
        }

        chkAsync.setSelected(defaultInfo.bAsync);
    }

    private WSDemo.DemoInfo getDemoInfo()
    {
        String username = txtfldUserName.getText().trim();
        String password = new String(txtfldPassword.getPassword());
        String hostname = txtfldHostName.getText().trim();
        int port = Integer.parseInt(txtfldPort.getText());
        boolean bUseSSL = chkUseSSL.isSelected();
        String projectId = txtfldProjectId.getText().trim();
        boolean bPerformExport = chkPerformExport.isSelected();
        File saveTo = null;
        String filePath = txtfldExportSaveTo.getText().trim();
        boolean encEnabled = chkEncEnabled.isSelected();
        boolean sigEnabled = chkSigEnabled.isSelected();
        File keystore = null;
        String keystorePath = txtFieldEncFile.getText().trim();
        String samlTokenPath = txtFieldSamlTokenFile.getText().trim();


        if ((filePath != null) && (filePath.length() > 0))
        {
            saveTo = new File(filePath);
        }

        if ((keystorePath != null) && (keystorePath.length() > 0))
        {
            keystore = new File(keystorePath);
        }

        boolean bAsync = chkAsync.isSelected();
        String keystoreType = combEncExtension.getSelectedItem().toString().trim();
        String keystorePass = new String(txtFieldKeystorePass.getPassword());
        String certAlias = txtFieldCertAlias.getText().trim();
        boolean encInbound = chkEncInbound.isSelected();

        int authMode = getAuthenticationType();

        boolean samlSigned = chkSamlSigned.isSelected();

        File samlKeystore = new File(txtSamlKeystore.getText());
        String samlKeystoreType = combSamlExtension.getSelectedItem().toString().trim();
        String samlAlias = txtSamlAlias.getText();
        String samlKeystorePass = new String(txtSamlKeystorePass.getPassword());
        String samlKeyPass = new String(txtSamlKeyPass.getPassword());

        WSDemo.DemoInfo demoInfo = new WSDemo.DemoInfo();

        demoInfo.username = username;
        demoInfo.password = password;
        demoInfo.hostname = hostname;
        demoInfo.port = port;
        demoInfo.projectId = projectId;
        demoInfo.bPerformExport = bPerformExport;
        demoInfo.saveTo = saveTo;
        demoInfo.bAsync = bAsync;
        demoInfo.encEnabled = encEnabled;
        demoInfo.sigEnabled = sigEnabled;
        demoInfo.keystore = keystore;
        demoInfo.keystoreType = keystoreType;
        demoInfo.keystorePass = keystorePass;
        demoInfo.certAlias = certAlias;
        demoInfo.encInbound = encInbound;
        demoInfo.authMode = authMode;
        demoInfo.samlSigned = samlSigned;
        demoInfo.samlKeystore = samlKeystore;
        demoInfo.samlKeystoreType = samlKeystoreType;
        demoInfo.samlKeystorepass = samlKeystorePass;
        demoInfo.samlKeypass = samlKeyPass;
        demoInfo.samlAlias = samlAlias;
        demoInfo.bUseSSL = bUseSSL;
        demoInfo.samlIssuer = this.txtfldSamlIssuer.getText().trim();
        demoInfo.samlTokenPath = samlTokenPath;

        return demoInfo;
    }

    private void validateConnectionInfo()
      throws Exception
    {
        String username = txtfldUserName.getText().trim();

        if (username.length() == 0)
        {
            throw new Exception("User name may not be empty.");
        }

        String hostname = txtfldHostName.getText().trim();

        if (hostname.length() == 0)
        {
            throw new Exception("Host name may not be empty.");
        }

        try
        {
            int port = Integer.parseInt(txtfldPort.getText());

            if ((port < 0) || (port > 65535))
            {
                throw new Exception("Port should be a valid integer between 0 and 65535.");
            }
        }
        catch (NumberFormatException e)
        {
            throw new Exception("Port should be a valid number between 0 and 65535.");
        }
    }

    private void validateSAMLSigningInfo()
      throws Exception
    {
        String keystorePath = txtSamlKeystore.getText().trim();
        File keystoreFile = new File(keystorePath);

        if (!keystoreFile.exists())
        {
            throw new Exception("The specified keystore file does not exist.\n\nEnsure that you are specifying a valid path and filename for the keystore.");
        }

        String keystoreType = combSamlExtension.getSelectedItem().toString().trim();
        KeyStore keyStore = null;
        
        try
        {
            keyStore = KeyStore.getInstance(keystoreType);
        }
        catch (Exception e)
        {
            throw new Exception("The system is not able to load the keystore file.\n\nEnsure that the certificate is a valid Java keystore (jks) type file.", e);
        }

        try
        {
            keyStore.load(new FileInputStream(keystoreFile), txtSamlKeystorePass.getPassword());
        }
        catch (Exception e)
        {
            throw new Exception("The system cannot load the keystore.\n\nEnsure that you are specifying a valid password.", e);
        }

        Certificate cert = keyStore.getCertificate(txtSamlAlias.getText().trim());

        if (cert == null)
        {
            throw new Exception("The system cannot load the digital certificate for the specified alias.\n\nEnsure that the alias and digital certificate are valid.");
        }

        try 
        {
            Key key = keyStore.getKey(txtSamlAlias.getText().trim(), txtSamlKeyPass.getPassword());

            if (!(key instanceof PrivateKey))
            {
                throw new Exception("The key found in the file was not a private key.");
            }
        }
        catch (Exception e)
        {
            throw new Exception("The system cannot process the private key in the keystore.\n\nEnsure that you have specified a keystore that contains the appropriate public/private key pair and that you have specified the valid private key password. ", e);
        }
    }

    private void validateEncryptionInfo()
      throws Exception
    {
        String keystorePath = txtFieldEncFile.getText().trim();
        File keystoreFile = new File(keystorePath);

        if (!keystoreFile.exists())
        {
            throw new Exception("The specified keystore file does not exist.\n\nEnsure that you are specifying a valid path and filename for the keystore.");
        }

        String keystoreType = combEncExtension.getSelectedItem().toString().trim();
        KeyStore keyStore = null;

        try
        {
            keyStore = KeyStore.getInstance(keystoreType);
        }
        catch (Exception e)
        {
            throw new Exception("The system is not able to load the keystore file.\n\nEnsure that the certificate is a valid Java keystore (jks) type file.", e);
        }

        try
        {
            keyStore.load(new FileInputStream(keystoreFile), txtFieldKeystorePass.getPassword());
        }
        catch (Exception e)
        {
            throw new Exception("The system cannot load the keystore.\n\nEnsure that you are specifying a valid password.", e);
        }

        Certificate cert = keyStore.getCertificate(txtFieldCertAlias.getText().trim());

        if (cert == null)
        {
            throw new Exception("The system cannot load the digital certificate for the specified alias.\n\nEnsure that the alias and digital certificate are valid.");
        }
    }

    private void validateDemoInfo()
      throws Exception
    {
        String projectId = txtfldProjectId.getText().trim();

        if (projectId.length() == 0)
        {
            throw new Exception("Project Id may not be empty.");
        }

        if (chkPerformExport.isSelected())
        {
            String filepath = txtfldExportSaveTo.getText().trim();

            if (filepath.length() == 0)
            {
                throw new Exception("Please specify a valid file name.");
            }

            File file = new File(filepath);

            if (file.exists() && file.isDirectory())
            {
                throw new Exception("Please specify a valid file name.");
            }
        }
    }

    private File getDirectory(String filepath)
    {
        try
        {
            int idx = Math.max(filepath.lastIndexOf('/'), filepath.lastIndexOf('\\'));
            String sDir = filepath.substring(0, idx);
            File dir = new File(sDir);

            if (dir.exists() && dir.isDirectory())
            {
                return dir;
            }
            else
            {
                return null;
            }
        }
        catch (Exception e)
        {
            return null;
        }
    }

    //~ Inner Classes ------------------------------------------------------------------------------

    public static class TextAreaOutputStream
      extends OutputStream
    {
        //~ Instance fields ------------------------------------------------------------------------

        private final JTextArea txtarea;

        //~ Constructors ---------------------------------------------------------------------------

        public TextAreaOutputStream(JTextArea txtarea)
        {
            this.txtarea = txtarea;
        }

        //~ Methods --------------------------------------------------------------------------------

        @Override
        public void write(int b)
          throws IOException
        {
            byte[] bs = new byte[1];
            bs[0] = (byte)b;
            txtarea.append(new String(bs));
            txtarea.setCaretPosition(txtarea.getText().length());
        }
    }
    
    
    public static void openWebpage(URI uri) throws Exception {
        Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
        if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
            try {
                desktop.browse(uri);
            } catch (Exception e) {
                throw new Exception("failed to launch web browser");
            }
        }
    }

}
