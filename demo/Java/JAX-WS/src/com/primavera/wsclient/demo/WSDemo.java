package com.primavera.wsclient.demo;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Future;

import javax.activation.DataHandler;
import javax.swing.WindowConstants;
import javax.xml.ws.AsyncHandler;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Response;
import javax.xml.ws.soap.SOAPBinding;

import org.apache.cxf.binding.soap.saaj.SAAJInInterceptor;
import org.apache.cxf.binding.soap.saaj.SAAJOutInterceptor;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;

import com.primavera.ws.p6.activity.Activity;
import com.primavera.ws.p6.activity.ActivityPortType;
import com.primavera.ws.p6.activity.ActivityService;
import com.primavera.ws.p6.authentication.AuthenticationService;
import com.primavera.ws.p6.authentication.AuthenticationServicePortType;
import com.primavera.ws.p6.eps.EPS;
import com.primavera.ws.p6.eps.EPSFieldType;
import com.primavera.ws.p6.eps.EPSPortType;
import com.primavera.ws.p6.eps.EPSService;
import com.primavera.ws.p6.export.ExportPortType;
import com.primavera.ws.p6.export.ExportProjectResponse;
import com.primavera.ws.p6.export.ExportService;
import com.primavera.ws.p6.export.FileTypeType;
import com.primavera.ws.p6.project.Project;
import com.primavera.ws.p6.project.ProjectFieldType;
import com.primavera.ws.p6.project.ProjectPortType;
import com.primavera.ws.p6.project.ProjectService;
import com.primavera.ws.p6.schemas.integrationfaulttype.IntegrationFaultType;

public class WSDemo
{
    //~ Static fields/initializers -----------------------------------------------------------------

    private static final String AUTHENTICATION_SERVICE = "/p6ws/services/AuthenticationService?wsdl";
    private static final String PROJECT_SERVICE = "/p6ws/services/ProjectService?wsdl";
    private static final String EPS_SERVICE = "/p6ws/services/EPSService?wsdl";
    private static final String ACTIVITY_SERVICE = "/p6ws/services/ActivityService?wsdl";
    private static final String EXPORT_SERVICE = "/p6ws/services/ExportService?wsdl";
    private static final String HTTP = "HTTP://";
    private static final String HTTPS = "HTTPS://";
    static final String XML = ".xml";
    static final String ZIP = ".zip";
    static final String GZIP = ".gz";

    //~ Instance fields ----------------------------------------------------------------------------

    private List<String> m_cookieHeaders = null;
    private final DemoInfo m_demoInfo;
    private final PrintStream m_ps;

    //~ Constructors -------------------------------------------------------------------------------

    public WSDemo(DemoInfo demoInfo, PrintStream ps)
    {
        if (demoInfo == null)
        {
            m_demoInfo = DemoInfo.DEFAULT_INFO;
        }
        else
        {
            m_demoInfo = demoInfo;
        }

        m_ps = ps;
    }

    //~ Methods ------------------------------------------------------------------------------------

    public static void main(String[] args)
    {
        WSDemoWizardFrame jf = new WSDemoWizardFrame();
        jf.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        jf.setVisible(true);
    }

    void run()
    {
        try
        {
            // Login if using cookie for session management
            if (m_demoInfo.authMode == COOKIE_MODE)
            {
                m_ps.println("Logging in as user: " + m_demoInfo.username + "...");

                if (login())
                {
                    m_ps.println("Logged in successfully.");
                }
                else
                {
                    m_ps.println("Login failed.");

                    return;
                }
            }

            // Delete project with provided ProjectId if it already exists
            m_ps.println("Checking if project " + m_demoInfo.projectId + " exists in the database...");

            int existingProjectObjectId = readProject();

            if (existingProjectObjectId > 0)
            {
                m_ps.println("Deleting project " + m_demoInfo.projectId + ".");
                deleteProject(existingProjectObjectId);
            }
            else
            {
                m_ps.println("Project " + m_demoInfo.projectId + " does not exist in the database.");
            }

            // Read root EPS, user needs to have access to root EPS
            m_ps.println("Reading the root EPS...");

            int epsObjectId = readEPS();

            if (epsObjectId == 0)
            {
                m_ps.println("No EPS node is available.");

                return;
            }

            // Create a project on root EPS
            m_ps.println("Creating project " + m_demoInfo.projectId + "...");

            int createdProjectObjectId = createProject(epsObjectId);
            m_ps.println("Project " + createdProjectObjectId + " created.");

            // Create activities under the project
            m_ps.println("Creating activities under project " + m_demoInfo.projectId + "...");

            List<Integer> actList = createActivities(createdProjectObjectId);
            m_ps.println("Activities " + actList + " were created.");

            // Export optionally
            if (m_demoInfo.bPerformExport)
            {
                m_ps.println("Exporting project " + m_demoInfo.projectId + ".");
                exportProject(createdProjectObjectId);
                m_ps.println("Project was successfully exported to file: " + m_demoInfo.saveTo + ".");
            }

            // Delete created project
            m_ps.println("Deleting project " + m_demoInfo.projectId + "...");
            deleteProject(createdProjectObjectId);
            m_ps.println("Project deleted.");

            // Logout if using cookie
            if (m_demoInfo.authMode == COOKIE_MODE)
            {
                m_ps.println("Logging out.");
                logout();
                m_ps.println("Logged out successfully.");
            }

            m_ps.println("Demo completed successfully.");
        }
        catch (Exception e)
        {
            m_ps.println();

            try
            {
                IntegrationFaultType ift = getIntegrationFaultType(e);

                if (ift == null)
                {
                    m_ps.println("Demo failed because of the following error:");
                    m_ps.println(e.getMessage());
                    e.printStackTrace();
                }
                else
                {
                    String errorDesc = ift.getErrorDescription();
                    m_ps.println("Demo failed because of the following error:");
                    m_ps.println(errorDesc);
                    e.printStackTrace();
                }
            }
            catch (Exception ex)
            {
                m_ps.println("Demo failed. Please check if the server is running and try again.");
                ex.printStackTrace();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private boolean login()
      throws Exception
    {
        String url = makeHttpURLString(m_demoInfo.hostname, m_demoInfo.port, AUTHENTICATION_SERVICE, m_demoInfo.bUseSSL);
        URL wsdlURL = new URL(url);
        AuthenticationService service = new AuthenticationService(wsdlURL);
        AuthenticationServicePortType servicePort = service.getAuthenticationServiceSOAP12PortHttp();
        BindingProvider bp = (BindingProvider)servicePort;
        bp.getRequestContext().put(BindingProvider.SESSION_MAINTAIN_PROPERTY, true);

        // Login with user name and password, using database instance 1, and verbose faults
        Boolean retVal = servicePort.login(m_demoInfo.username, m_demoInfo.password, 1);
        Map<String,Object> responseContext = bp.getResponseContext();
        System.out.println(responseContext);


        // Cookie must be used in all subsequent calls
        Map<String,List<String>> responseHeaders = (Map<String,List<String>>)responseContext.get("javax.xml.ws.http.response.headers");
        System.out.println(responseHeaders.get("Set-Cookie").size());
        m_cookieHeaders = responseHeaders.get("Set-Cookie");

        return retVal.booleanValue();
    }

    private void logout()
      throws Exception
    {
        String url = makeHttpURLString(m_demoInfo.hostname, m_demoInfo.port, AUTHENTICATION_SERVICE, m_demoInfo.bUseSSL);
        URL wsdlURL = new URL(url);
        AuthenticationService service = new AuthenticationService(wsdlURL);
        AuthenticationServicePortType servicePort = service.getAuthenticationServiceSOAP12PortHttp();
        Client client = ClientProxy.getClient(servicePort);
        setCookieOrUserTokenData(client);
        servicePort.logout("");
    }

    private int readEPS()
      throws Exception
    {
        String url = makeHttpURLString(m_demoInfo.hostname, m_demoInfo.port, EPS_SERVICE, m_demoInfo.bUseSSL);
        URL wsdlURL = new URL(url);
        EPSService service = new EPSService(wsdlURL);
        EPSPortType servicePort = service.getEPSPort();
        Client client = ClientProxy.getClient(servicePort);
        setCookieOrUserTokenData(client);

        List<EPSFieldType> epsFields = new ArrayList<EPSFieldType>();
        epsFields.add(EPSFieldType.OBJECT_ID);
        epsFields.add(EPSFieldType.ID);
        epsFields.add(EPSFieldType.NAME);


        // ParentObjectId will be null for all root level EPS
        List<EPS> EPSs = servicePort.readEPS(epsFields, "ParentObjectId is null", null);

        if ((EPSs == null) || (EPSs.size() == 0))
        {
            System.out.println("No EPS node available");

            return 0;
        }
        else
        {
            return EPSs.get(0).getObjectId().intValue();
        }
    }

    private int createProject(int epsObjectId)
      throws Exception
    {
        ProjectPortType servicePort = createProjectServicePort(m_demoInfo.hostname, m_demoInfo.port);
        List<Project> projects = new ArrayList<Project>();

        // Create project with required fields
        Project proj = new Project();
        proj.setParentEPSObjectId(Integer.valueOf(epsObjectId));
        proj.setId(m_demoInfo.projectId);
        proj.setName(m_demoInfo.projectId);
        projects.add(proj);

        List<Integer> objIds = servicePort.createProjects(projects);
        System.out.println(objIds.size() + " Project created:");

        return objIds.get(0).intValue();
    }

    private int readProject()
      throws Exception
    {
        ProjectPortType servicePort = createProjectServicePort(m_demoInfo.hostname, m_demoInfo.port);
        List<ProjectFieldType> fields = new ArrayList<ProjectFieldType>();
        fields.add(ProjectFieldType.OBJECT_ID);


        // Load project with specific Id
        List<Project> projects = servicePort.readProjects(fields, "Id = '" + m_demoInfo.projectId + "'", null);

        if ((projects == null) || (projects.size() == 0))
        {
            return 0;
        }

        return projects.get(0).getObjectId().intValue();
    }

    private void deleteProject(int projectObjectId)
      throws Exception
    {
        ProjectPortType servicePort = createProjectServicePort(m_demoInfo.hostname, m_demoInfo.port);
        List<Integer> delIds = new ArrayList<Integer>();
        delIds.add(Integer.valueOf(projectObjectId));
        servicePort.deleteProjects(delIds);
    }

    private ProjectPortType createProjectServicePort(String hostname, int port)
      throws Exception
    {
        String url = makeHttpURLString(hostname, port, PROJECT_SERVICE, m_demoInfo.bUseSSL);
        URL wsdlURL = new URL(url);
        ProjectService service = new ProjectService(wsdlURL);
        ProjectPortType servicePort = service.getProjectPort();
        Client client = ClientProxy.getClient(servicePort);
        setCookieOrUserTokenData(client);

        return servicePort;
    }

    private List<Integer> createActivities(int projectObjectId)
      throws Exception
    {
        String url = makeHttpURLString(m_demoInfo.hostname, m_demoInfo.port, ACTIVITY_SERVICE, m_demoInfo.bUseSSL);
        URL wsdlURL = new URL(url);
        ActivityService service = new ActivityService(wsdlURL);
        ActivityPortType servicePort = service.getActivityPort();
        Client client = ClientProxy.getClient(servicePort);
        setCookieOrUserTokenData(client);

        List<Activity> activities = new ArrayList<Activity>();

        for (int i = 1; i <= 3; i++)
        {
            Activity act = new Activity();
            act.setProjectObjectId(Integer.valueOf(projectObjectId));
            act.setId("TestAct" + i);
            act.setName("Test Activity " + i);
            activities.add(act);
        }

        List<Integer> objIds = servicePort.createActivities(activities);

        return objIds;
    }

    private void exportProject(int projectObjectId)
      throws Exception
    {
        String url = makeHttpURLString(m_demoInfo.hostname, m_demoInfo.port, EXPORT_SERVICE, m_demoInfo.bUseSSL);
        URL wsdlURL = new URL(url);
        ExportService service = new ExportService(wsdlURL);
        ExportPortType servicePort = service.getExportPort();
        Client client = ClientProxy.getClient(servicePort);
        setCookieOrUserTokenData(client);

        // Set timeout
        HTTPConduit httpConduit = (HTTPConduit)client.getConduit();
        HTTPClientPolicy policy = httpConduit.getClient();
        policy.setReceiveTimeout(0);

        // Enable MTOM
        SOAPBinding binding = (SOAPBinding)((BindingProvider)servicePort).getBinding();
        binding.setMTOMEnabled(true);

        FileTypeType fileType = getFileType(m_demoInfo.saveTo.getAbsolutePath());

        if (m_demoInfo.bAsync)
        {
            // Asynchronous call
            final long asyncStartTime = System.currentTimeMillis();
            Future<? > future = servicePort.exportProjectAsync("UTF-8", fileType, null, new Integer(projectObjectId), null, null, null, new AsyncHandler<ExportProjectResponse>()
                {
                    public void handleResponse(Response<ExportProjectResponse> resp)
                    {
                        try
                        {
                            ExportProjectResponse response = resp.get();
                            DataHandler dataHandler = response.getProjectData();
                            writeToFile(dataHandler.getInputStream(), m_demoInfo.saveTo);

                            final long duration = System.currentTimeMillis() - asyncStartTime;
                            m_ps.println("Totoal time for export: " + duration + "ms.");
                        }
                        catch (Exception e)
                        {
                            e.printStackTrace();
                            m_ps.println("Exception when getting export response: " + e.getMessage());
                        }
                    }
                });

            m_ps.println("Waiting for asynchronous call to return...");

            while (!future.isDone())
            {
                Thread.sleep(100);
            }
        }
        else
        {
            // Synchronous call
            long startTime = System.currentTimeMillis();
            DataHandler dataHandler = servicePort.exportProject("UTF-8", fileType, null, new Integer(projectObjectId), null, null, null);
            writeToFile(dataHandler.getInputStream(), m_demoInfo.saveTo);

            long duration = System.currentTimeMillis() - startTime;
            m_ps.println("Total time for export: " + duration + "ms.");
        }
    }

    private String makeHttpURLString(String hostname, int port, String suffix, boolean bUseSSL)
    {
        StringBuilder sb = new StringBuilder(bUseSSL ? HTTPS : HTTP);
        sb.append(hostname).append(":").append(port).append(suffix);

        return sb.toString();
    }

    private void writeToFile(InputStream inputStream, File file)
      throws IOException
    {
        BufferedInputStream bis = new BufferedInputStream(inputStream);
        BufferedOutputStream bos = null;
        byte[] buffer = new byte[1024];

        try
        {
            bos = new BufferedOutputStream(new FileOutputStream(file));

            int count;

            while ((count = bis.read(buffer)) > 0)
            {
                bos.write(buffer, 0, count);
            }
        }
        finally
        {
            if (bos != null)
            {
                bos.close();
            }
        }
    }

    private FileTypeType getFileType(String filepath)
    {
        if (filepath.endsWith(XML))
        {
            return FileTypeType.XML;
        }

        if (filepath.endsWith(ZIP))
        {
            return FileTypeType.ZIP;
        }
        else if (filepath.endsWith(GZIP))
        {
            return FileTypeType.GZIP;
        }
        else
        {
            return null;
        }
    }

    private void setCookieOrUserTokenData(Client client)
    {
        // Uncomment the following two lines to log SOAPMessages
        client.getEndpoint().getOutInterceptors().add(new LoggingOutInterceptor());
        client.getEndpoint().getInInterceptors().add(new LoggingInInterceptor());

        if (m_demoInfo.authMode == USERNAME_TOKEN_MODE || m_demoInfo.authMode == SAML_11_MODE || m_demoInfo.authMode == SAML_20_MODE)
        {
            client.getEndpoint().getOutInterceptors().add(new SAAJOutInterceptor());
            client.getEndpoint().getInInterceptors().add(new SAAJInInterceptor());

            // To do UsernameToken or SAML, we use our own Interceptor
            //  This will also handle encryption, if enabled
            client.getEndpoint().getOutInterceptors().add(new DemoOutInterceptor(m_demoInfo));

            // However, we only need a custom inbound Interceptor if we know that the server
            //  is sending back encrypted messages.
            if (m_demoInfo.encEnabled && m_demoInfo.encInbound)
            {
                client.getEndpoint().getInInterceptors().add(new DemoInInterceptor());
            }
        }
        else
        {
            HTTPConduit httpConduit = (HTTPConduit)client.getConduit();
            HTTPClientPolicy policy = httpConduit.getClient();
            policy.setCookie(m_cookieHeaders.get(0));
        }
    }

    private IntegrationFaultType getIntegrationFaultType(Throwable realException)
      throws SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
    {
        Class<? extends Throwable> exceptionClass = realException.getClass();
        Method[] classMethods = exceptionClass.getMethods();

        if ((classMethods != null) && (classMethods.length > 0))
        {
            for (Method method : classMethods)
            {
                if (method.getName().equals("getFaultInfo"))
                {
                    Object integrationFaultTypeObject = method.invoke(realException);

                    if (integrationFaultTypeObject instanceof IntegrationFaultType)
                    {
                        return (IntegrationFaultType)integrationFaultTypeObject;
                    }
                }
            }
        }

        return null;
    }

    
    public static final int USERNAME_TOKEN_MODE = 0;
    public static final int SAML_11_MODE = 1;
    public static final int SAML_20_MODE = 2;
    public static final int COOKIE_MODE = 3;

    //~ Inner Classes ------------------------------------------------------------------------------

    static class DemoInfo
    {
        //~ Static fields/initializers -------------------------------------------------------------

        static final DemoInfo DEFAULT_INFO = new DemoInfo();
        
        static final String s_propsFileName = System.getProperty("user.home")+"/WSDemo.properties";
        
        static
        {
            loadInfoFromProps(DEFAULT_INFO, false);
        }
        
        static private void loadInfoFromProps(DemoInfo info, boolean bUseDefaults)
        {
            Properties props = new Properties();
            if (!bUseDefaults)
            {
                try
                {
                    props.load(new FileInputStream(s_propsFileName));
                }
                catch (Exception e)
                {
                }
            }
            
            try
            {
                info.username = props.getProperty("username", "admin");
//                info.password = props.getProperty("password", "admin");
                info.hostname = props.getProperty("hostname", "localhost");
                info.port = safeParseInt(props.getProperty("port", "7001"), 7001);
                info.projectId = props.getProperty("projectId", "WS-Demo");
                info.bPerformExport = safeParseBoolean(props.getProperty("bPerformExport", "false"), false);
                info.saveTo = safeParseFile(props.getProperty("saveTo", "saveTo"));
                info.bAsync = safeParseBoolean(props.getProperty("bAsync", "false"), false);
                info.encEnabled = safeParseBoolean(props.getProperty("encEnabled", "false"), false);
                info.sigEnabled = safeParseBoolean(props.getProperty("sigEnabled", "false"), false);
                info.keystore = safeParseFile(props.getProperty("keystore", "keystore"));
                info.keystoreType = props.getProperty("keystoreType", "JKS");
                info.keystorePass = props.getProperty("keystorePass", "storePass");
                info.certAlias = props.getProperty("certAlias", "wsalias");
                info.encInbound = safeParseBoolean(props.getProperty("encInbound", "true"), true);
                info.authMode = safeParseInt(props.getProperty("authMode", "0"),USERNAME_TOKEN_MODE);
                info.samlSigned = safeParseBoolean(props.getProperty("samlSigned", "true"), true);
                info.samlKeystore = safeParseFile(props.getProperty("samlKeystore", "samlKeystore"));
                info.samlKeystoreType = props.getProperty("samlKeystoreType", "JKS");
                info.samlKeystorepass = props.getProperty("samlKeystorepass", "storepass");
                info.samlKeypass = props.getProperty("samlKeypass", "samlkeypass");
                info.samlAlias = props.getProperty("samlAlias", info.samlAlias);
                info.bUseSSL = safeParseBoolean(props.getProperty("bUseSSL", "false"), false);
                info.samlIssuer = props.getProperty("samlIssuer", "http://your.saml.issuer.com");
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }

        static private int safeParseInt(String intStr, int defaultValue)
        {
            try
            {
                return Integer.parseInt(intStr);
            }
            catch(Exception e)
            {
                return defaultValue;
            }
        }
        static private boolean safeParseBoolean(String boolStr, boolean defaultValue)
        {
            try
            {
                return Boolean.parseBoolean(boolStr);
            }
            catch(Exception e)
            {
                return defaultValue;
            }
        }
        static private File safeParseFile(String fileName)
        {
            if (fileName == null || fileName.length() == 0)
                return null;
            try
            {
                return new File(fileName);
            }
            catch(Exception e)
            {
                return null; 
            }
        }
        
        //~ Instance fields ------------------------------------------------------------------------

        String username;
        String password = "";
        String hostname;
        int port;
        String projectId;
        boolean bPerformExport;
        File saveTo;
        boolean bAsync;
        boolean encEnabled;
        boolean sigEnabled;
        File keystore;
        String keystoreType;
        String keystorePass;
        String certAlias;
        boolean encInbound;
        int authMode;
        boolean samlSigned;
        File samlKeystore;
        String samlKeystoreType;
        String samlKeystorepass;
        String samlKeypass;
        String samlAlias;
        boolean bUseSSL;
        String samlIssuer = "";
        String samlTokenPath = "";

        //~ Constructors ---------------------------------------------------------------------------

        DemoInfo()
        {
        }
        
        void saveToPropertiesFile()
        {
            Properties props = new Properties();
            
            props.setProperty("username", this.username);
//            props.setProperty("password",this.password);
            props.setProperty("hostname",this.hostname);
            props.setProperty("port", Integer.toString(this.port));
            props.setProperty("projectId", this.projectId);
            props.setProperty("bPerformExport",Boolean.toString(this.bPerformExport));
            props.setProperty("saveTo", this.saveTo.getAbsolutePath());
            props.setProperty("bAsync", Boolean.toString(this.bAsync));
            props.setProperty("encEnabled", Boolean.toString(this.encEnabled));
            props.setProperty("sigEnabled", Boolean.toString(this.sigEnabled));
            props.setProperty("keystore", this.keystore.getAbsolutePath());
            props.setProperty("keystoreType",this.keystoreType);
            props.setProperty("keystorePass",this.keystorePass);
            props.setProperty("certAlias", this.certAlias);
            props.setProperty("encInbound", Boolean.toString(this.encInbound));
            props.setProperty("authMode", Integer.toString(this.authMode));
            props.setProperty("samlSigned", Boolean.toString(this.samlSigned));
            props.setProperty("samlKeystore", this.samlKeystore.getAbsolutePath());
            props.setProperty("samlKeystoreType",this.samlKeystoreType);
            props.setProperty("samlKeystorepass",this.samlKeystorepass);
            props.setProperty("samlKeypass", this.samlKeypass);
            props.setProperty("samlAlias", this.samlAlias);
            props.setProperty("bUseSSL", Boolean.toString(this.bUseSSL));
            props.setProperty("samlIssuer", this.samlIssuer);
            
            try
            {
                props.store(new FileOutputStream(s_propsFileName), "");
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
        
    }
    
}
