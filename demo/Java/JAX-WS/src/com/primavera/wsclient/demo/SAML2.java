package com.primavera.wsclient.demo;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import oracle.security.xmlsec.saml2.util.SAML2Initializer;
import oracle.security.xmlsec.saml2.util.SAML2URI;
import oracle.security.xmlsec.wss.WSSecurity;
import oracle.security.xmlsec.wss.soap.WSSOAPEnvelope;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.primavera.wsclient.demo.WSDemo.DemoInfo;

public class SAML2
{
    //~ Static fields/initializers -----------------------------------------------------------------
    
    private static final String ASSERTION = "Assertion";

    //~ Instance fields ----------------------------------------------------------------------------

    //~ Constructors -------------------------------------------------------------------------------


    public SAML2()
    {
    }

    //~ Methods ------------------------------------------------------------------------------------

    public static Element addSAMLAssertion(WSSecurity sec, WSSOAPEnvelope wsEnvelope, WSDemo.DemoInfo demoInfo)
      throws Exception
    {
        SAML2Initializer.initialize();

        Document aDoc = wsEnvelope.getOwnerDocument();

        Document samlxml = getSAMLXML(demoInfo);
        NodeList assrtList = 
            samlxml.getElementsByTagNameNS(SAML2URI.ns_saml, ASSERTION);
        
        Element element = (Element)assrtList.item(0);
        Node importedNode = aDoc.importNode(element, true);
        sec.appendChild(importedNode);

        return samlxml.getDocumentElement();
    }
    
    
    private static Document getSAMLXML(DemoInfo demoInfo) throws Exception
    {
        return parseDomContent(new FileInputStream(new File(demoInfo.samlTokenPath)));
    }
    
    public static Document parseDomContent(InputStream is) throws ParserConfigurationException, SAXException, IOException
    {
        DocumentBuilderFactory docbf = DocumentBuilderFactory.newInstance();
        docbf.setNamespaceAware(true);

        DocumentBuilder docBuilder = docbf.newDocumentBuilder();
        return docBuilder.parse(is);
    }

   
}
