package com.primavera.wsclient.demo;

import oracle.security.xmlsec.enc.XEReferenceList;
import oracle.security.xmlsec.util.XMLUtils;
import oracle.security.xmlsec.wss.WSSecurity;
import oracle.security.xmlsec.wss.soap.WSSOAPEnvelope;

import org.apache.cxf.binding.soap.SoapFault;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.SoapVersion;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;

public class DemoInInterceptor
  extends AbstractPhaseInterceptor<SoapMessage>
{
    //~ Constructors -------------------------------------------------------------------------------

    public DemoInInterceptor()
    {
        super(Phase.RECEIVE);
    }

    //~ Methods ------------------------------------------------------------------------------------

    public void handleMessage(SoapMessage message)
      throws Fault
    {
        SoapVersion version = message.getVersion();

        try
        {
            // First we need to do some general setup to get the Soap information we need
            InputStream inputStream = message.getContent(InputStream.class);
            DocumentBuilder db = XMLUtils.createDocBuilder();
            Document doc = db.parse(inputStream);
            WSSOAPEnvelope wsEnvelope = new WSSOAPEnvelope(doc.getDocumentElement());
            List<? > securityList = wsEnvelope.getSecurity();
            WSSecurity wsSecurity = (WSSecurity)securityList.get(0);

            // Once we have all this, we can get all the encrypted information
            List<XEReferenceList> xRefList = wsSecurity.getReferenceLists();

            for (XEReferenceList xerRef : xRefList)
            {
                // And decrypt it all one by one
                WSSecurity.decrypt(xerRef, DemoSecretKeyHolder.getSecretKey());
            }

            // And lastly we make sure that the message is updated with the unencrypted information
            message.setContent(InputStream.class, new ByteArrayInputStream(XMLUtils.toBytesXML(wsEnvelope, false, false)));
        }
        catch (Exception e)
        {
            throw new SoapFault("Unable to verify security information sent back by server.", e, version.getSender());
        }
    }
}
