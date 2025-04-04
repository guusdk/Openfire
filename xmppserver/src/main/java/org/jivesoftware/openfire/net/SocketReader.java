/*
 * Copyright (C) 2005-2008 Jive Software, 2016-2024 Ignite Realtime Foundation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.net;

import org.dom4j.*;
import org.dom4j.io.XMPPPacketReader;
import org.jivesoftware.openfire.Connection;
import org.jivesoftware.openfire.PacketRouter;
import org.jivesoftware.openfire.RoutingTable;
import org.jivesoftware.openfire.StreamIDFactory;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.disco.IQDiscoInfoHandler;
import org.jivesoftware.openfire.session.LocalSession;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.spi.BasicStreamIDFactory;
import org.jivesoftware.util.LocaleUtils;
import org.jivesoftware.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import org.xmpp.packet.*;

import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * A SocketReader creates the appropriate {@link Session} based on the defined namespace in the
 * stream element and will then keep reading and routing the received packets.
 *
 * @author Gaston Dombiak
 * @deprecated Old, pre NIO / MINA code. Should not be used as Netty offers better performance. Currently only in use for server dialback.
 */
public abstract class SocketReader implements Runnable {

    private static final Logger Log = LoggerFactory.getLogger(SocketReader.class);

    /**
     * The utf-8 charset for decoding and encoding Jabber packet streams.
     */
    private static String CHARSET = "UTF-8";

    /**
     * A factory that generates random stream IDs
     */
    private static final StreamIDFactory STREAM_ID_FACTORY = new BasicStreamIDFactory();

    /**
     * Reuse the same factory for all the connections.
     */
    private static XmlPullParserFactory factory = null;

    /**
     * Session associated with the socket reader.
     */
    protected LocalSession session;
    /**
     * Reference to the physical connection.
     */
    protected SocketConnection connection;
    /**
     * Server name for which we are attending clients.
     */
    protected String serverName;

    /**
     * Indicates if sockets initially will be plain text (false), or ecnrypted (true).
     */
    protected boolean directTLS;

    /**
     * Router used to route incoming packets to the correct channels.
     */
    private PacketRouter router;
    /**
     * Routing table used for checking whether a domain is known or not.
     */
    private RoutingTable routingTable;
    /**
     * Specifies whether the socket is using blocking or non-blocking connections.
     */
    private SocketReadingMode readingMode;
    XMPPPacketReader reader = null;
    protected boolean open;

    static {
        try {
            factory = XmlPullParserFactory.newInstance(MXParser.class.getName(), null);
        }
        catch (XmlPullParserException e) {
            Log.error("Error creating a parser factory", e);
        }
    }

    /**
     * Creates a dedicated reader for a socket.
     *
     * @param router the router for sending packets that were read.
     * @param routingTable the table that keeps routes to registered services.
     * @param serverName the name of the server this socket is working for.
     * @param socket the socket to read from.
     * @param connection the connection being read.
     * @param useBlockingMode true means that the server will use a thread per connection.
     * @param directTLS false means that the socket initially is a plaintext connection.
     */
    public SocketReader(PacketRouter router, RoutingTable routingTable, String serverName,
            Socket socket, SocketConnection connection, boolean useBlockingMode, boolean directTLS ) {
        this.serverName = serverName;
        this.router = router;
        this.routingTable = routingTable;
        this.connection = connection;
        this.directTLS = directTLS;

        connection.setSocketReader(this);

        // Reader is associated with a new XMPPPacketReader
        reader = new XMPPPacketReader();
        reader.setXPPFactory(factory);

        // Set the blocking reading mode to use
        readingMode = new BlockingReadingMode(socket, this);
    }

    /**
     * A dedicated thread loop for reading the stream and sending incoming
     * packets to the appropriate router.
     */
    @Override
    public void run() {
        readingMode.run();
    }

    protected void process(Element doc) throws Exception {
        if (doc == null) {
            return;
        }
       
        String tag = doc.getName();
        if ("message".equals(tag)) {
            Message packet;
            try {
                packet = new Message(doc);
            }
            catch(IllegalArgumentException e) {
                Log.debug("SocketReader: Rejecting packet. JID malformed", e);
                // The original packet contains a malformed JID so answer with an error.
                Message reply = new Message();
                reply.setID(doc.attributeValue("id"));
                reply.setTo(session.getAddress());
                reply.getElement().addAttribute("from", doc.attributeValue("to"));
                reply.setError(PacketError.Condition.jid_malformed);
                session.process(reply);
                return;
            }
            processMessage(packet);
        }
        else if ("presence".equals(tag)) {
            Presence packet;
            try {
                packet = new Presence(doc);
            }
            catch (IllegalArgumentException e) {
                Log.debug("SocketReader: Rejecting packet. JID malformed", e);
                // The original packet contains a malformed JID so answer an error
                Presence reply = new Presence();
                reply.setID(doc.attributeValue("id"));
                reply.setTo(session.getAddress());
                reply.getElement().addAttribute("from", doc.attributeValue("to"));
                reply.setError(PacketError.Condition.jid_malformed);
                session.process(reply);
                return;
            }
            // Check that the presence type is valid. If not then assume available type
            try {
                packet.getType();
            }
            catch (IllegalArgumentException e) {
                Log.debug("Invalid presence (type): " + packet);
                // The presence packet contains an invalid presence type so replace it with
                // an available presence type
                packet.setType(null);
            }
            // Check that the presence show is valid. If not then assume available show value
            try {
                packet.getShow();
            }
            catch (IllegalArgumentException e) {
                Log.debug("Invalid presence (show): " + packet);
                // The presence packet contains an invalid presence show so replace it with
                // an available presence show
                packet.setShow(null);
            }
            if (session.getStatus() == Session.Status.CLOSED && packet.isAvailable()) {
                // Ignore available presence packets sent from a closed session. A closed
                // session may have buffered data pending to be processes so we want to ignore
                // just Presences of type available
                Log.warn("Ignoring available presence packet of closed session: " + packet);
                return;
            }
            processPresence(packet);
        }
        else if ("iq".equals(tag)) {
            IQ packet;
            try {
                packet = getIQ(doc);
            }
            catch(IllegalArgumentException e) {
                Log.debug("SocketReader: Rejecting packet. JID malformed", e);
                // The original packet contains a malformed JID so answer an error
                IQ reply = new IQ();
                if (!doc.elements().isEmpty()) {
                    reply.setChildElement(((Element) doc.elements().get(0)).createCopy());
                }
                reply.setID(doc.attributeValue("id"));
                reply.setTo(session.getAddress());
                if (doc.attributeValue("to") != null) {
                    reply.getElement().addAttribute("from", doc.attributeValue("to"));
                }
                reply.setError(PacketError.Condition.jid_malformed);
                session.process(reply);
                return;
            }
            processIQ(packet);
        }
        else
        {
            if (!processUnknowPacket(doc)) {
                Log.warn(LocaleUtils.getLocalizedString("admin.error.packet.tag") +
                        doc.asXML());
                open = false;
            }
        }
    }

    /**
     * Process the received IQ packet. Registered
     * {@link org.jivesoftware.openfire.interceptor.PacketInterceptor} will be invoked before
     * and after the packet was routed.<p>
     *
     * Subclasses may redefine this method for different reasons such as modifying the sender
     * of the packet to avoid spoofing, rejecting the packet or even process the packet in
     * another thread.
     *
     * @param packet the received packet.
     * @throws UnauthorizedException if the connection required encryption but was not encrypted.
     */
    protected void processIQ(IQ packet) throws UnauthorizedException {
        // Ensure that connection was encrypted if TLS was required.
        if (connection.getConfiguration().getTlsPolicy() == Connection.TLSPolicy.required &&
                !connection.isEncrypted()) {
            closeNeverEncryptedConnection();
            return;
        }
        router.route(packet);
        session.incrementClientPacketCount();
    }

    /**
     * Process the received Presence packet. Registered
     * {@link org.jivesoftware.openfire.interceptor.PacketInterceptor} will be invoked before
     * and after the packet was routed.<p>
     *
     * Subclasses may redefine this method for different reasons such as modifying the sender
     * of the packet to avoid spoofing, rejecting the packet or even process the packet in
     * another thread.
     *
     * @param packet the received packet.
     * @throws UnauthorizedException if the connection required encryption but was not encrypted.
     */
    protected void processPresence(Presence packet) throws UnauthorizedException {
        // Ensure that connection was encrypted if TLS was required
        if (connection.getConfiguration().getTlsPolicy() == Connection.TLSPolicy.required &&
                !connection.isEncrypted()) {
            closeNeverEncryptedConnection();
            return;
        }
        router.route(packet);
        session.incrementClientPacketCount();
    }

    /**
     * Process the received Message packet. Registered
     * {@link org.jivesoftware.openfire.interceptor.PacketInterceptor} will be invoked before
     * and after the packet was routed.<p>
     *
     * Subclasses may redefine this method for different reasons such as modifying the sender
     * of the packet to avoid spoofing, rejecting the packet or even process the packet in
     * another thread.
     *
     * @param packet the received packet.
     * @throws UnauthorizedException if the connection required encryption but was not encryption.
     */
    protected void processMessage(Message packet) throws UnauthorizedException {
        // Ensure that connection was encrypted if TLS was required
        if (connection.getConfiguration().getTlsPolicy() == Connection.TLSPolicy.required &&
                !connection.isEncrypted()) {
            closeNeverEncryptedConnection();
            return;
        }
        router.route(packet);
        session.incrementClientPacketCount();
    }

    /**
     * Returns true if a received packet of an unkown type (i.e. not a Message, Presence
     * or IQ) has been processed. If the packet was not processed then an exception will
     * be thrown which will make the thread to stop processing further packets.
     *
     * @param doc the DOM element of an unkown type.
     * @return  true if a received packet has been processed.
     */
    abstract boolean processUnknowPacket(Element doc);

    /**
     * Returns the last time a full Document was read or a heartbeat was received. Hearbeats
     * are represented as whitespaces received while a Document is not being parsed.
     *
     * @return the time in milliseconds when the last document or heartbeat was received.
     */
    long getLastActive() {
        return reader.getLastActive();
    }

    /**
     * Returns a name that identifies the type of reader and the unique instance.
     *
     * @return a name that identifies the type of reader and the unique instance.
     */
    abstract String getName();

    /**
     * Close the connection since TLS was mandatory and the entity never negotiated TLS. Before
     * closing the connection a stream error will be sent to the entity.
     */
    void closeNeverEncryptedConnection() {
        // Send a stream error and close the underlying connection.
        connection.close(new StreamError(StreamError.Condition.not_authorized, "TLS is mandatory, but was not established."));
        // Log a warning so that admins can track this case from the server side
        Log.warn("TLS was required by the server and connection was never secured. Closing connection: {}", connection);
    }

    private IQ getIQ(Element doc) {
        Element query = doc.element("query");
        if (query != null && "jabber:iq:roster".equals(query.getNamespaceURI())) {
            return new Roster(doc);
        }else if (query != null && "jabber:iq:version".equals(query.getNamespaceURI())) {
            IQ iq = new IQ(doc);
            if (iq.getType().equals(IQ.Type.result) && iq.getFrom().equals(session.getAddress())){
                try {
                    List<Element> elements =  query.elements();
                    if (elements.size() >0){
                        for (Element element : elements){
                            session.setSoftwareVersionData(element.getName(), element.getStringValue());
                        }
                    }    
                } catch (Exception e) {
                    Log.error(e.getMessage(), e);
                }  
            }
            return iq;
        }else if(query != null && "http://jabber.org/protocol/disco#info".equals(query.getNamespaceURI())){
            //XEP-0232 if responses service discovery can include detailed information about the software application
            IQ iq = new IQ(doc); 
            if(iq.getFrom().equals(session.getAddress())){
                IQDiscoInfoHandler.setSoftwareVersionDataFormFromDiscoInfo(query, session);
            } 
            return new IQ(doc);
        }else {
            return new IQ(doc);
        }
    }


    /**
     * Uses the XPP to grab the opening stream tag and create an active session
     * object. The session to create will depend on the sent namespace. In all
     * cases, the method obtains the opening stream tag, checks for errors, and
     * either creates a session or returns an error and kills the connection.
     * If the connection remains open, the XPP will be set to be ready for the
     * first packet. A call to next() should result in an START_TAG state with
     * the first packet in the stream.
     *
     * @throws UnauthorizedException if the connection required encryption but was not encrypted.
     * @throws XmlPullParserException if there was an XML error while creating the session.
     * @throws IOException if an IO error occurred while creating the session.
     */
    protected void createSession()
            throws UnauthorizedException, XmlPullParserException, IOException {
        XmlPullParser xpp = reader.getXPPParser();
        for (int eventType = xpp.getEventType(); eventType != XmlPullParser.START_TAG;) {
            eventType = xpp.next();
        }

        // Check that the TO attribute of the stream header matches the server name or a valid
        // subdomain. If the value of the 'to' attribute is not valid then return a host-unknown
        // error and close the underlying connection.
        String host = reader.getXPPParser().getAttributeValue("", "to");
        if (validateHost() && isHostUnknown(host)) {
            final Element stream = DocumentHelper.createElement(QName.get("stream", "stream", xpp.getNamespace("stream")));
            final Document document = DocumentHelper.createDocument(stream);
            document.setXMLEncoding(StandardCharsets.UTF_8.toString());
            stream.add(Namespace.get("", xpp.getNamespace(null)));
            stream.addAttribute("from", host);
            stream.addAttribute("id", STREAM_ID_FACTORY.createStreamID().getID());
            stream.addAttribute("version", "1.0");

            connection.deliverRawText(StringUtils.asUnclosedStream(document));

            // Send the host_unknown error and close the underlying connection
            connection.close(new StreamError(StreamError.Condition.host_unknown, "The 'to' attribute does not specify an XMPP domain entity served by this service."));
            // Log a warning so that admins can track this cases from the server side
            Log.warn("Closing session due to incorrect hostname in stream header. Host: {}. Connection: {}", host, connection);
        }

        // Create the correct session based on the sent namespace. At this point the server
        // may offer the client to encrypt the connection. If the client decides to encrypt
        // the connection then a <starttls> stanza should be received
        else if (!createSession(xpp.getNamespace(null))) {
            // No session was created because of an invalid namespace prefix so answer a stream
            // error and close the underlying connection
            final Element stream = DocumentHelper.createElement(QName.get("stream", "stream", xpp.getNamespace("stream")));
            final Document document = DocumentHelper.createDocument(stream);
            document.setXMLEncoding(StandardCharsets.UTF_8.toString());
            stream.add(Namespace.get("", xpp.getNamespace(null)));
            stream.addAttribute("from", host);
            stream.addAttribute("id", STREAM_ID_FACTORY.createStreamID().getID());
            stream.addAttribute("version", "1.0");

            connection.deliverRawText(StringUtils.asUnclosedStream(document));

            // Include the bad-namespace-prefix in the response and close the underlying connection.
            connection.close(new StreamError(StreamError.Condition.bad_namespace_prefix, "The namespace used in the request does not identify functionality that can be provided by this endpoint."));
            // Log a warning so that admins can track this cases from the server side
            Log.warn("Closing session due to bad_namespace_prefix in stream header. Prefix: {}. Connection: {}", xpp.getNamespace(null), connection);
        }
    }

    private boolean isHostUnknown(String host) {
        if (host == null) {
            // Answer false since when using server dialback the stream header will not
            // have a TO attribute
            return false;
        }
        if (serverName.equals(host)) {
            // requested host matched the server name
            return false;
        }
        if (routingTable.hasComponentRoute(new JID(host))) {
            // Check if the host matches a subdomain of this host
            return false;
        }

        return !Trunking.isTrunkingEnabledFor(host);
    }

    /**
     * Returns the stream namespace. (E.g. jabber:client, jabber:server, etc.).
     *
     * @return the stream namespace.
     */
    abstract Namespace getNamespace();

    /**
     * Returns true if the value of the 'to' attribute in the stream header should be
     * validated. If the value of the 'to' attribute is not valid then a host-unknown error
     * will be returned and the underlying connection will be closed.
     *
     * @return true if the value of the 'to' attribute in the initial stream header should be
     *         validated.
     */
    abstract boolean validateHost();

    /**
     * Notification message indicating that the SocketReader is shutting down. The thread will
     * stop reading and processing new requests. Subclasses may want to redefine this message
     * for releasing any resource they might need.
     */
    protected void shutdown() {
    }

    /**
     * Creates the appropriate {@link org.jivesoftware.openfire.session.Session} subclass based on the specified namespace.
     *
     * @param namespace the namespace sent in the stream element. eg. jabber:client.
     * @return the created session or null.
     * @throws UnauthorizedException if the connection required encryption but was not encrypted.
     * @throws XmlPullParserException if there was an XML error while creating the session.
     * @throws IOException if an IO error occurred while creating the session.
     */
    abstract boolean createSession(String namespace) throws UnauthorizedException,
            XmlPullParserException, IOException;

    public LocalSession getSession()
    {
        return session;
    }
}
