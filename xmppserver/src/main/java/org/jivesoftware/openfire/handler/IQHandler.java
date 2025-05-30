/*
 * Copyright (C) 2004-2008 Jive Software, 2017-2025 Ignite Realtime Foundation. All rights reserved.
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

package org.jivesoftware.openfire.handler;

import org.jivesoftware.openfire.ChannelHandler;
import org.jivesoftware.openfire.IQHandlerInfo;
import org.jivesoftware.openfire.PacketDeliverer;
import org.jivesoftware.openfire.PacketException;
import org.jivesoftware.openfire.SessionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.container.BasicModule;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.util.LocaleUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;
import org.xmpp.packet.PacketError;

import java.util.Optional;

/**
 * Base class whose main responsibility is to handle IQ packets. Subclasses may
 * only need to specify the IQHandlerInfo (i.e. name and namespace of the packets
 * to handle) and actually handle the IQ packet. Simplifies creation of simple
 * TYPE_IQ message handlers.
 *
 * @author Gaston Dombiak
 */
public abstract class IQHandler extends BasicModule implements ChannelHandler<IQ> {

    private static final Logger Log = LoggerFactory.getLogger(IQHandler.class);

    protected PacketDeliverer deliverer;
    protected SessionManager sessionManager;

    /**
     * Create a basic module with the given name.
     *
     * @param moduleName The name for the module or null to use the default
     */
    public IQHandler(String moduleName) {
        super(moduleName);
    }

    /**
     * RFC 6121 8.5.1. "No Such User" specifies how the server must respond to a request made against a non-existing user.
     *
     * The abstract IQ Handler plugin can act accordingly, but allows implementations to override this behavior. By
     * default, Openfire will perform a non-existing user check and act according to the RFC 6121. Subclasses can
     * disable this behavior by overriding this method, and returning 'false'.
     *
     * @return 'true' if the Abstract IQ Handler implementation should detect if the IQ request is made against a non-existing user and return an error.
     * @see <a href="http://xmpp.org/rfcs/rfc6121.html#rules-localpart-nosuchuser">RFC 6121 8.5.1. "No Such User"</a>
     * @see <a href="https://igniterealtime.atlassian.net/jira/software/c/projects/OF/issues/OF-880">OF-880</a>
     */
    public boolean performNoSuchUserCheck() {
        return true;
    }

    /**
     * Performs the check as defined in RFC 6121 8.5.1. "No Such User":
     * <blockquote>If the 'to' address specifies a bare JID <localpart@domainpart> or full JID
     * <localpart@domainpart/resourcepart> where the domainpart of the JID matches a configured domain that is serviced
     * by the server itself, the server MUST proceed as follows. [...] If the user account identified by the 'to'
     * attribute does not exist, how the stanza is processed depends on the stanza type. [...] For an IQ stanza, the
     * server MUST return a <service-unavailable/> stanza error to the sender.</blockquote>
     *
     * @see <a href="http://xmpp.org/rfcs/rfc6121.html#rules-localpart-nosuchuser">RFC 6121 8.5.1. "No Such User"</a>
     */
    public Optional<IQ> processNoSuchUserCheck(IQ iq)
    {
        if (iq.isResponse()) {
            return Optional.empty();
        }

        final JID recipientJID = iq.getTo();

        if (iq.isRequest() && recipientJID != null && recipientJID.getNode() != null
            && !XMPPServer.getInstance().isRemote(recipientJID)
            && !UserManager.getInstance().isRegisteredUser(recipientJID, false)
            && !sessionManager.isAnonymousClientSession(recipientJID)
            && !UserManager.isPotentialFutureLocalUser(recipientJID) && sessionManager.getSession(recipientJID) == null
            && !(recipientJID.asBareJID().equals(iq.getFrom().asBareJID()) && sessionManager.isPreAuthenticatedSession(iq.getFrom())) // A pre-authenticated session queries the server about itself.
        )
        {
            // For an IQ stanza, the server MUST return a <service-unavailable/> stanza error to the sender.
            IQ response = IQ.createResultIQ(iq);
            response.setChildElement(iq.getChildElement().createCopy());
            response.setError(PacketError.Condition.service_unavailable);
            return Optional.of(response);
        }
        return Optional.empty();
    }

    @Override
    public void process(IQ iq) throws PacketException {

        // Check for 'no such user' as per RFC 6121 8.5.1.
        if (performNoSuchUserCheck()) {
            final Optional<IQ> noSuchUserResponse = processNoSuchUserCheck(iq);
            if (noSuchUserResponse.isPresent()) {
                Log.trace("Responding with 'no such user' defined response, since the intended recipient isn't a local user ('no-such-user' check) to: {}", iq);
                sessionManager.getSession(iq.getFrom()).process(noSuchUserResponse.get());
                return;
            }
        }

        try {
            IQ reply = handleIQ(iq);
            if (reply != null) {
                deliverer.deliver(reply);
            }
        }
        catch (org.jivesoftware.openfire.auth.UnauthorizedException e) {
            if (iq != null) {
                try {
                    IQ response = IQ.createResultIQ(iq);
                    response.setChildElement(iq.getChildElement().createCopy());
                    response.setError(PacketError.Condition.not_authorized);
                    sessionManager.getSession(iq.getFrom()).process(response);
                }
                catch (Exception de) {
                    Log.error(LocaleUtils.getLocalizedString("admin.error"), de);
                    sessionManager.getSession(iq.getFrom()).close();
                }
            }
        }
        catch (Exception e) {
            Log.error(LocaleUtils.getLocalizedString("admin.error"), e);
            try {
                IQ response = IQ.createResultIQ(iq);
                response.setChildElement(iq.getChildElement().createCopy());
                response.setError(PacketError.Condition.internal_server_error);
                sessionManager.getSession(iq.getFrom()).process(response);
            }
            catch (Exception e1) {
                // Do nothing
            }
        }
    }

    /**
     * Handles the received IQ packet.
     *
     * @param packet the IQ packet to handle.
     * @return the response to send back.
     * @throws UnauthorizedException if the user that sent the packet is not
     *      authorized to request the given operation.
     */
    public abstract IQ handleIQ(IQ packet) throws UnauthorizedException;

    /**
     * Returns the handler information to help generically handle IQ packets.
     * IQHandlers that aren't local server iq handlers (e.g. chatbots, transports, etc)
     * return {@code null}.
     *
     * @return The IQHandlerInfo for this handler
     */
    public abstract IQHandlerInfo getInfo();

    @Override
    public void initialize(XMPPServer server) {
        super.initialize(server);
        deliverer = server.getPacketDeliverer();
        sessionManager = server.getSessionManager();
    }
}
