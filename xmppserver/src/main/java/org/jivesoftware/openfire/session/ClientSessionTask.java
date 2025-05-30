/*
 * Copyright (C) 2007-2009 Jive Software, 2021-2025 Ignite Realtime Foundation. All rights reserved.
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

package org.jivesoftware.openfire.session;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.spi.ClientRoute;
import org.jivesoftware.openfire.spi.RoutingTableImpl;
import org.jivesoftware.util.cache.Cache;
import org.jivesoftware.util.cache.CacheFactory;
import org.jivesoftware.util.cache.ExternalizableUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * Class that defines possible remote operations that could be performed
 * on remote client sessions.
 *
 * @author Gaston Dombiak
 */
public class ClientSessionTask extends RemoteSessionTask {

    private static final Logger logger = LoggerFactory.getLogger(ClientSessionTask.class);

    private JID address;
    private transient Session session;

    public ClientSessionTask() {
        super();
    }

    public ClientSessionTask(JID address, Operation operation) {
        super(operation);
        this.address = address;
    }

    Session getSession() {
        if (session == null) {
            session = XMPPServer.getInstance().getRoutingTable().getClientRoute(address);
        }
        return session;
    }

    public void run() {
        if (getSession() == null || getSession().isClosed()) {
            if (this.operation == Operation.removeDetached) {
                logger.debug("Asked to remove detached sessions for JID {}, but no such sessions exist.", address); // This is a rather likely scenario. Don't log an error for this (OF-3034).
            } else {
                logger.error("Unable to execute task for JID {}: {}", address, this, new IllegalStateException("Session not found for JID: " + address));
            }
            return;
        }
        super.run();

        ClientSession session = (ClientSession) getSession();
        if (session instanceof RemoteClientSession) {
            // The session is being hosted by other cluster node so log this unexpected case
            Cache<String, ClientRoute> usersCache = CacheFactory.createCache(RoutingTableImpl.C2S_CACHE_NAME);
            ClientRoute route = usersCache.get(address.toString());
            byte[] nodeIDByte = route != null ? route.getNodeID().toByteArray() : new byte[0];

            logger.warn("Found remote session instead of local session. JID: {} found in Node: {} and local node is: {}",
                address, nodeIDByte, XMPPServer.getInstance().getNodeID().toByteArray());
        }
        if (operation == Operation.isInitialized) {
            if (session instanceof RemoteClientSession) {
                // Something is wrong since the session should be local instead of remote
                // Assume some default value
                result = true;
            }
            else {
                result = session.isInitialized();
            }
        }
        if (operation == Operation.isAnonymous) {
            if (session instanceof RemoteClientSession) {
                // Something is wrong since the session should be local instead of remote
                // Assume some default value
                result = false;
            }
            else {
                result = session.isAnonymousUser();
            }
        }
        else if (operation == Operation.incrementConflictCount) {
            if (session instanceof RemoteClientSession) {
                // Something is wrong since the session should be local instead of remote
                // Assume some default value
                result = 2;
            }
            else {
                result = session.incrementConflictCount();
            }
        }
        else if (operation == Operation.hasRequestedBlocklist) {
            if (session instanceof RemoteClientSession) {
                // Something is wrong since the session should be local instead of remote
                // Assume some default value
                result = false;
            }
            else {
                result = session.hasRequestedBlocklist();
            }
        }
    }

    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        ExternalizableUtil.getInstance().writeSerializable(out, address);
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        address = (JID) ExternalizableUtil.getInstance().readSerializable(in);
    }

    public String toString() {
        return super.toString() + " operation: " + operation + " address: " + address;
    }
}
