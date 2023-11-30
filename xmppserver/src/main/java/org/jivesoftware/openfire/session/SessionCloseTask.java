/*
 * Copyright (C) 2023 Ignite Realtime Foundation. All rights reserved.
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

import org.jivesoftware.openfire.SessionManager;
import org.jivesoftware.openfire.StreamID;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.spi.BasicStreamIDFactory;
import org.jivesoftware.util.SAXReaderUtil;
import org.jivesoftware.util.TaskEngine;
import org.jivesoftware.util.cache.ClusterTask;
import org.jivesoftware.util.cache.ExternalizableUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;
import org.xmpp.packet.StreamError;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Cluster task that will ask a remote cluster node to close a local session.
 *
 * @author Guus der Kinderen
 */
public class SessionCloseTask implements ClusterTask<Void> {
    private static final Logger Log = LoggerFactory.getLogger(SessionCloseTask.class);

    private SessionType sessionType;
    private JID address;
    private StreamID streamID; // For Incoming Server Session.
    private DomainPair domainPair; // Four Outgoing Server session.
    private StreamError error;

    public SessionCloseTask() {
        super();
    }

    SessionCloseTask(RemoteSession remoteSession, JID address, StreamError error) {
        if (remoteSession instanceof RemoteClientSession) {
            this.sessionType = SessionType.client;
        }
        else if (remoteSession instanceof RemoteComponentSession) {
            this.sessionType = SessionType.component;
        }
        else if (remoteSession instanceof RemoteConnectionMultiplexerSession) {
            this.sessionType = SessionType.connectionManager;
        }
        else {
            Log.error("Invalid RemoteSession was used for task: " + remoteSession);
        }
        this.address = address;
        this.error = error;
    }

    SessionCloseTask(StreamID streamID, StreamError error) {
        this.sessionType = SessionType.incomingServer;
        this.streamID = streamID;
        this.error = error;
    }

    SessionCloseTask(DomainPair domainPair, StreamError error) {
        this.sessionType = SessionType.outgoingServer;
        this.domainPair = domainPair;
        this.error = error;
    }

    public Void getResult() {
        return null;
    }

    public void run() {
        // Run in another thread to avoid blocking calls (in hazelcast)
        final Session session = getSession();
        if (session != null) {
            final Future<?> future = TaskEngine.getInstance().submit( () -> {
                try {
                    session.close(error);
                } catch (Exception e) {
                    Log.info("An exception was logged while closing session: {} with optional error {}", session, error, e);
                }
            });
            // Wait until the close operation is done or timeout is met
            try {
                future.get(15, TimeUnit.SECONDS);
            }
            catch (Exception e) {
                Log.info("An exception was logged while executing cluster task to close session: {} with optional error: {}", session, error, e);
            }
        }
    }

    public void writeExternal(ObjectOutput out) throws IOException {
        ExternalizableUtil.getInstance().writeBoolean(out, error != null);
        if (error != null) {
            ExternalizableUtil.getInstance().writeSafeUTF(out, error.toXML());
        }
        ExternalizableUtil.getInstance().writeInt(out, sessionType.ordinal());
        ExternalizableUtil.getInstance().writeBoolean(out, address != null);
        if (address != null) {
            ExternalizableUtil.getInstance().writeSerializable(out, address);
        }
        ExternalizableUtil.getInstance().writeBoolean(out, streamID != null);
        if (streamID != null) {
            ExternalizableUtil.getInstance().writeSafeUTF( out, streamID.getID() );
        }
    }

    public void readExternal(ObjectInput in) throws IOException {
        if (ExternalizableUtil.getInstance().readBoolean(in)) {
            final String rawText = ExternalizableUtil.getInstance().readSafeUTF(in);
            try {
                error = new StreamError(SAXReaderUtil.readRootElement(rawText));
            } catch (ExecutionException | InterruptedException e) {
                throw new IOException(e);
            }
        }
        sessionType = SessionType.values()[ExternalizableUtil.getInstance().readInt(in)];
        if (ExternalizableUtil.getInstance().readBoolean(in)) {
            address = (JID) ExternalizableUtil.getInstance().readSerializable(in);
        }
        if (ExternalizableUtil.getInstance().readBoolean(in)) {
            streamID = BasicStreamIDFactory.createStreamID( ExternalizableUtil.getInstance().readSafeUTF(in) );
        }
    }

    Session getSession() {
        if (sessionType == SessionType.client) {
            return XMPPServer.getInstance().getRoutingTable().getClientRoute(address);
        }
        else if (sessionType == SessionType.component) {
            return SessionManager.getInstance().getComponentSession(address.getDomain());
        }
        else if (sessionType == SessionType.connectionManager) {
            return SessionManager.getInstance().getConnectionMultiplexerSession(address);
        }
        else if (sessionType == SessionType.outgoingServer) {
            return SessionManager.getInstance().getOutgoingServerSession(domainPair);
        }
        else if (sessionType == SessionType.incomingServer) {
            return SessionManager.getInstance().getIncomingServerSession(streamID);
        }
        Log.error("Found unknown session type: " + sessionType);
        return null;
    }

    public String toString() {
        return super.toString() + " sessionType: " + sessionType + " address: " + address;
    }

    private enum SessionType {
        client,
        outgoingServer,
        incomingServer,
        component,
        connectionManager
    }
}
