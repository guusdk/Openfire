package org.jivesoftware.openfire.nio;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.jivesoftware.openfire.Connection;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.net.ServerStanzaHandler;
import org.jivesoftware.openfire.net.StanzaHandler;
import org.jivesoftware.openfire.spi.ConnectionConfiguration;

import java.util.concurrent.CompletableFuture;

import static java.nio.charset.StandardCharsets.UTF_8;

public class OutgoingServerConnectionHandler extends ServerConnectionHandler {
    
    private final String localDomain;
    private final String remoteDomain;
    private final int port;
    
    public OutgoingServerConnectionHandler( ConnectionConfiguration configuration, String localDomain, String remoteDomain, int port, CompletableFuture<Boolean> callback ) {
        super(configuration);
        this.localDomain = localDomain;
        this.remoteDomain = remoteDomain;
        this.port = port;
    }

    @Override
    StanzaHandler createStanzaHandler( NIOConnection connection )
    {
        return new ServerStanzaHandler(XMPPServer.getInstance().getPacketRouter(), connection, true );
    }

    @Override
    public void sessionOpened(IoSession session) throws Exception {
        super.sessionOpened(session);
        Connection c = createNIOConnection(session);

//        log.debug("Send the stream header and wait for response...");
        String openingStream = "<stream:stream" +
            " xmlns:db=\"jabber:server:dialback\"" +
            " xmlns:stream=\"http://etherx.jabber.org/streams\"" +
            " xmlns=\"jabber:server\"" +
            " from=\"" + localDomain + "\"" + // OF-673
            " to=\"" + remoteDomain + "\"" +
            " version=\"1.0\">";
        c.deliverRawText(openingStream);

        // Set a read timeout (of 5 seconds) so we don't keep waiting forever
//        int soTimeout = socket.getSoTimeout();
//        socket.setSoTimeout(5000);
    }

}
