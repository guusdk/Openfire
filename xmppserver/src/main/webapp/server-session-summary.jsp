<%@ page contentType="text/html; charset=UTF-8" %>
<%--
  -
  - Copyright (C) 2004-2008 Jive Software, 2017-2023 Ignite Realtime Foundation. All rights reserved.
  -
  - Licensed under the Apache License, Version 2.0 (the "License");
  - you may not use this file except in compliance with the License.
  - You may obtain a copy of the License at
  -
  -     http://www.apache.org/licenses/LICENSE-2.0
  -
  - Unless required by applicable law or agreed to in writing, software
  - distributed under the License is distributed on an "AS IS" BASIS,
  - WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  - See the License for the specific language governing permissions and
  - limitations under the License.
--%>

<%@ page import="org.jivesoftware.openfire.SessionManager,
                 org.jivesoftware.openfire.session.OutgoingServerSession,
                 org.jivesoftware.openfire.session.Session,
                 org.jivesoftware.util.ParamUtils,
                 org.jivesoftware.util.StringUtils,
                 org.jivesoftware.util.CookieUtils,
                 java.util.*"
    errorPage="error.jsp"
%>

<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%!
    final int DEFAULT_RANGE = 15;
    final int[] RANGE_PRESETS = {15, 25, 50, 75, 100};
%>

<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager"  />
<% webManager.init(request, response, session, application, out ); %>

<%  // Get parameters
    int start = ParamUtils.getIntParameter(request,"start",0);
    int range = ParamUtils.getIntParameter(request,"range",webManager.getRowsPerPage("server-session-summary", DEFAULT_RANGE));
    boolean close = ParamUtils.getBooleanParameter(request,"close");
    String domainName = ParamUtils.getParameter(request,"hostname");

    Cookie csrfCookie = CookieUtils.getCookie(request, "csrf");
    String csrfParam = ParamUtils.getParameter(request, "csrf");

    if (close) {
        if (csrfCookie == null || csrfParam == null || !csrfCookie.getValue().equals(csrfParam)) {
            close = false;
        }
    }
    csrfParam = StringUtils.randomString(15);
    CookieUtils.setCookie(request, response, "csrf", csrfParam, -1);
    pageContext.setAttribute("csrf", csrfParam);
    if (request.getParameter("range") != null) {
        webManager.setRowsPerPage("server-session-summary", range);
    }

    // Get the session manager
    SessionManager sessionManager = webManager.getSessionManager();

    // Close all connections related to the specified domain name
    if (close) {
        try {
            final List<IncomingServerSession> incomingServerSessions = sessionManager.getIncomingServerSessions(domainName);
            for (Session incomingServerSession : incomingServerSessions) {
                incomingServerSession.close();
            }

            Collection<OutgoingServerSession> outgoingServerSessions = sessionManager.getOutgoingServerSessions(domainName);
            for (OutgoingServerSession outgoingServerSession : outgoingServerSessions) {
                if (outgoingServerSession != null) {
                    outgoingServerSession.close();
                }
            }
            // Log the event
            webManager.logEvent("closed server sessions for "+ domainName, "Closed " + incomingServerSessions.size() + " incoming and " + outgoingServerSessions + " outgoing session(s).");
            // wait one second
            Thread.sleep(250L);
        }
        catch (Exception ignored) {
            // Session might have disappeared on its own
        }
        // redirect back to this page
        response.sendRedirect("server-session-summary.jsp?close=success");
        return;
    }

    // Get the session count
    final Set<String> domainNames = new TreeSet<>();
    domainNames.addAll(sessionManager.getIncomingServers());
    domainNames.addAll(sessionManager.getOutgoingServers());
    final int sessionCount = domainNames.size();

    // paginator vars
    int numPages = (int)Math.ceil((double)sessionCount/(double)range);
    int curPage = (start/range) + 1;
    int maxIndex = Math.min(start + range, sessionCount);
%>

<html>
    <head>
        <title><fmt:message key="server.session.summary.title"/></title>
        <meta name="pageID" content="server-session-summary"/>
        <meta name="helpPage" content="view_active_server_sessions.html"/>
    </head>
    <body>

<%  if ("success".equals(request.getParameter("close"))) { %>

    <p class="jive-success-text">
    <fmt:message key="server.session.summary.close" />
    </p>

<%  } %>

<p>
<fmt:message key="server.session.summary.active" />: <b><%= domainNames.size() %></b>

<%  if (numPages > 1) { %>

    - <fmt:message key="global.showing" /> <%= (start+1) %>-<%= (start+range) %>

<%  } %>
 - <fmt:message key="server.session.summary.sessions_per_page" />:
<select size="1" onchange="location.href='server-session-summary.jsp?start=0&range=' + this.options[this.selectedIndex].value;">

    <% for (int aRANGE_PRESETS : RANGE_PRESETS) { %>

    <option value="<%= aRANGE_PRESETS %>"
            <%= (aRANGE_PRESETS == range ? "selected" : "") %>><%= aRANGE_PRESETS %>
    </option>

    <% } %>

</select>
</p>

<%  if (numPages > 1) { %>

    <p>
    <fmt:message key="global.pages" />:
    [
    <%  for (int i=0; i<numPages; i++) {
            String sep = ((i+1)<numPages) ? " " : "";
            boolean isCurrent = (i+1) == curPage;
    %>
        <a href="server-session-summary.jsp?start=<%= (i*range) %>"
         class="<%= ((isCurrent) ? "jive-current" : "") %>"
         ><%= (i+1) %></a><%= sep %>

    <%  } %>
    ]
    </p>

<%  } %>

<p>
<fmt:message key="server.session.summary.info">
    <fmt:param value="<a href=\"connection-settings-socket-s2s.jsp\">" />
    <fmt:param value="</a>" />
</fmt:message>
</p>

<div class="jive-table">
<table>
<thead>
    <tr>
        <th>&nbsp;</th>
        <th nowrap><fmt:message key="server.session.label.host" /></th>
        <th nowrap colspan="3"><fmt:message key="server.session.label.connection" /></th>
        <th nowrap><fmt:message key="server.session.label.protocol" /></th>
        <th nowrap style="text-align: center;"><fmt:message key="server.session.label.creation" /></th>
        <th nowrap style="text-align: center;"><fmt:message key="server.session.label.last_active" /></th>
        <th nowrap style="text-align: center;"><fmt:message key="server.session.label.close_connect" /></th>
    </tr>
</thead>
<tbody>
    <%  // Check if no out/in connection to/from a remote server exists
        if (domainNames.isEmpty()) {
    %>
        <tr>
            <td colspan="10">

                <fmt:message key="server.session.summary.not_session" />

            </td>
        </tr>

    <%  } %>

    <% int count = 0;
        final List<String> paginatedDomainNames = new ArrayList<>(domainNames).subList(start, maxIndex);
        for (String host : paginatedDomainNames) {
            count++;
            List<IncomingServerSession> inSessions = sessionManager.getIncomingServerSessions(host);
            List<OutgoingServerSession> outSessions = sessionManager.getOutgoingServerSessions(host);
            if (inSessions.isEmpty() && outSessions.isEmpty()) {
                // If the connections were just closed then skip this host
                continue;
            }
    %>
        <%@ include file="server-session-row.jspf" %>
    <%  } %>

</tbody>
</table>
</div>

<%  if (numPages > 1) { %>

    <p>
    <fmt:message key="global.pages" />:
    [
    <%  for (int i=0; i<numPages; i++) {
            String sep = ((i+1)<numPages) ? " " : "";
            boolean isCurrent = (i+1) == curPage;
    %>
        <a href="server-session-summary.jsp?start=<%= (i*range) %>"
         class="<%= ((isCurrent) ? "jive-current" : "") %>"
         ><%= (i+1) %></a><%= sep %>

    <%  } %>
    ]
    </p>

<%  } %>

<br>
<p>
<fmt:message key="server.session.summary.last_update" />: <%= JiveGlobals.formatDateTime(new Date()) %>
</p>

    </body>
</html>
