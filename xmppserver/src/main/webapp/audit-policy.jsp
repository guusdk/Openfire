<%@ page contentType="text/html; charset=UTF-8" %>
<%--
  - Copyright (C) 2016-2025 Ignite Realtime Foundation. All rights reserved.
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

<%@ page import="org.jivesoftware.util.ParamUtils,
                 org.jivesoftware.util.CookieUtils,
                 org.jivesoftware.openfire.XMPPServer,
                 org.jivesoftware.openfire.audit.AuditManager,
                 org.jivesoftware.openfire.user.UserNotFoundException,
                 org.jivesoftware.util.StringUtils,
                 org.xmpp.packet.JID,
                 java.io.File"
    errorPage="error.jsp"
%>
<%@ page import="java.util.*"%>
<%@ page import="java.time.Duration" %>

<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="admin" prefix="admin" %>

<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager"  />
<% webManager.init(request, response, session, application, out ); %>

<html>
<head>
<title><fmt:message key="audit.policy.title"/></title>
<meta name="pageID" content="server-audit-policy"/>
<meta name="helpPage" content="set_server_traffic_auditing_policy.html"/>
</head>
<body>



<%   // Get parameters:
    boolean update = request.getParameter("update") != null;
    boolean auditEnabled = ParamUtils.getBooleanParameter(request,"auditEnabled");
    boolean auditMessages = ParamUtils.getBooleanParameter(request,"auditMessages");
    boolean auditPresence = ParamUtils.getBooleanParameter(request,"auditPresence");
    boolean auditIQ = ParamUtils.getBooleanParameter(request,"auditIQ");
    String maxTotalSize = ParamUtils.getParameter(request,"maxTotalSize");
    String maxFileSize = ParamUtils.getParameter(request,"maxFileSize");
    String maxDays = ParamUtils.getParameter(request,"maxDays");
    String logTimeout = ParamUtils.getParameter(request,"logTimeout");
    String logDir = ParamUtils.getParameter(request,"logDir");
    String ignore = ParamUtils.getParameter(request,"ignore");


    // Get an audit manager:
    AuditManager auditManager = XMPPServer.getInstance().getAuditManager();

    Map<String,String> errors = new HashMap<>();
    Cookie csrfCookie = CookieUtils.getCookie(request, "csrf");
    String csrfParam = ParamUtils.getParameter(request, "csrf");
    boolean csrfStatus = true;

    if (update) {
        if (csrfCookie == null || csrfParam == null || !csrfCookie.getValue().equals(csrfParam)) {
            update = false;
            errors.put("csrf", "csrf");
            csrfStatus = false;
        }
    }
    csrfParam = StringUtils.randomString(16);
    CookieUtils.setCookie(request, response, "csrf", csrfParam, -1);
    pageContext.setAttribute("csrf", csrfParam);
    if (update) {
        auditManager.setEnabled(auditEnabled);
        auditManager.setAuditMessage(auditMessages);
        auditManager.setAuditPresence(auditPresence);
        auditManager.setAuditIQ(auditIQ);
        /*
        auditManager.setAuditXPath(auditXPath);
        if (newXpathQuery != null) {
            auditManager.addXPath(newXpathQuery);
        }
        for (int i=0; i<xpathQuery.length; i++) {
            auditManager.removeXPath(xpathQuery[i]);
        }
        */
        try {
            auditManager.setMaxTotalSize(Integer.parseInt(maxTotalSize));
        } catch (Exception e){
            errors.put("maxTotalSize","maxTotalSize");
        }
        try {
            auditManager.setMaxFileSize(Integer.parseInt(maxFileSize));
        } catch (Exception e){
            errors.put("maxFileSize","maxFileSize");
        }
        try {
            auditManager.setRetention(Duration.ofDays(Integer.parseInt(maxDays)));
        } catch (Exception e){
            errors.put("maxDays","maxDays");
        }
        try {
            auditManager.setLogTimeout(Duration.ofSeconds(Integer.parseInt(logTimeout)));
        } catch (Exception e){
            errors.put("logTimeout","logTimeout");
        }
        if (logDir == null || logDir.trim().isEmpty()) {
            errors.put("logDir","logDir");
        }
        else {
            if (new File(logDir).isDirectory()) {
                auditManager.setLogDir(logDir);
            }
            else {
                errors.put("logDir","logDir");
            }
        }
        if (errors.isEmpty()){
            if (ignore == null){
                // remove all ignored users
                auditManager.setIgnoreList(new ArrayList<>());
            }
            else {
                // Set the new ignore list
                Collection<String> newIgnoreList = new HashSet<>(ignore.length());
                StringTokenizer tokenizer = new StringTokenizer(ignore, ", \t\n\r\f");
                while (tokenizer.hasMoreTokens()) {
                    String tok = tokenizer.nextToken();
                    String username = tok;
                    if (tok.contains("@")) {
                        if (tok.contains("@" + webManager.getServerInfo().getXMPPDomain())) {
                           username = new JID(tok).getNode();
                        }
                        else {
                            // Skip this JID since it belongs to a remote server
                            continue;
                        }
                    }
                    try {
                        webManager.getUserManager().getUser(username);
                        newIgnoreList.add(username);
                    }
                    catch (UserNotFoundException e){
                    }
                }
                auditManager.setIgnoreList(newIgnoreList);
            }
            // Log the event
            // TODO: Should probably log more here
            webManager.logEvent("updated stanza audit policy", null);
        // All done, redirect
        %>

    <admin:infoBox type="success">
        <fmt:message key="audit.policy.settings.saved_successfully" />
    </admin:infoBox>

        <%
        }
        else if (!csrfStatus) {
        %>
    <admin:infobox type="error"><fmt:message key="global.csrf.failed" /></admin:infobox>
        <%
        }
    }

    // Set page vars
    if (errors.isEmpty()) {
        auditEnabled = auditManager.isEnabled();
        auditMessages = auditManager.isAuditMessage();
        auditPresence = auditManager.isAuditPresence();
        auditIQ = auditManager.isAuditIQ();
        maxTotalSize = Integer.toString(auditManager.getMaxTotalSize());
        maxFileSize = Integer.toString(auditManager.getMaxFileSize());
        maxDays = Long.toString(auditManager.getRetention().toDays());
        logTimeout = Long.toString(auditManager.getLogTimeout().toSeconds());
        logDir = auditManager.getLogDir();
        StringBuilder ignoreList = new StringBuilder();
        for (String username : auditManager.getIgnoreList()) {
            if (ignoreList.isEmpty()) {
                ignoreList.append(username);
            }
            else {
                ignoreList.append(", ").append(username);
            }
        }
        ignore = ignoreList.toString();
    }
%>

<p>
<fmt:message key="title" />
<fmt:message key="audit.policy.title_info" />
</p>

<!-- BEGIN 'Set Message Audit Policy' -->
<form action="audit-policy.jsp" name="f">
    <input type="hidden" name="csrf" value="${csrf}">
    <div class="jive-contentBoxHeader">
        <fmt:message key="audit.policy.policytitle" />
    </div>
    <div class="jive-contentBox">
        <table>
        <tbody>
            <tr>
                <td style="width: 1%; white-space: nowrap">
                    <input type="radio" name="auditEnabled" value="false" id="rb01"
                     <%= (!auditEnabled ? "checked" : "") %>>
                </td>
                <td>
                    <label for="rb01">
                    <b><fmt:message key="audit.policy.label_disable_auditing" /></b> <fmt:message key="audit.policy.label_disable_auditing_info" />
                    </label>
                </td>
            </tr>
            <tr>
                <td style="width: 1%; white-space: nowrap">
                    <input type="radio" name="auditEnabled" value="true" id="rb02"
                     <%= (auditEnabled ? "checked" : "") %>>
                </td>
                <td>
                    <label for="rb02">
                    <b><fmt:message key="audit.policy.label_enable_auditing" /></b> <fmt:message key="audit.policy.label_enable_auditing_info" />
                    </label>
                </td>
            </tr>
            <tr>
                <td style="width: 1%; white-space: nowrap">
                    &nbsp;
                </td>
                <td>
                    <table>
                    <tr>
                        <td style="width: 1%; white-space: nowrap" class="c1">
                            <label for="logDir"><fmt:message key="audit.policy.log_directory" /></label>
                        </td>
                        <td>
                            <input type="text" size="50" maxlength="150" id="logDir" name="logDir"
                             value="<%= ((logDir != null) ? StringUtils.escapeForXML(logDir) : "") %>">

                        <%  if (errors.get("logDir") != null) { %>

                            <span class="jive-error-text">
                            <fmt:message key="audit.policy.valid_log_directory" />
                            </span>

                        <%  } %>

                        </td>
                    </tr>
                    <tr>
                        <td style="width: 1%; white-space: nowrap" class="c1">
                            <label for="maxTotalSize"><fmt:message key="audit.policy.maxtotal_size" /></label>
                        </td>
                        <td>
                            <input type="text" size="15" maxlength="50" id="maxTotalSize" name="maxTotalSize"
                             value="<%= ((maxTotalSize != null) ? StringUtils.escapeForXML(maxTotalSize) : "") %>">

                        <%  if (errors.get("maxTotalSize") != null) { %>

                            <span class="jive-error-text">
                            <fmt:message key="audit.policy.validnumber" />
                            </span>

                        <%  } %>

                        </td>
                    </tr>
                    <tr>
                        <td style="width: 1%; white-space: nowrap" class="c1">
                            <label for="maxFileSize"><fmt:message key="audit.policy.maxfile_size" /></label>
                        </td>
                        <td>
                            <input type="text" size="15" maxlength="50" id="maxFileSize" name="maxFileSize"
                             value="<%= ((maxFileSize != null) ? StringUtils.escapeForXML(maxFileSize) : "") %>">

                        <%  if (errors.get("maxFileSize") != null) { %>

                            <span class="jive-error-text">
                            <fmt:message key="audit.policy.validnumber" />
                            </span>

                        <%  } %>

                        </td>
                    </tr>
                    <tr>
                        <td style="width: 1%; white-space: nowrap" class="c1">
                            <label for="maxDays"><fmt:message key="audit.policy.maxdays_number" /></label>
                        </td>
                        <td>
                            <input type="text" size="15" maxlength="50" id="maxDays" name="maxDays"
                             value="<%= ((maxDays != null) ? StringUtils.escapeForXML(maxDays) : "") %>">

                            <%  if (errors.get("maxDays") != null) { %>

                                <span class="jive-error-text">
                                <fmt:message key="audit.policy.validnumber" />
                                </span>

                            <%  } %>

                        </td>
                    </tr>
                    <tr>
                        <td style="width: 1%; white-space: nowrap" class="c1">
                            <label for="logTimeout"><fmt:message key="audit.policy.flush_interval" /></label>
                        </td>
                        <td>
                            <input type="text" size="15" maxlength="50" id="logTimeout" name="logTimeout"
                             value="<%= ((logTimeout != null) ? StringUtils.escapeForXML(logTimeout) : "") %>">

                        <%  if (errors.get("logTimeout") != null) { %>

                            <span class="jive-error-text">
                            <fmt:message key="audit.policy.validnumber" />
                            </span>

                        <%  } %>

                        </td>
                    </tr>
                    <tr>
                        <td style="width: 1%; white-space: nowrap" class="c1">
                            <fmt:message key="audit.policy.packet_audit" />
                        </td>
                        <td>

                            <table>
                            <tr>
                                <td style="width: 1%; white-space: nowrap">
                                    <input type="checkbox" name="auditMessages" id="cb01"
                                     onclick="this.form.auditEnabled[1].checked=true;"
                                     <%= (auditMessages ? "checked" : "") %>>
                                </td>
                                <td>
                                    <label for="cb01">
                                    <b><fmt:message key="audit.policy.label_audit_messenge_packets" /></b>
                                    </label>
                                </td>
                            </tr>
                            <tr>
                                <td style="width: 1%; white-space: nowrap">
                                    <input type="checkbox" name="auditPresence" id="cb02"
                                     onclick="this.form.auditEnabled[1].checked=true;"
                                     <%= (auditPresence ? "checked" : "") %>>
                                </td>
                                <td>
                                    <label for="cb02">
                                    <b><fmt:message key="audit.policy.label_audit_presence_packets" /></b>
                                    </label>
                                </td>
                            </tr>
                            <tr>
                                <td style="width: 1%; white-space: nowrap">
                                    <input type="checkbox" name="auditIQ" id="cb03"
                                     onclick="this.form.auditEnabled[1].checked=true;"
                                     <%= (auditIQ ? "checked" : "") %>>
                                </td>
                                <td>
                                    <label for="cb03">
                                    <b><fmt:message key="audit.policy.label_audit_iq_packets" /></b>
                                    </label>
                                </td>
                            </tr>
                            </table>
                        </td>
                    </tr>
                    <tr style="vertical-align: top;">
                        <td style="width: 1%; white-space: nowrap" class="c1">
                            <label for="ignore"><fmt:message key="audit.policy.ignore" /></label>
                        </td>
                        <td>
                            <textarea id="ignore" name="ignore" cols="40" rows="3" wrap="virtual"><%= ((ignore != null) ? StringUtils.escapeHTMLTags(ignore) : "") %></textarea>
                            <%  if (errors.get("ignore") != null) { %>

                                <span class="jive-error-text">
                                <fmt:message key="audit.policy.validignore" />
                                </span>

                            <%  } %>
                        </td>
                    </tr>
                    </table>
                </td>
            </tr>
        </tbody>
        </table>
        <table>
            <tr>
                <td style="width: 1%; white-space: nowrap" class="c1">
                    <fmt:message key="audit.policy.queued_packets" />
                </td>
                <td>
                     <%= auditManager.getAuditor().getQueuedPacketsNumber() %>
                </td>
            </tr>
        </table>
    </div>
    <input type="submit" name="update" value="<fmt:message key="global.save_settings" />">
</form>
<!-- END 'Set Message Audit Policy' -->


</body>
</html>
