<%@ page contentType="text/html; charset=UTF-8" %>
<%--
  -
  - Copyright (C) 2004-2008 Jive Software, 2017-2025 Ignite Realtime Foundation. All rights reserved.
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
                 org.jivesoftware.util.StringUtils,
                 org.jivesoftware.util.CookieUtils,
                 org.jivesoftware.openfire.user.*,
                 java.net.URLEncoder"
    errorPage="error.jsp"
%><%@ page import="org.xmpp.packet.JID"%>
<%@ page import="org.jivesoftware.openfire.security.SecurityAuditManager" %>
<%@ page import="org.jivesoftware.util.StringUtils" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="org.jivesoftware.openfire.admin.AdminManager" %>
<%@ page import="java.nio.charset.StandardCharsets" %>

<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib prefix="admin" uri="admin" %>
<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager" />
<% webManager.init(request, response, session, application, out ); %>

<%  // Get parameters
    boolean save = ParamUtils.getBooleanParameter(request,"save");
    boolean success = ParamUtils.getBooleanParameter(request,"success");
    String username = ParamUtils.getParameter(request,"username");
    String name = ParamUtils.getParameter(request,"name");
    String email = ParamUtils.getParameter(request,"email");
    boolean isAdmin = ParamUtils.getBooleanParameter(request,"isadmin");
    Map<String, String> errors = new HashMap<>();
    Cookie csrfCookie = CookieUtils.getCookie(request, "csrf");
    String csrfParam = ParamUtils.getParameter(request, "csrf");
    if (save) {
        if (csrfCookie == null || csrfParam == null || !csrfCookie.getValue().equals(csrfParam)) {
            save = false;
            errors.put("csrf", "CSRF Failure");
        }
    }
    csrfParam = StringUtils.randomString(15);
    CookieUtils.setCookie(request, response, "csrf", csrfParam, -1);
    pageContext.setAttribute("csrf", csrfParam);

    // Handle a cancel
    if (request.getParameter("cancel") != null) {
        response.sendRedirect("user-properties.jsp?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8));
        return;
    }

    // Load the user object
    User user = webManager.getUserManager().getUser(username);

    // Handle a save
    if (save) {
        // If provider requires email, validate
        if (UserManager.getUserProvider().isEmailRequired()) {
            if (!StringUtils.isValidEmailAddress(email)) {
                errors.put("email","");
            }
        }
        // If provider requires name, validate
        if (UserManager.getUserProvider().isNameRequired()) {
            if (name == null || name.isEmpty()) {
                errors.put("name","");
            }
        }

        if (errors.isEmpty()) {
            user.setEmail(email);
            user.setName(name);

            if (!AdminManager.getAdminProvider().isReadOnly()) {
                boolean isCurrentAdmin = AdminManager.getInstance().isUserAdmin(user.getUsername(), false);
                if (isCurrentAdmin && !isAdmin) {
                    AdminManager.getInstance().removeAdminAccount(user.getUsername());
                }
                else if (!isCurrentAdmin && isAdmin) {
                    AdminManager.getInstance().addAdminAccount(user.getUsername());
                }
            }

            if (!SecurityAuditManager.getSecurityAuditProvider().blockUserEvents()) {
                // Log the event
                webManager.logEvent("edited user "+username, "set name = "+name+", email = "+email+", admin = "+isAdmin);
            }

            // Changes good, so redirect
            response.sendRedirect("user-properties.jsp?editsuccess=true&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8));
            return;
        }
    }

    pageContext.setAttribute("errors", errors);
    pageContext.setAttribute("success", success);
%>

<html>
    <head>
        <title><fmt:message key="user.edit.form.title"/></title>
        <meta name="subPageID" content="user-properties"/>
        <meta name="extraParams" content="<%= "username="+URLEncoder.encode(username, StandardCharsets.UTF_8) %>"/>
    </head>
    <body>

    <c:choose>
        <c:when test="${not empty errors}">
            <c:forEach var="err" items="${errors}">
                <admin:infobox type="error">
                    <c:choose>
                        <c:when test="${err.key eq 'csrf'}"><fmt:message key="global.csrf.failed" /></c:when>
                        <c:when test="${err.key eq 'name'}"><fmt:message key="user.create.invalid_name" /></c:when>
                        <c:when test="${err.key eq 'email'}"><fmt:message key="user.create.invalid_email" /></c:when>
                        <c:otherwise>
                            <c:if test="${not empty err.value}">
                                <fmt:message key="admin.error"/>: <c:out value="${err.value}"/>
                            </c:if>
                            (<c:out value="${err.key}"/>)
                        </c:otherwise>
                    </c:choose>
                </admin:infobox>
            </c:forEach>
        </c:when>
        <c:when test="${success}">
            <admin:infoBox type="success">
                <fmt:message key="user.edit.form.update" />
            </admin:infoBox>
        </c:when>
    </c:choose>

<p>
<fmt:message key="user.edit.form.info" />
</p>

<form action="user-edit-form.jsp">

<input type="hidden" name="csrf" value="${csrf}">
<input type="hidden" name="username" value="<%= StringUtils.escapeForXML(username) %>">
<input type="hidden" name="save" value="true">

<fieldset>
    <legend><fmt:message key="user.edit.form.property" /></legend>
    <div>
    <table style="width: 100%">
    <tbody>
        <tr>
            <td class="c1">
                <fmt:message key="user.create.username" />:
            </td>
            <td>
                <%= StringUtils.escapeHTMLTags(JID.unescapeNode(user.getUsername())) %>
            </td>
        </tr>
        <tr>
            <td class="c1">
                <label for="name"><fmt:message key="user.create.name" />: <%= UserManager.getUserProvider().isNameRequired() ? "*" : "" %></label>
            </td>
            <td>
                <input type="text" size="30" maxlength="150" id="name" name="name"
                 value="<%= StringUtils.escapeForXML(user.getName()) %>">
            </td>
        </tr>
        <tr>
            <td class="c1">
                <label for="email"><fmt:message key="user.create.email" />: <%= UserManager.getUserProvider().isEmailRequired() ? "*" : "" %></label>
            </td>
            <td>
                <input type="text" size="30" maxlength="150" id="email" name="email"
                 value="<%= ((user.getEmail()!=null) ? StringUtils.escapeForXML(user.getEmail()) : "") %>">
            </td>
        </tr>
        <% if (!AdminManager.getAdminProvider().isReadOnly()) { %>
        <tr>
            <td class="c1">
                <label for="isadmin"><fmt:message key="user.create.isadmin" /></label>
            </td>
            <td>
                <input type="checkbox" id="isadmin" name="isadmin"<%= AdminManager.getInstance().isUserAdmin(user.getUsername(), false) ? " checked='checked'" : "" %>>
                (<fmt:message key="user.create.admin_info"/>)
            </td>
        </tr>
        <% } %>
    </tbody>
    </table>
    </div>

</fieldset>

<br><br>

<input type="submit" value="<fmt:message key="global.save_properties" />">
<input type="submit" name="cancel" value="<fmt:message key="global.cancel" />">

</form>

<br/>

<span class="jive-description">
* <fmt:message key="user.create.requied" />
</span>

    </body>
</html>
