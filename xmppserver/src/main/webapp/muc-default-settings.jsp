<%@ page contentType="text/html; charset=UTF-8" %>
<%--
  -
  - Copyright (C) 2004-2010 Jive Software, 2017-2025 Ignite Realtime Foundation. All rights reserved.
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

<%@ page import="org.jivesoftware.util.*,
                 java.util.*,
                 org.jivesoftware.openfire.muc.spi.MUCPersistenceManager"
    errorPage="error.jsp"
%>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="java.nio.charset.StandardCharsets" %>

<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@ taglib uri="admin" prefix="admin" %>
<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager" />
<% webManager.init(request, response, session, application, out ); %>

<%  // Get parameters
    boolean save = request.getParameter("save") != null;
    boolean success = request.getParameter("success") != null;
    String mucname = ParamUtils.getParameter(request,"mucname");

    String publicRoom = ParamUtils.getParameter(request, "roomconfig_publicroom");
    String persistentRoom = ParamUtils.getParameter(request, "roomconfig_persistentroom");
    String retireOnDeletion = ParamUtils.getParameter(request, "roomconfig_retireondel");
    String moderatedRoom = ParamUtils.getParameter(request, "roomconfig_moderatedroom");
    String membersOnly = ParamUtils.getParameter(request, "roomconfig_membersonly");
    String nonanonymous = ParamUtils.getParameter(request, "roomconfig_nonanonymous");
    String allowInvites = ParamUtils.getParameter(request, "roomconfig_allowinvites");
    String changeSubject = ParamUtils.getParameter(request, "roomconfig_changesubject");
    String reservedNick = ParamUtils.getParameter(request, "roomconfig_reservednick");
    String canChangeNick = ParamUtils.getParameter(request, "roomconfig_canchangenick");
    String registrationEnabled = ParamUtils.getParameter(request, "roomconfig_registration");
    String enableLog = ParamUtils.getParameter(request, "roomconfig_enablelogging");
    String preserveHistOnRoomDeletion = ParamUtils.getParameter(request, "roomconfig_preservehistondel");
    String maxUsers = ParamUtils.getParameter(request, "roomconfig_maxusers");
    String broadcastModerator = ParamUtils.getParameter(request, "roomconfig_broadcastmoderator");
    String broadcastParticipant = ParamUtils.getParameter(request, "roomconfig_broadcastparticipant");
    String broadcastVisitor = ParamUtils.getParameter(request, "roomconfig_broadcastvisitor");
    String allowpm = ParamUtils.getParameter(request, "roomconfig_allowpm");

    if (!webManager.getMultiUserChatManager().isServiceRegistered(mucname)) {
        // The requested service name does not exist so return to the list of the existing rooms
        response.sendRedirect("muc-service-summary.jsp");
        return;
    }

    // Handle a save
    Map<String,String> errors = new HashMap<>();
    Cookie csrfCookie = CookieUtils.getCookie(request, "csrf");
    String csrfParam = ParamUtils.getParameter(request, "csrf");

    if (save) {
        if (csrfCookie == null || csrfParam == null || !csrfCookie.getValue().equals(csrfParam)) {
            save = false;
            errors.put("csrf", "CSRF Failure!");
        }
    }
    csrfParam = StringUtils.randomString(15);
    CookieUtils.setCookie(request, response, "csrf", csrfParam, -1);
    pageContext.setAttribute("csrf", csrfParam);
    if (save) {
        try {
            if (maxUsers == null || maxUsers.isEmpty()) {
                maxUsers = "0"; // 0 indicates no limit.
            }
            Integer.parseInt(maxUsers);
            MUCPersistenceManager.setProperty(mucname, "room.maxUsers", maxUsers);
        }
        catch (Exception e) {
            errors.put("max_users", "max_users");
        }
        if ( Arrays.asList("anyone", "moderators", "participants", "none").contains(allowpm)) {
            MUCPersistenceManager.setProperty(mucname, "room.allowpm", allowpm);
        } else {
            errors.put("allowpm", "allowpm");
        }
        if (errors.isEmpty()) {
            if (publicRoom != null && !publicRoom.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.publicRoom", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.publicRoom", "false");
            }
            if (persistentRoom != null && !persistentRoom.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.persistent", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.persistent", "false");
            }
            if (retireOnDeletion != null && !retireOnDeletion.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.retireOnDeletion", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.retireOnDeletion", "false");
            }
            if (moderatedRoom != null && !moderatedRoom.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.moderated", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.moderated", "false");
            }
            if (membersOnly != null && !membersOnly.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.membersOnly", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.membersOnly", "false");
            }
            if (nonanonymous != null && !nonanonymous.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.canAnyoneDiscoverJID", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.canAnyoneDiscoverJID", "false");
            }
            if (allowInvites != null && !allowInvites.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.canOccupantsInvite", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.canOccupantsInvite", "false");
            }
            if (changeSubject != null && !changeSubject.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.canOccupantsChangeSubject", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.canOccupantsChangeSubject", "false");
            }
            if (reservedNick != null && !reservedNick.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.loginRestrictedToNickname", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.loginRestrictedToNickname", "false");
            }
            if (canChangeNick != null && !canChangeNick.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.canChangeNickname", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.canChangeNickname", "false");
            }
            if (registrationEnabled != null && !registrationEnabled.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.registrationEnabled", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.registrationEnabled", "false");
            }
            if (enableLog != null && !enableLog.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.logEnabled", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.logEnabled", "false");
            }
            if (preserveHistOnRoomDeletion != null && !preserveHistOnRoomDeletion.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.preserveHistOnRoomDeletion", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.preserveHistOnRoomDeletion", "false");
            }
            if (broadcastModerator != null && !broadcastModerator.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.broadcastModerator", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.broadcastModerator", "false");
            }
            if (broadcastParticipant != null && !broadcastParticipant.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.broadcastParticipant", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.broadcastParticipant", "false");
            }
            if (broadcastVisitor != null && !broadcastVisitor.trim().isEmpty()) {
                MUCPersistenceManager.setProperty(mucname, "room.broadcastVisitor", "true");
            }
            else {
                MUCPersistenceManager.setProperty(mucname, "room.broadcastVisitor", "false");
            }
        }

        response.sendRedirect("muc-default-settings.jsp?success=true&mucname="+URLEncoder.encode(mucname, StandardCharsets.UTF_8));
        return;
    }

    pageContext.setAttribute("errors", errors);
    pageContext.setAttribute("success", success);
    pageContext.setAttribute("mucname", mucname);
    pageContext.setAttribute("publicRoom", MUCPersistenceManager.getBooleanProperty(mucname, "room.publicRoom", true));
    pageContext.setAttribute("persistent", MUCPersistenceManager.getBooleanProperty(mucname, "room.persistent", false));
    pageContext.setAttribute("retireOnDeletion", MUCPersistenceManager.getBooleanProperty(mucname, "room.retireOnDeletion", false));
    pageContext.setAttribute("moderated", MUCPersistenceManager.getBooleanProperty(mucname, "room.moderated", false));
    pageContext.setAttribute("membersOnly", MUCPersistenceManager.getBooleanProperty(mucname, "room.membersOnly", false));
    pageContext.setAttribute("canAnyoneDiscoverJID", MUCPersistenceManager.getBooleanProperty(mucname, "room.canAnyoneDiscoverJID", true));
    pageContext.setAttribute("canOccupantsInvite", MUCPersistenceManager.getBooleanProperty(mucname, "room.canOccupantsInvite", false));
    pageContext.setAttribute("canOccupantsChangeSubject", MUCPersistenceManager.getBooleanProperty(mucname, "room.canOccupantsChangeSubject", false));
    pageContext.setAttribute("loginRestrictedToNickname", MUCPersistenceManager.getBooleanProperty(mucname, "room.loginRestrictedToNickname", false));
    pageContext.setAttribute("canChangeNickname", MUCPersistenceManager.getBooleanProperty(mucname, "room.canChangeNickname", true));
    pageContext.setAttribute("registrationEnabled", MUCPersistenceManager.getBooleanProperty(mucname, "room.registrationEnabled", true));
    pageContext.setAttribute("logEnabled", MUCPersistenceManager.getBooleanProperty(mucname, "room.logEnabled", true));
    pageContext.setAttribute("preserveHistOnRoomDeletion", MUCPersistenceManager.getBooleanProperty(mucname, "room.preserveHistOnRoomDeletion", true));
    pageContext.setAttribute("maxUsers", MUCPersistenceManager.getIntProperty(mucname, "room.maxUsers", 30));
    pageContext.setAttribute("broadcastModerator", MUCPersistenceManager.getBooleanProperty(mucname, "room.broadcastModerator", true));
    pageContext.setAttribute("broadcastParticipant", MUCPersistenceManager.getBooleanProperty(mucname, "room.broadcastParticipant", true));
    pageContext.setAttribute("broadcastVisitor", MUCPersistenceManager.getBooleanProperty(mucname, "room.broadcastVisitor", true));
    pageContext.setAttribute("allowpm", MUCPersistenceManager.getProperty(mucname, "room.allowpm", "anyone"));
    pageContext.setAttribute("xxx", MUCPersistenceManager.getBooleanProperty(mucname, "room.xxx", true));
    pageContext.setAttribute("xxx", MUCPersistenceManager.getBooleanProperty(mucname, "room.xxx", true));
    pageContext.setAttribute("xxx", MUCPersistenceManager.getBooleanProperty(mucname, "room.xxx", true));
%>

<html>
    <head>
        <title><fmt:message key="muc.default.settings.title"/></title>
        <meta name="subPageID" content="muc-defaultsettings"/>
        <meta name="extraParams" content="<%= "mucname="+URLEncoder.encode(mucname, StandardCharsets.UTF_8) %>"/>
        <meta name="helpPage" content="set_group_chat_room_creation_permissions.html"/>
    </head>

    <body>

    <p>
        <c:url var="mucserviceeditformlink" value="muc-service-edit-form.jsp">
            <c:param name="mucname" value="${mucname}"/>
        </c:url>
        <fmt:message key="muc.default.settings.info" />
        <fmt:message key="groupchat.service.settings_affect" /><b><a href="${mucserviceeditformlink}"><c:out value="${mucname}"/></a></b>
    </p>

    <c:choose>
        <c:when test="${not empty errors}">
            <c:forEach var="err" items="${errors}">
                <admin:infobox type="error">
                    <c:choose>
                        <c:when test="${err.key eq 'csrf'}"><fmt:message key="global.csrf.failed" /></c:when>
                        <c:otherwise><fmt:message key="muc.default.settings.error" /></c:otherwise>
                    </c:choose>
                </admin:infobox>
            </c:forEach>
        </c:when>
        <c:when test="${success}">
            <admin:infobox type="success">
                <fmt:message key="muc.default.settings.update" />
            </admin:infobox>
        </c:when>
    </c:choose>

    <!-- BEGIN 'Default Room Settings' -->
    <form action="muc-default-settings.jsp?save" method="post">

    <input type="hidden" name="csrf" value="${csrf}">
    <input type="hidden" name="mucname" value="${fn:escapeXml(mucname)}" />

    <fmt:message key="muc.default.settings.title" var="settingsTitle"/>
    <admin:contentBox title="${settingsTitle}">
        <table>
            <colgroup>
                <col style="width: 1%"/>
                <col style="width: 99%"/>
            </colgroup>
        <tbody>
            <tr>
                <td><input name="roomconfig_publicroom" value="true" id="publicRoom" type="checkbox" ${publicRoom ? 'checked' : ''}></td>
                <td><label for="publicRoom"><fmt:message key="muc.default.settings.public_room" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_persistentroom" value="true" id="persistentRoom" type="checkbox" ${persistent ? 'checked' : ''}></td>
                <td><label for="persistentRoom"><fmt:message key="muc.default.settings.persistent_room" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_retireondel" value="true" id="retireOnDeletion" type="checkbox" ${retireOnDeletion ? 'checked' : ''}></td>
                <td><label for="retireOnDeletion"><fmt:message key="muc.default.settings.retire" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_moderatedroom" value="true" id="moderated" type="checkbox" ${moderated ? 'checked' : ''}></td>
                <td><label for="moderated"><fmt:message key="muc.default.settings.moderated" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_membersonly" value="true" id="membersOnly" type="checkbox" ${membersOnly ? 'checked' : ''}></td>
                <td><label for="membersOnly"><fmt:message key="muc.default.settings.members_only" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_nonanonymous" value="true" id="nonanonymous" type="checkbox" ${canAnyoneDiscoverJID ? 'checked' : ''}></td>
                <td><label for="nonanonymous"><fmt:message key="muc.default.settings.can_anyone_discover_jid" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_allowinvites" value="true" id="allowInvites" type="checkbox" ${canOccupantsInvite ? 'checked' : ''}></td>
                <td><label for="allowInvites"><fmt:message key="muc.default.settings.allow_invites" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_changesubject" value="true" id="changeSubject" type="checkbox" ${canOccupantsChangeSubject ? 'checked' : ''}></td>
                <td><label for="changeSubject"><fmt:message key="muc.default.settings.change_subject" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_reservednick" value="true" id="reservedNick" type="checkbox" ${loginRestrictedToNickname ? 'checked' : ''}></td>
                <td><label for="reservedNick"><fmt:message key="muc.default.settings.reserved_nick" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_canchangenick" value="true" id="canChangeNick" type="checkbox" ${canChangeNickname ? 'checked' : ''}></td>
                <td><label for="canChangeNick"><fmt:message key="muc.default.settings.can_change_nick" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_registration" value="true" id="registration" type="checkbox" ${registrationEnabled ? 'checked' : ''}></td>
                <td><label for="registration"><fmt:message key="muc.default.settings.registration" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_enablelogging" value="true" id="enableLogging" type="checkbox" ${logEnabled ? 'checked' : ''}></td>
                <td><label for="enableLogging"><fmt:message key="muc.default.settings.enable_logging" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_preservehistondel" value="true" id="preserveHistOnRoomDeletion" type="checkbox" ${preserveHistOnRoomDeletion ? 'checked' : ''}></td>
                <td><label for="preserveHistOnRoomDeletion"><fmt:message key="muc.default.settings.preserve_hist_on_room_deletion" /></label></td>
            </tr>
            <tr>
                <td>&nbsp;</td>
                <td>
                    <label for="roomconfig_maxusers"><fmt:message key="muc.default.settings.max_users" />:</label>
                    <input type="number" name="roomconfig_maxusers" id="roomconfig_maxusers" min="1" value="${maxUsers eq 0 ? '' : maxUsers}" size="5">
                    <fmt:message key="muc.room.edit.form.empty_nolimit" />
                </td>
            </tr>
            <tr>
                <td><input name="roomconfig_broadcastmoderator" value="true" id="broadcastModerator" type="checkbox" ${broadcastModerator ? 'checked' : ''}></td>
                <td><label for="broadcastModerator"><fmt:message key="muc.default.settings.broadcast_presence_moderator" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_broadcastparticipant" value="true" id="broadcastParticipant" type="checkbox" ${broadcastParticipant ? 'checked' : ''}></td>
                <td><label for="broadcastParticipant"><fmt:message key="muc.default.settings.broadcast_presence_participant" /></label></td>
            </tr>
            <tr>
                <td><input name="roomconfig_broadcastvisitor" value="true" id="broadcastVisitor" type="checkbox" ${broadcastVisitor ? 'checked' : ''}></td>
                <td><label for="broadcastVisitor"><fmt:message key="muc.default.settings.broadcast_presence_visitor" /></label></td>
            </tr>
            <tr>
                <td>

                </td>
                <td><label for="allowpm"><fmt:message key="muc.default.settings.allowpm" /></label>
                    <select name="roomconfig_allowpm" id="allowpm">
                        <option value="none" ${allowpm eq 'none' ? 'selected' : ''}><fmt:message key="muc.default.settings.none" /></option>
                        <option value="moderators" ${allowpm eq 'moderators' ? 'selected' : ''}><fmt:message key="muc.default.settings.moderator" /></option>
                        <option value="participants" ${allowpm eq 'participants' ? 'selected' : ''}><fmt:message key="muc.default.settings.participant" /></option>
                        <option value="anyone" ${allowpm eq 'anyone' ? 'selected' : ''}><fmt:message key="muc.default.settings.anyone" /></option>
                    </select>
                </td>
            </tr>
        </tbody>
        </table>
    </admin:contentBox>
    <input type="submit" value="<fmt:message key="global.save_settings" />">

    </form>
    <!-- END 'Default Room Settings' -->

</body>
</html>
