/*
 * Copyright (C) 2004-2008 Jive Software. 2022 Ignite Realtime Foundation. All rights reserved.
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

package org.jivesoftware.openfire.group;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.locks.Lock;

import com.google.common.collect.Interner;
import com.google.common.collect.Interners;
import org.apache.commons.lang3.StringUtils;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.event.GroupEventDispatcher;
import org.jivesoftware.openfire.event.GroupEventListener;
import org.jivesoftware.openfire.event.UserEventDispatcher;
import org.jivesoftware.openfire.event.UserEventListener;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.util.CacheableOptional;
import org.jivesoftware.util.SystemProperty;
import org.jivesoftware.util.cache.Cache;
import org.jivesoftware.util.cache.CacheFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import javax.annotation.Nonnull;

/**
 * Manages groups.
 *
 * @see Group
 * @author Matt Tucker
 */
public class GroupManager {

    public static final SystemProperty<Class> GROUP_PROVIDER = SystemProperty.Builder.ofType(Class.class)
        .setKey("provider.group.className")
        .setBaseClass(GroupProvider.class)
        .setDefaultValue(DefaultGroupProvider.class)
        .addListener(GroupManager::initProvider)
        .setDynamic(true)
        .build();

    private static final Logger Log = LoggerFactory.getLogger(GroupManager.class);

    private static GroupManager INSTANCE;

    private static final Interner<JID> userBasedMutex = Interners.newWeakInterner();
    private static final Interner<PagedGroupNameKey> pagedGroupNameKeyInterner = Interners.newWeakInterner();

    private static final String GROUP_COUNT_KEY = "GROUP_COUNT";
    private static final String GROUP_NAMES_KEY = "GROUP_NAMES";
    private static final String USER_GROUPS_KEY = "USER_GROUPS";

    private static final Object GROUP_COUNT_LOCK = new Object();
    private static final Object GROUP_NAMES_LOCK = new Object();
    private static final Object USER_GROUPS_LOCK = new Object();

    /**
     * Returns a singleton instance of GroupManager.
     *
     * @return a GroupManager instance.
     */
    public static synchronized GroupManager getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new GroupManager();
        }
        return INSTANCE;
    }

    private Cache<String, CacheableOptional<Group>> groupCache;
    private Cache<String, Serializable> groupMetaCache;
    private static GroupProvider provider;

    private GroupManager() {
        // Initialize caches.
        groupCache = CacheFactory.createCache("Group"); // TODO determine if this works in a cluster (should this be a local cache?)

        // A cache for meta-data around groups: count, group names, groups associated with
        // a particular user
        groupMetaCache = CacheFactory.createCache("Group Metadata Cache"); // TODO determine if this works in a cluster (should this be a local cache?)

        initProvider(GROUP_PROVIDER.getValue());

        GroupEventDispatcher.addListener(new GroupEventListener() {
            @Override
            public void groupCreated(Group group, Map params) {

                // Adds default properties if they don't exist, since the creator of
                // the group could set them.
                if (group.getSharedWith() == null) {
                    group.shareWithNobody();
                }
                
                // Since the group could be created by the provider, add it possible again
                groupCache.put(group.getName(), CacheableOptional.of(group));

                // Evict only the information related to Groups.
                // Do not evict groups with 'user' as keys.
                clearGroupCountCache();
                clearGroupNameCache();

                // Evict cached information for affected users
                evictCachedUsersForGroup(group);

                // Evict cached paginated group names
                evictCachedPaginatedGroupNames();
            }

            @Override
            public void groupDeleting(Group group, Map params) {
                // Since the group could be deleted by the provider, remove it possible again
                groupCache.put(group.getName(), CacheableOptional.of( null ));

                // Evict only the information related to Groups.
                // Do not evict groups with 'user' as keys.
                clearGroupCountCache();
                clearGroupNameCache();

                // Evict cached information for affected users
                evictCachedUsersForGroup(group);

                // Evict cached paginated group names
                evictCachedPaginatedGroupNames();
            }

            @Override
            public void groupModified(Group group, Map params) {
                String type = (String)params.get("type");
                // If shared group settings changed, expire the cache.
                if (type != null) {
                    if (type.equals("propertyModified") ||
                        type.equals("propertyDeleted") || type.equals("propertyAdded"))
                    {
                        Object key = params.get("propertyKey");
                        if ("sharedRoster.showInRoster".equals(key) || "*".equals(key))
                        {
                            clearGroupNameCache();

                            String originalValue = (String) params.get("originalValue");
                            String newValue = group.getProperties().get("sharedRoster.showInRoster");

                            // 'showInRoster' has changed
                            if (!StringUtils.equals(originalValue, newValue)) {

                                if ("everybody".equals(originalValue) || "everybody".equals(newValue)) {
                                    evictCachedUserSharedGroups();
                                }
                            }
                        } else if ("sharedRoster.groupList".equals(key)) {

                            String originalValue = (String) params.get("originalValue");
                            String newValue = group.getProperties().get("sharedRoster.groupList");

                            // 'groupList' has changed
                            if (!StringUtils.equals(originalValue, newValue)) {
                                evictCachedUsersForGroup( group );

                                // Also clear the cache for groups that have been removed from the shared list.
                                if ( originalValue != null ) {
                                    final Set<String> newGroupNames = newValue == null ? new HashSet<>() : splitGroupList(newValue);
                                    final Set<String> oldGroupNames = splitGroupList(originalValue);

                                    // The 'new' group names are already handled by the evictCachedUserForGroup call above. No need to do that twice.
                                    oldGroupNames.removeAll(newGroupNames);
                                    oldGroupNames.forEach( g -> evictCachedUsersForGroup(g) );
                                }
                            }
                        }
                    }
                    // clean up cache for old group name
                    if (type.equals("nameModified")) {
                        String originalName = (String) params.get("originalValue");
                        if (originalName != null) {
                            groupCache.remove(originalName);
                        }

                        clearGroupNameCache();

                        // Evict cached information for affected users
                        evictCachedUsersForGroup(group);

                        // Evict cached paginated group names
                        evictCachedPaginatedGroupNames();
                        
                    }
                }
                // Set object again in cache. This is done so that other cluster nodes
                // get refreshed with latest version of the object
                groupCache.put(group.getName(), CacheableOptional.of(group));
            }

            @Override
            public void memberAdded(Group group, Map params) {
                // Set object again in cache. This is done so that other cluster nodes
                // get refreshed with latest version of the object
                groupCache.put(group.getName(), CacheableOptional.of(group));
                
                // Remove only the collection of groups the member belongs to.
                String member = (String) params.get("member");
                evictCachedUserForGroup(member);
            }

            @Override
            public void memberRemoved(Group group, Map params) {
                // Set object again in cache. This is done so that other cluster nodes
                // get refreshed with latest version of the object
                groupCache.put(group.getName(), CacheableOptional.of(group));
                
                // Remove only the collection of groups the member belongs to.
                String member = (String) params.get("member");
                evictCachedUserForGroup(member);
            }

            @Override
            public void adminAdded(Group group, Map params) {
                // Set object again in cache. This is done so that other cluster nodes
                // get refreshed with latest version of the object
                groupCache.put(group.getName(), CacheableOptional.of(group));
                
                // Remove only the collection of groups the member belongs to.
                String member = (String) params.get("admin");
                evictCachedUserForGroup(member);
            }

            @Override
            public void adminRemoved(Group group, Map params) {
                // Set object again in cache. This is done so that other cluster nodes
                // get refreshed with latest version of the object
                groupCache.put(group.getName(), CacheableOptional.of(group));
                
                // Remove only the collection of groups the member belongs to.
                String member = (String) params.get("admin");
                evictCachedUserForGroup(member);
            }

        });

        UserEventDispatcher.addListener(new UserEventListener() {
            @Override
            public void userCreated(User user, Map<String, Object> params) {
                // ignore
            }

            @Override
            public void userDeleting(User user, Map<String, Object> params) {
                deleteUser(user);
            }

            @Override
            public void userModified(User user, Map<String, Object> params) {
                // ignore
            }
        });
    }

    private static void initProvider(final Class clazz) {
        if (provider == null || !clazz.equals(provider.getClass())) {
            try {
                provider = (GroupProvider) clazz.newInstance();
            } catch (Exception e) {
                Log.error("Error loading group provider: " + clazz.getName(), e);
                provider = new DefaultGroupProvider();
            }
        }
    }

    /**
     * Factory method for creating a new Group. A unique name is the only required field.
     *
     * @param name the new and unique name for the group.
     * @return a new Group.
     * @throws GroupAlreadyExistsException if the group name already exists in the system.
     */
    public Group createGroup(String name) throws GroupAlreadyExistsException, GroupNameInvalidException {
        final Lock lock = groupCache.getLock(name);
        lock.lock();
        try {
            Group newGroup;
            try {
                getGroup(name);
                // The group already exists since now exception, so:
                throw new GroupAlreadyExistsException();
            }
            catch (GroupNotFoundException unfe) {
                // The group doesn't already exist so we can create a new group
                newGroup = provider.createGroup(name);
                // Update caches.
                clearGroupNameCache();
                clearGroupCountCache();
                groupCache.put(name, CacheableOptional.of(newGroup));

                // Fire event.
                GroupEventDispatcher.dispatchEvent(newGroup,
                        GroupEventDispatcher.EventType.group_created, Collections.emptyMap());
            }
            return newGroup;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the corresponding group if the given JID represents a group. 
     *
     * @param jid The JID for the group to retrieve
     * @return The group corresponding to the JID, or null if the JID does not represent a group
     * @throws GroupNotFoundException if the JID represents a group that does not exist
     */
    public Group getGroup(JID jid) throws GroupNotFoundException {
        JID groupJID = GroupJID.fromJID(jid);
        return (groupJID instanceof GroupJID) ? getGroup(((GroupJID)groupJID).getGroupName()) : null;
    }

    /**
     * Returns a Group by name.
     *
     * @param name The name of the group to retrieve
     * @return The group corresponding to that name
     * @throws GroupNotFoundException if the group does not exist.
     */
    public Group getGroup(String name) throws GroupNotFoundException {
        return getGroup(name, false);
    }

    /**
     * Returns a Group by name.
     *
     * @param name The name of the group to retrieve
     * @param forceLookup Invalidate the group cache for this group
     * @return The group corresponding to that name
     * @throws GroupNotFoundException if the group does not exist.
     */
    public Group getGroup(String name, boolean forceLookup) throws GroupNotFoundException {

        final CacheableOptional<Group> firstCachedGroup;
        if (forceLookup) {
            firstCachedGroup = null;
            groupCache.remove(name);
        } else {
            firstCachedGroup = groupCache.get(name);
        }

        if (firstCachedGroup != null) {
            return toGroup(name, firstCachedGroup);
        }

        final Lock lock = groupCache.getLock(name);
        lock.lock();
        try {
            final CacheableOptional<Group> secondCachedGroup = groupCache.get(name);
            if (secondCachedGroup != null) {
                return toGroup(name, secondCachedGroup);
            }

            try {
                final Group group = provider.getGroup(name);
                groupCache.put(name, CacheableOptional.of(group));
                return group;
            } catch (final GroupNotFoundException e) {
                groupCache.put(name, CacheableOptional.of(null));
                throw e;
            }
        } finally {
            lock.unlock();
        }
    }

    private Group toGroup(final String name, final CacheableOptional<Group> coGroup) throws GroupNotFoundException {
        return coGroup
            .toOptional()
            .orElseThrow(() -> new GroupNotFoundException("Group with name " + name + " not found (cached)."));
    }

    /**
     * Deletes a group from the system.
     *
     * @param group the group to delete.
     */
    public void deleteGroup(Group group) throws GroupNotFoundException {
        // Fire event.
        GroupEventDispatcher.dispatchEvent(group, GroupEventDispatcher.EventType.group_deleting,
                Collections.emptyMap());

        // Delete the group.
        provider.deleteGroup(group.getName());

        // Add a no-hit to the cache.
        groupCache.put(group.getName(), CacheableOptional.of(null));
        clearGroupNameCache();
        clearGroupCountCache();
    }

    /**
     * Deletes a user from all the groups where he/she belongs. The most probable cause
     * for this request is that the user has been deleted from the system.
     *
     * @param user the deleted user from the system.
     */
    public void deleteUser(User user) {
        JID userJID = XMPPServer.getInstance().createJID(user.getUsername(), null);
        for (Group group : getGroups(userJID)) {
            if (group.getAdmins().contains(userJID)) {
                if (group.getAdmins().remove(userJID)) {
                    // Remove the group from cache.
                    groupCache.remove(group.getName());
                }
            }
            else {
                if (group.getMembers().remove(userJID)) {
                    // Remove the group from cache.
                    groupCache.remove(group.getName());
                }
            }
        }
        evictCachedUserForGroup(userJID.toBareJID());
    }

    /**
     * Returns the total number of groups in the system.
     *
     * @return the total number of groups.
     */
    public int getGroupCount() {
            Integer count = getGroupCountFromCache();
        if (count == null) {
            synchronized(GROUP_COUNT_LOCK) {
                count = getGroupCountFromCache();
                if (count == null) {
                    count = provider.getGroupCount();
                    saveGroupCountInCache(count);
                }
            }
        }
        return count;
    }

    /**
     * Returns an unmodifiable Collection of all groups in the system.
     * 
     * NOTE: Iterating through the resulting collection has the effect of loading
     * every group into memory. This may be an issue for large deployments. You
     * may call the size() method on the resulting collection to determine the best
     * approach to take before iterating over (and thus instantiating) the groups.
     *
     * @return an unmodifiable Collection of all groups.
     */
    public Collection<Group> getGroups() {
        HashSet<String> groupNames = getGroupNamesFromCache();
        if (groupNames == null) {
            synchronized(GROUP_NAMES_LOCK) {
                groupNames = getGroupNamesFromCache();
                if (groupNames == null) {
                    groupNames = new HashSet<>(provider.getGroupNames());
                    saveGroupNamesInCache(groupNames);
                }
            }
        }
        return new GroupCollection(groupNames);
    }

    /**
     * Returns an unmodifiable Collection of all shared groups in the system.
     * 
     * NOTE: Iterating through the resulting collection has the effect of loading all
     * shared groups into memory. This may be an issue for large deployments. You
     * may call the size() method on the resulting collection to determine the best
     * approach to take before iterating over (and thus instantiating) the groups.
     *
     * @return an unmodifiable Collection of all shared groups.
     */
    public Collection<Group> getSharedGroups() {
        HashSet<String> groupNames;
        if (!provider.isSharingSupported()) {
            groupNames = new HashSet<>();
        } else {
            groupNames = new HashSet<>(provider.getSharedGroupNames());
        }
        return new GroupCollection(groupNames);
    }
    
    /**
     * Returns an unmodifiable Collection of all shared groups in the system for a given userName.
     *
     * @param userName the user to check
     * @return an unmodifiable Collection of all shared groups for the given userName.
     */
    public Collection<Group> getSharedGroups(String userName) {
        HashSet<String> groupNames;
        if (!provider.isSharingSupported()) {
            groupNames = new HashSet<>();
        } else {
            // assume this is a local user
            groupNames = new HashSet<>(provider.getSharedGroupNames(new JID(userName,
                XMPPServer.getInstance().getServerInfo().getXMPPDomain(), null)));
        }
        return new GroupCollection(groupNames);
    }
    
    /**
     * Returns an unmodifiable Collection of all shared groups in the system for a given group name.
     *
     * @param groupToCheck The group to check
     * @return an unmodifiable Collection of all shared groups for the given group name.
     */
    public Collection<Group> getVisibleGroups(Group groupToCheck) {
        HashSet<String> groupNames;
        if (!provider.isSharingSupported()) {
            groupNames = new HashSet<>();
        } else {
            // Get all the public shared groups.
            groupNames = new HashSet<>(provider.getPublicSharedGroupNames());

            // Now get all visible groups to the given group.
            groupNames.addAll(provider.getVisibleGroupNames(groupToCheck.getName()));
        }
        return new GroupCollection(groupNames);
    }
    
    /**
     * Returns an unmodifiable Collection of all public shared groups in the system.
     *
     * @return an unmodifiable Collection of all shared groups.
     */
    public Collection<Group> getPublicSharedGroups() {
        HashSet<String> groupNames;
        if (!provider.isSharingSupported()) {
            groupNames = new HashSet<>();
        } else {
            groupNames = new HashSet<>(provider.getPublicSharedGroupNames());
        }
        return new GroupCollection(groupNames);
    }
    
    /**
     * Returns an unmodifiable Collection of all groups in the system that
     * match given propValue for the specified propName.
     *
     * @param propName the property name to search for
     * @param propValue the property value to search for
     * @return an unmodifiable Collection of all matching groups.
     */
    public Collection<Group> search(String propName, String propValue) {
        Collection<String> groupsWithProps = provider.search(propName, propValue);
        return new GroupCollection(groupsWithProps);
    }

    /**
     * Returns all groups given a start index and desired number of results. This is
     * useful to support pagination in a GUI where you may only want to display a certain
     * number of results per page. It is possible that the number of results returned will
     * be less than that specified by numResults if numResults is greater than the number
     * of records left in the system to display.
     *
     * @param startIndex start index in results.
     * @param numResults number of results to return.
     * @return an Iterator for all groups in the specified range.
     */
    public Collection<Group> getGroups(int startIndex, int numResults) {
        HashSet<String> groupNames = getPagedGroupNamesFromCache(startIndex, numResults);
        if (groupNames == null) {
            // synchronizing on intern'ed string isn't great, but this value is deemed sufficiently unique for this to be safe here.
            synchronized (pagedGroupNameKeyInterner.intern(getPagedGroupNameKey(startIndex, numResults))) {
                groupNames = getPagedGroupNamesFromCache(startIndex, numResults);
                if (groupNames == null) {
                    groupNames = new HashSet<>(provider.getGroupNames(startIndex, numResults));
                    savePagedGroupNamesFromCache(groupNames, startIndex, numResults);
                }
            }
        }
        return new GroupCollection(groupNames);
    }

    /**
     * Returns an iterator for all groups that the User is a member of.
     *
     * @param user the user.
     * @return all groups the user belongs to.
     */
    public Collection<Group> getGroups(User user) {
        return getGroups(XMPPServer.getInstance().createJID(user.getUsername(), null, true));
    }

    /**
     * Returns an iterator for all groups that the entity with the specified JID is a member of.
     *
     * @param user the JID of the entity to get a list of groups for.
     * @return all groups that an entity belongs to.
     */
    public Collection<Group> getGroups(JID user) {
        HashSet<String> groupNames = getUserGroupsFromCache(user);
        if (groupNames == null) {
            synchronized (userBasedMutex.intern(user)) {
                groupNames = getUserGroupsFromCache(user);
                if (groupNames == null) {
                    groupNames = new HashSet<>(provider.getGroupNames(user));
                    saveUserGroupsInCache(user, groupNames);
                }
            }
        }
        return new GroupCollection(groupNames);
    }

    /**
     * Returns true if groups are read-only.
     *
     * @return true if groups are read-only.
     */
    public boolean isReadOnly() {
        return provider.isReadOnly();
    }

    /**
     * Returns true if searching for groups is supported.
     *
     * @return true if searching for groups are supported.
     */
    public boolean isSearchSupported() {
        return provider.isSearchSupported();
    }

    /**
     * Returns the groups that match the search. The search is over group names and
     * implicitly uses wildcard matching (although the exact search semantics are left
     * up to each provider implementation). For example, a search for "HR" should match
     * the groups "HR", "HR Department", and "The HR People".<p>
     *
     * Before searching or showing a search UI, use the {@link #isSearchSupported} method
     * to ensure that searching is supported.
     *
     * @param query the search string for group names.
     * @return all groups that match the search.
     */
    public Collection<Group> search(String query) {
        Collection<String> groupNames = provider.search(query);
        return new GroupCollection(groupNames);
    }

    /**
     * Returns the groups that match the search given a start index and desired number
     * of results. The search is over group names and implicitly uses wildcard matching
     * (although the exact search semantics are left up to each provider implementation).
     * For example, a search for "HR" should match the groups "HR", "HR Department", and
     * "The HR People".<p>
     *
     * Before searching or showing a search UI, use the {@link #isSearchSupported} method
     * to ensure that searching is supported.
     *
     * @param query the search string for group names.
     * @param startIndex the start index to retrieve the group list from
     * @param numResults the maximum number of results to return
     * @return all groups that match the search.
     */
    public Collection<Group> search(String query, int startIndex, int numResults) {
        Collection<String> groupNames = provider.search(query, startIndex, numResults);
        return new GroupCollection(groupNames);
    }

    /**
     * Returns the configured group provider. Note that this method has special access
     * privileges since only a few certain classes need to access the provider directly.
     *
     * @return the group provider.
     */
    public GroupProvider getProvider() {
        return provider;
    }

    private void evictCachedUserForGroup(String userJid) {
        if (userJid != null) {
            JID user = new JID(userJid);

            // remove cache for getGroups
            synchronized (USER_GROUPS_LOCK) {
                clearUserGroupsCache(user);
            }
        }
    }

    /**
     * Evict from cache all cached user entries that relate to the provided group.
     *
     * This method ignores group names for which a group cannot be found.
     * 
     * @param groupName The name of a group for which to evict cached user entries (cannot be null).
     */
    private void evictCachedUsersForGroup(String groupName)
    {
        try {
            evictCachedUsersForGroup( getGroup(groupName) );
        } catch ( GroupNotFoundException e ) {
            Log.debug("Unable to evict cached users for group '{}': this group does not exist.", groupName, e);
        }
    }

    /**
     * Evict from cache all cached user entries that relate to the provided group.
     *
     * @param group The group for which to evict cached user entries (cannot be null).
     */
    private void evictCachedUsersForGroup(Group group)
    {
        // Get all nested groups, removing any cyclic dependency.
        final Set<Group> groups = getSharedGroups( group );

        // Evict cached information for affected users.
        groups.forEach( g -> {
            g.getAdmins().forEach( jid -> evictCachedUserForGroup( jid.toBareJID()) );
            g.getMembers().forEach( jid -> evictCachedUserForGroup( jid.toBareJID()) );
        });

        // If any of the groups is shared with everybody, evict all cached groups.
        if ( groups.stream().anyMatch( g -> g.getSharedWith() == SharedGroupVisibility.everybody)) {
            evictCachedUserSharedGroups();
        }
    }

    /**
     * Find the unique set of groups with which the provided group is shared,
     * directly or indirectly. An indirect share is defined as a scenario where
     * the group is shared by a group that's shared with another group.
     *
     * @param group The group for which to return all groups that it is shared with (cannot be null).
     * @return A set of groups with which all members of 'group' are shared with (never null).
     */
    @Nonnull
    private Set<Group> getSharedGroups(@Nonnull final Group group) {
        final HashSet<Group> result = new HashSet<>();
        if (provider.isSharingSupported()) {
            if (group.getSharedWith() == SharedGroupVisibility.usersOfGroups) {
                final Set<String> groupNames = new HashSet<>(group.getSharedWithUsersInGroupNames());

                for ( String groupName : groupNames )
                {
                    try {
                        result.add(getGroup(groupName));
                    }
                    catch ( GroupNotFoundException e )
                    {
                        Log.debug("While iterating over subgroups of group '{}', an unrecognized spefgroup was found: '{}'", group.getName(), groupName, e);
                    }
                }
            }
        }

        return result;
    }

    /**
     * Splits a comma-separated string of group name in a set of group names.
     * @param csv The comma-separated list. Cannot be null.
     * @return A set of group names.
     */
    protected static Set<String> splitGroupList( String csv )
    {
        final Set<String> result = new HashSet<>();
        final StringTokenizer tokenizer = new StringTokenizer(csv, ",\t\n\r\f");
        while ( tokenizer.hasMoreTokens() )
        {
            result.add(tokenizer.nextToken().trim());
        }

        return result;
    }

    private void evictCachedPaginatedGroupNames() {
        groupMetaCache.keySet().stream()
            .filter(key -> key.startsWith(GROUP_NAMES_KEY))
            .forEach(key -> groupMetaCache.remove(key));
    }

    private void evictCachedUserSharedGroups() {
        groupMetaCache.keySet().stream()
            .filter(key -> key.startsWith(GROUP_NAMES_KEY))
            .forEach(key -> groupMetaCache.remove(key));
    }

    /*
        For reasons currently unclear, this class stores a number of different objects in the groupMetaCache. To
        better encapsulate this, all access to the groupMetaCache is via these methods
     */
    @SuppressWarnings("unchecked")
    private HashSet<String> getGroupNamesFromCache() {
        return (HashSet<String>)groupMetaCache.get(GROUP_NAMES_KEY);
    }

    private void clearGroupNameCache() {
        groupMetaCache.remove(GROUP_NAMES_KEY);
    }

    private void saveGroupNamesInCache(final HashSet<String> groupNames) {
        groupMetaCache.put(GROUP_NAMES_KEY, groupNames);
    }

    private PagedGroupNameKey getPagedGroupNameKey(final int startIndex, final int numResults) {
        return new PagedGroupNameKey(startIndex, numResults);
    }

    private static final class PagedGroupNameKey {

        public final int startIndex;

        public final int numResults;

        public PagedGroupNameKey( int startIndex, int numResults){
            this.startIndex = startIndex;
            this.numResults = numResults;
        }

        @Override
        public String toString() {
            return GROUP_NAMES_KEY + startIndex + "," + numResults;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PagedGroupNameKey that = (PagedGroupNameKey) o;
            return startIndex == that.startIndex && numResults == that.numResults;
        }

        @Override
        public int hashCode() {
            return Objects.hash(startIndex, numResults);
        }
    }

    @SuppressWarnings("unchecked")
    private HashSet<String> getPagedGroupNamesFromCache(final int startIndex, final int numResults) {
        return (HashSet<String>)groupMetaCache.get(getPagedGroupNameKey(startIndex, numResults).toString());
    }

    private void savePagedGroupNamesFromCache(final HashSet<String> groupNames, final int startIndex, final int numResults) {
        groupMetaCache.put(getPagedGroupNameKey(startIndex, numResults).toString(), groupNames);

    }

    private Integer getGroupCountFromCache() {
        return (Integer)groupMetaCache.get(GROUP_COUNT_KEY);
    }

    private void saveGroupCountInCache(final int count) {
        groupMetaCache.put(GROUP_COUNT_KEY, count);
    }

    private void clearGroupCountCache() {
        groupMetaCache.remove(GROUP_COUNT_KEY);
    }

    @SuppressWarnings("unchecked")
    private HashSet<String> getUserGroupsFromCache(final JID user) {
        return (HashSet<String>)groupMetaCache.get(getUserGroupsKey(user));
    }

    private void clearUserGroupsCache(final JID user) {
        groupMetaCache.remove(getUserGroupsKey(user));
    }

    private void saveUserGroupsInCache(final JID user, final HashSet<String> groupNames) {
        groupMetaCache.put(getUserGroupsKey(user), groupNames);
    }

    private String getUserGroupsKey(final JID user) {
        return USER_GROUPS_KEY + user.toBareJID();
    }

}
