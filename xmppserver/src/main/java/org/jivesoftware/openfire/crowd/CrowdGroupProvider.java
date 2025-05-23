/*
 * Copyright (C) 2012 Issa Gorissen <issa-gorissen@usa.net>, 2017-2025 Ignite Realtime Foundation. All rights reserved.
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
package org.jivesoftware.openfire.crowd;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.group.AbstractGroupProvider;
import org.jivesoftware.openfire.group.Group;
import org.jivesoftware.openfire.group.GroupNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.NamedThreadFactory;
import org.jivesoftware.util.cache.Cache;
import org.jivesoftware.util.cache.CacheFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;


/**
 * Atlassian Crowd implementation of the GroupProvider. We do not permit
 * modifications of groups from this provider - only read-only access.
 */
public class CrowdGroupProvider extends AbstractGroupProvider {
    private static final Logger LOG = LoggerFactory.getLogger(CrowdGroupProvider.class);
    private static final int CACHE_TTL = 3600; // ttl in seconds - one hour
    private static final String JIVE_CROWD_GROUPS_CACHE_TTL_SECS = "crowd.groups.cache.ttl.seconds";
    
    private static final String GROUP_CACHE_NAME = "crowdGroup";
    private static final String GROUP_MEMBERSHIP_CACHE_NAME = "crowdGroupMembership";
    private static final String USER_MEMBERSHIP_CACHE_NAME = "crowdUserMembership";

    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private static final ScheduledExecutorService crowdGroupSync = Executors.newSingleThreadScheduledExecutor(
        new NamedThreadFactory("CrowdGroupSync-", Executors.defaultThreadFactory(), false, Thread.NORM_PRIORITY)
    );
    private static final CrowdManager manager = CrowdManager.getInstance();

    private static List<String> groups = new ArrayList<>();
    
    private final XMPPServer server = XMPPServer.getInstance();
    
    
    static {
        String propertyValue = JiveGlobals.getProperty(JIVE_CROWD_GROUPS_CACHE_TTL_SECS);
        int ttl = (propertyValue == null || propertyValue.trim().isEmpty()) ? CACHE_TTL : Integer.parseInt(propertyValue);

        crowdGroupSync.scheduleAtFixedRate(new GroupSynch(), 0, ttl, TimeUnit.SECONDS);
        
        JiveGlobals.setProperty(JIVE_CROWD_GROUPS_CACHE_TTL_SECS, String.valueOf(ttl));
    }
    
    public CrowdGroupProvider() {
        super();
        String propertyValue = JiveGlobals.getProperty(JIVE_CROWD_GROUPS_CACHE_TTL_SECS);
        int ttl = (propertyValue == null || propertyValue.trim().isEmpty()) ? CACHE_TTL : Integer.parseInt(propertyValue);

        Cache<String, ArrayList<JID>> groupMembershipCache = CacheFactory.createLocalCache(GROUP_MEMBERSHIP_CACHE_NAME);
        groupMembershipCache.setMaxCacheSize(-1L);
        groupMembershipCache.setMaxLifetime(ttl * 1000L); // msecs instead of sec - see Cache API

        Cache<JID, ArrayList<String>> userMembershipCache = CacheFactory.createLocalCache(USER_MEMBERSHIP_CACHE_NAME);
        userMembershipCache.setMaxCacheSize(-1L);
        userMembershipCache.setMaxLifetime(ttl * 1000L); // msecs instead of sec - see Cache API
        
        Cache<String, org.jivesoftware.openfire.crowd.jaxb.Group> groupCache = CacheFactory.createLocalCache(GROUP_CACHE_NAME);
        groupCache.setMaxCacheSize(-1L);
        groupCache.setMaxLifetime(ttl * 1000L); // msecs instead of sec - see Cache API
    }

    @Override
    public Group getGroup(String name) throws GroupNotFoundException {
        try {
            Cache<String, org.jivesoftware.openfire.crowd.jaxb.Group> groupCache = CacheFactory.createLocalCache(GROUP_CACHE_NAME);
            org.jivesoftware.openfire.crowd.jaxb.Group group = groupCache.get(name);
            if (group == null) {
                group = manager.getGroup(name);
                groupCache.put(name, group);
            }
            Collection<JID> members = getGroupMembers(name);
            Collection<JID> admins = Collections.emptyList();
            return new Group(name, group.description, members, admins);
            
        } catch (RemoteException re) {
            LOG.error("Failure to load group:" + name, re);
            throw new GroupNotFoundException(re);
        }
    }

    
    private Collection<JID> getGroupMembers(String groupName) {
        Cache<String, ArrayList<JID>> groupMembershipCache = CacheFactory.createLocalCache(GROUP_MEMBERSHIP_CACHE_NAME);
        Collection<JID> members = groupMembershipCache.get(groupName);
        if (members != null) {
            return members;
        }
        
        try {
            List<String> users = manager.getGroupMembers(groupName);
            ArrayList<JID> results = new ArrayList<>();

            for (String username : users) {
                results.add(server.createJID(username, null));
            }
            
            groupMembershipCache.put(groupName, results);
            return results;
            
        } catch (RemoteException re) {
            LOG.error("Failure to get the members of crowd group:" + groupName, re);
        }
        
        groupMembershipCache.put(groupName, new ArrayList<>());
        return Collections.emptyList();
    }
    
    @Override
    public Collection<String> getGroupNames(JID user) {
        user = user.asBareJID();
        Cache<JID, ArrayList<String>> userMembershipCache = CacheFactory.createCache(USER_MEMBERSHIP_CACHE_NAME);
        ArrayList<String> groups = userMembershipCache.get(user);
        if (groups != null) {
            return groups;
        }
        
        try {
            groups = new ArrayList<>(manager.getUserGroups(user.getNode()));
            userMembershipCache.put(user, groups);
            return groups;
        } catch (RemoteException re) {
            LOG.error("Failure to load the groups of user:" + user, re);
        }
        
        userMembershipCache.put(user, new ArrayList<>());
        return Collections.emptyList();
    }

    @Override
    public int getGroupCount() {
        lock.readLock().lock();
        try {
            return groups.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public Collection<String> getGroupNames() {
        lock.readLock().lock();
        try {
            return groups;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public Collection<String> getGroupNames(int startIndex, int numResults) {
        lock.readLock().lock();
        try {
            Collection<String> results = new ArrayList<>(numResults);
            
            for (int i = 0, j = startIndex; i < numResults && j < groups.size(); ++i, ++j) {
                results.add(groups.get(j));
            }
            
            return results;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public Collection<String> search(String query) {
        lock.readLock().lock();
        try {
            ArrayList<String> results = new ArrayList<>();
            
            if (query != null && !query.trim().isEmpty()) {
                
                if (query.endsWith("*")) {
                    query = query.substring(0, query.length() - 1);
                }
                if (query.startsWith("*")) {
                    query = query.substring(1);
                }
                query = query.toLowerCase();
                
                for (String groupName : groups) {
                    if (groupName.toLowerCase().contains(query)) {
                        results.add(groupName);
                    }
                }
            }
            
            return results;
            
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public Collection<String> search(String query, int startIndex, int numResults) {
        lock.readLock().lock();
        try {
            ArrayList<String> foundGroups = (ArrayList<String>) search(query);
            
            Collection<String> results = new ArrayList<>();
            
            for (int i = 0, j = startIndex; i < numResults && j < foundGroups.size(); ++i, ++j) {
                results.add(foundGroups.get(j));
            }
            
            return results;
            
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Modifying group not implemented - read-only for now
     */
    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public boolean isSearchSupported() {
        return true;
    }

    
    
    /**
     * @see org.jivesoftware.openfire.group.AbstractGroupProvider#search(java.lang.String, java.lang.String)
     */
    // TODO search on group attributes in Crowd
    @Override
    public Collection<String> search(String key, String value) {
        LOG.info("Search groups on attributes not implemented yet");
        return Collections.emptyList();
    }





    static class GroupSynch implements Runnable {
        @Override
        public void run() {
            LOG.info("running sync with crowd...");
            CrowdManager manager;
            try {
                manager = CrowdManager.getInstance();
            } catch (Exception e) {
                LOG.error("Failure to load the Crowd manager", e);
                return;
            }
            
            List<String> allGroups;
            try {
                allGroups = manager.getAllGroupNames();
            } catch (RemoteException re) {
                LOG.error("Failure to fetch all crowd groups name", re);
                return;
            }
            
            if (allGroups != null && !allGroups.isEmpty()) {
                CrowdGroupProvider.lock.writeLock().lock();
                try {
                    CrowdGroupProvider.groups = allGroups;
                } finally {
                    CrowdGroupProvider.lock.writeLock().unlock();
                }
            }
            
            LOG.info("crowd sync done, returned " + (allGroups == null ? "no" : allGroups.size()) + " groups");
        }
    }

}
