package org.jivesoftware.openfire.muc.spi;

import org.jivesoftware.openfire.event.GroupEventDispatcher;
import org.jivesoftware.openfire.muc.MUCRoom;
import org.jivesoftware.openfire.muc.MultiUserChatService;
import org.jivesoftware.util.cache.Cache;
import org.jivesoftware.util.cache.CacheFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.stream.Collectors;

/**
 * this class supports the simple MUCRoom management including remove,add and query.
 *
 * Note that this implementation provides a representation of rooms that are currently actively loaded in memory only.
 * More rooms might exist in the database.
 *
 * @author <a href="mailto:583424568@qq.com">wuchang</a>
 * 2016-1-14
 */
public class LocalMUCRoomManager
{
    private static final Logger Log = LoggerFactory.getLogger(LocalMUCRoomManager.class);

    /**
     * Name of the service that this instance is operating for.
     */
    private final String serviceName;

    /**
     * The cluster-shared data structure that holds all MUC rooms.
     */
    private final Cache<String, MUCRoom> CACHE_ROOM;

    /**
     * A cluster-local copy of rooms, used to (re)populating #CACHE_ROOM upon cluster join or leave.
     */
    private final Map<String, MUCRoom> rooms = new HashMap<>();

    LocalMUCRoomManager(@Nonnull final MultiUserChatService service) {
        this.serviceName = service.getServiceName();
        CACHE_ROOM= CacheFactory.createCache("MUC Service '" + serviceName + "' Rooms");
        CACHE_ROOM.setMaxLifetime(-1);
        CACHE_ROOM.setMaxCacheSize(-1L);
    }

    /**
     * Returns the number of chat rooms that are currently actively loaded in memory.
     *
     * @return a chat room count.
     */
    public int getNumberChatRooms(){
        return CACHE_ROOM.size();
    }

    /**
     * Obtain a mutex object that can be used to control cluster-wide access to the MUCRoom instance.
     *
     * @param roomName The name of the entity for which to return a lock.
     * @return A lock object that can be used to control cluster-wide access to a particular MUCRoom instance.
     */
    public Lock getLock(@Nonnull final String roomName) {
        return CACHE_ROOM.getLock(roomName);
    }

    public void addRoom(final MUCRoom room) {
        updateRoom(room);
        GroupEventDispatcher.addListener(room); // TODO this event listener is added only in the node where the room is created. Does this mean that events are not prop
    }

    /**
     * Ensures that updates to the provided MUCRoom instance become visible to other cluster nodes.
     *
     * @param room A MUCRoom instance.
     */
    public void updateRoom(final MUCRoom room)
    {
        final Lock lock = CACHE_ROOM.getLock(room.getName());
        lock.lock();
        try {
            CACHE_ROOM.put(room.getName(), room);
            rooms.put(room.getName(), room);
        } finally {
            lock.unlock();
        }
    }

    // TODO As modifications to rooms won't be persisted in the cache without the room having being explicitly put back in the cache,
    //      this method probably needs work. Documentation should be added and/or this should return an Unmodifiable collection (although
    //      that still does not rule out modifications to individual collection items. Can we replace it completely with a 'getRoomNames()'
    //      method, which would then force usage to acquire a lock before operating on a room.
    public Collection<MUCRoom> getRooms(){
        return CACHE_ROOM.values();
    }

    /**
     * Obtain a chat room by name.
     *
     * If the instance is being modified after being returned from this method, then {@link #updateRoom(MUCRoom)}
     * MUST be used. Failing to do so will cause the update to remain invisible to other cluster nodes.
     *
     * @param roomName The name of a chat room.
     * @return The chat room corresponding to that name.
     */
    public MUCRoom getRoom(final String roomName) {
        return CACHE_ROOM.get(roomName);
    }

    public MUCRoom removeRoom(final String roomName){
        //memory leak will happen if we forget remove it from GroupEventDispatcher
        final Lock lock = CACHE_ROOM.getLock(roomName);
        lock.lock();
        try {
            final MUCRoom room = CACHE_ROOM.remove(roomName);
            if (room != null) {
                GroupEventDispatcher.removeListener(room);
            }
            rooms.remove(roomName);
            return room;
        } finally {
            lock.unlock();
        }
    }
    
    public void cleanupRooms(final Date cleanUpDate) {
        final Set<String> roomNames = getRooms().stream().map(MUCRoom::getName).collect(Collectors.toSet());
        for (final String roomName : roomNames) {
            final Lock lock = CACHE_ROOM.getLock(roomName);
            lock.lock();
            try {
                final MUCRoom room = getRoom(roomName);
                if (room.getEmptyDate() != null && room.getEmptyDate().before(cleanUpDate)) {
                    removeRoom(roomName);
                }
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * When the local node is joining or leaving a cluster, {@link org.jivesoftware.util.cache.CacheFactory} will swap
     * the implementation used to instantiate caches. This causes the cache content to be 'reset': it will no longer
     * contain the data that's provided by the local node. This method restores data that's provided by the local node
     * in the cache. It is expected to be invoked right after joining
     * ({@link org.jivesoftware.openfire.cluster.ClusterEventListener#joinedCluster()} or leaving
     * ({@link org.jivesoftware.openfire.cluster.ClusterEventListener#leftCluster()} a cluster.
     */
    void restoreCacheContent() {
        Log.trace( "Restoring cache content for cache '{}' by adding all MUC Rooms that are known to the local node.", CACHE_ROOM.getName() );

        for (Map.Entry<String, MUCRoom> entry : rooms.entrySet()) {
            final Lock lock = CACHE_ROOM.getLock(entry.getKey());
            lock.lock();
            try {
                if (!CACHE_ROOM.containsKey(entry.getKey())) {
                    CACHE_ROOM.put(entry.getKey(), entry.getValue());
                } else {
                    final MUCRoom roomInCluster = CACHE_ROOM.get(entry.getKey());
                    if (!roomInCluster.equals(entry.getValue())) { // TODO: unsure if #equals() is enough to verify equality here.
                        Log.warn("Joined an Openfire cluster on which a room exists that clashes with a room that exists locally. Room name: '{}' on service '{}'", entry.getKey(), serviceName);
                        // FIXME handle collision. Two nodes have different rooms using the same name.
                    }
                }
            } finally {
                lock.unlock();
            }
        }
    }
}
