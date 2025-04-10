/*
 * Copyright (C) 2005-2008 Jive Software, 2017-2024 Ignite Realtime Foundation. All rights reserved.
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

package org.jivesoftware.util;

import org.jivesoftware.openfire.JMXManager;
import org.jivesoftware.openfire.mbean.ThreadPoolExecutorDelegate;
import org.jivesoftware.openfire.mbean.ThreadPoolExecutorDelegateMBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.ObjectName;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.*;

/**
 * Performs tasks using worker threads. It also allows tasks to be scheduled to be
 * run at future dates. This class mimics relevant methods in both
 * {@link ExecutorService} and {@link Timer}. Any {@link TimerTask} that's
 * scheduled to be run in the future will automatically be run using the thread
 * executor's thread pool. This means that the standard restriction that TimerTasks
 * should run quickly does not apply.
 *
 * @author Matt Tucker
 */
public class TaskEngine {

    private static final Logger Log = LoggerFactory.getLogger(TaskEngine.class);

    /**
     * The number of threads to keep in the thread pool that is used to execute tasks of Openfire's TaskEngine, even if they are idle.
     */
    public static final SystemProperty<Integer> EXECUTOR_CORE_POOL_SIZE = SystemProperty.Builder.ofType(Integer.class)
        .setKey("xmpp.taskengine.threadpool.size.core")
        .setMinValue(0)
        .setDefaultValue(0)
        .setDynamic(false)
        .build();

    /**
     * The maximum number of threads to allow in the thread pool that is used to execute tasks of Openfire's TaskEngine.
     */
    public static final SystemProperty<Integer> EXECUTOR_MAX_POOL_SIZE = SystemProperty.Builder.ofType(Integer.class)
        .setKey("xmpp.taskengine.threadpool.size.max")
        .setMinValue(1)
        .setDefaultValue(Integer.MAX_VALUE)
        .setDynamic(false)
        .build();

    /**
     * The number of threads in the thread pool that is used to execute tasks of Openfire's TaskEngine is greater than the core, this is the maximum time that excess idle threads will wait for new tasks before terminating.
     */
    public static final SystemProperty<Duration> EXECUTOR_POOL_KEEP_ALIVE = SystemProperty.Builder.ofType(Duration.class)
        .setKey("xmpp.taskengine.threadpool.keepalive")
        .setChronoUnit(ChronoUnit.SECONDS)
        .setDefaultValue(Duration.ofSeconds(60))
        .setDynamic(false)
        .build();

    /**
     * Object name used to register delegate MBean (JMX) for the taskengine thread pool executor.
     */
    private ObjectName objectName;

    private static final TaskEngine instance = new TaskEngine();

    /**
     * Returns a task engine instance (singleton).
     *
     * @return a task engine.
     */
    public static TaskEngine getInstance() {
        return instance;
    }

    private Timer timer;
    private ThreadPoolExecutor executor;
    private final Map<TimerTask, TimerTaskWrapper> wrappedTasks = new ConcurrentHashMap<>();

    /**
     * Constructs a new task engine.
     */
    private TaskEngine() {
        timer = new Timer("TaskEngine-timer", true);
        final ThreadFactory threadFactory = new NamedThreadFactory( "TaskEngine-pool-", true, Thread.NORM_PRIORITY, Thread.currentThread().getThreadGroup(), 0L );
        executor = new ThreadPoolExecutor(
            EXECUTOR_CORE_POOL_SIZE.getValue(),
            EXECUTOR_MAX_POOL_SIZE.getValue(),
            EXECUTOR_POOL_KEEP_ALIVE.getValue().toSeconds(),
            TimeUnit.SECONDS,
            new SynchronousQueue<>(),
            threadFactory);

        if (JMXManager.isEnabled()) {
            final ThreadPoolExecutorDelegateMBean mBean = new ThreadPoolExecutorDelegate(executor);
            objectName = JMXManager.tryRegister(mBean, ThreadPoolExecutorDelegateMBean.BASE_OBJECT_NAME + "taskEngine");
        }
    }

    /**
     * Submits a Runnable task for execution and returns a Future
     * representing that task.
     *
     * @param task the task to submit.
     * @return a Future representing pending completion of the task,
     *      and whose {@code get()} method will return {@code null}
     *      upon completion.
     */
    public Future<?> submit(Runnable task) {
        try {
            return executor.submit(task);
        } catch (Throwable t) {
            Log.warn("Failed to schedule task; will retry using caller's thread.", t);
            FutureTask<?> result = new FutureTask<>(task, null);
            result.run();
            return result;
        }
    }

    /**
     * Submits a Callable task for execution and returns a Future
     * representing that task.
     *
     * @param task the task to submit.
     * @return a Future representing pending completion of the task
     */
    public <V> Future<V> submit(Callable<V> task) {
        try {
            return executor.submit(task);
        } catch (Throwable t) {
            Log.warn("Failed to schedule task; will retry using caller's thread.", t);
            try {
                final V result = task.call();
                return CompletableFuture.completedFuture(result);
            } catch (Exception e) {
                return CompletableFuture.failedFuture(e);
            }
        }
    }

    /**
     * Schedules the specified task for execution after the specified delay.
     *
     * @param task  task to be scheduled.
     * @param delay delay before task is to be executed.
     * @throws IllegalArgumentException if {@code delay} is negative, or
     *         {@code delay + System.currentTimeMillis()} is negative.
     * @throws IllegalStateException if task was already scheduled or
     *         cancelled, or timer was cancelled.
     */
    public void schedule(TimerTask task, Duration delay) {
        timer.schedule(new TimerTaskWrapper(task), delay.toMillis());
    }

    /**
     * Schedules the specified task for execution at the specified time.  If
     * the time is in the past, the task is scheduled for immediate execution.
     *
     * @param task task to be scheduled.
     * @param time time at which task is to be executed.
     * @throws IllegalArgumentException if {@code time.getTime()} is negative.
     * @throws IllegalStateException if task was already scheduled or
     *         cancelled, timer was cancelled, or timer thread terminated.
     */
    public void schedule(TimerTask task, Instant time) {
        timer.schedule(new TimerTaskWrapper(task), Date.from(time));
    }

    /**
     * Schedules the specified task for repeated <i>fixed-delay execution</i>,
     * beginning after the specified delay.  Subsequent executions take place
     * at approximately regular intervals separated by the specified period.
     *
     * <p>In fixed-delay execution, each execution is scheduled relative to
     * the actual execution time of the previous execution.  If an execution
     * is delayed for any reason (such as garbage collection or other
     * background activity), subsequent executions will be delayed as well.
     * In the long run, the frequency of execution will generally be slightly
     * lower than the reciprocal of the specified period (assuming the system
     * clock underlying {@code Object.wait(long)} is accurate).
     *
     * <p>Fixed-delay execution is appropriate for recurring activities
     * that require "smoothness."  In other words, it is appropriate for
     * activities where it is more important to keep the frequency accurate
     * in the short run than in the long run.  This includes most animation
     * tasks, such as blinking a cursor at regular intervals.  It also includes
     * tasks wherein regular activity is performed in response to human
     * input, such as automatically repeating a character as long as a key
     * is held down.
     *
     * @param task task to be scheduled.
     * @param delay  delay before task is to be executed.
     * @param period time between successive task executions.
     * @throws IllegalArgumentException if {@code delay} is negative, or
     *         {@code delay + System.currentTimeMillis()} is negative.
     * @throws IllegalStateException if task was already scheduled or
     *         cancelled, timer was cancelled, or timer thread terminated.
     *
     */
    public void schedule(TimerTask task, Duration delay, Duration period) {
        TimerTaskWrapper taskWrapper = new TimerTaskWrapper(task);
        wrappedTasks.put(task, taskWrapper);
        timer.schedule(taskWrapper, delay.toMillis(), period.toMillis());
    }

    /**
     * Schedules the specified task for repeated <i>fixed-delay execution</i>,
     * beginning at the specified time. Subsequent executions take place at
     * approximately regular intervals, separated by the specified period.
     *
     * <p>In fixed-delay execution, each execution is scheduled relative to
     * the actual execution time of the previous execution.  If an execution
     * is delayed for any reason (such as garbage collection or other
     * background activity), subsequent executions will be delayed as well.
     * In the long run, the frequency of execution will generally be slightly
     * lower than the reciprocal of the specified period (assuming the system
     * clock underlying {@code Object.wait(long)} is accurate).
     *
     * <p>Fixed-delay execution is appropriate for recurring activities
     * that require "smoothness."  In other words, it is appropriate for
     * activities where it is more important to keep the frequency accurate
     * in the short run than in the long run.  This includes most animation
     * tasks, such as blinking a cursor at regular intervals.  It also includes
     * tasks wherein regular activity is performed in response to human
     * input, such as automatically repeating a character as long as a key
     * is held down.
     *
     * @param task task to be scheduled.
     * @param firstTime First time at which task is to be executed.
     * @param period time between successive task executions.
     * @throws IllegalArgumentException if {@code time.getTime()} is negative.
     * @throws IllegalStateException if task was already scheduled or
     *         cancelled, timer was cancelled, or timer thread terminated.
     */
    public void schedule(TimerTask task, Instant firstTime, Duration period) {
        TimerTaskWrapper taskWrapper = new TimerTaskWrapper(task);
        wrappedTasks.put(task, taskWrapper);
        timer.schedule(taskWrapper, Date.from(firstTime), period.toMillis());
    }

    /**
     * Schedules the specified task for repeated <i>fixed-rate execution</i>,
     * beginning after the specified delay.  Subsequent executions take place
     * at approximately regular intervals, separated by the specified period.
     *
     * <p>In fixed-rate execution, each execution is scheduled relative to the
     * scheduled execution time of the initial execution.  If an execution is
     * delayed for any reason (such as garbage collection or other background
     * activity), two or more executions will occur in rapid succession to
     * "catch up."  In the long run, the frequency of execution will be
     * exactly the reciprocal of the specified period (assuming the system
     * clock underlying {@code Object.wait(long)} is accurate).
     *
     * <p>Fixed-rate execution is appropriate for recurring activities that
     * are sensitive to <i>absolute</i> time, such as ringing a chime every
     * hour on the hour, or running scheduled maintenance every day at a
     * particular time.  It is also appropriate for recurring activities
     * where the total time to perform a fixed number of executions is
     * important, such as a countdown timer that ticks once every second for
     * ten seconds.  Finally, fixed-rate execution is appropriate for
     * scheduling multiple repeating timer tasks that must remain synchronized
     * with respect to one another.
     *
     * @param task task to be scheduled.
     * @param delay delay before task is to be executed.
     * @param period time between successive task executions.
     * @throws IllegalArgumentException if {@code delay} is negative, or
     *         {@code delay + System.currentTimeMillis()} is negative.
     * @throws IllegalStateException if task was already scheduled or
     *         cancelled, timer was cancelled, or timer thread terminated.
     */
    public void scheduleAtFixedRate(TimerTask task, Duration delay, Duration period) {
        TimerTaskWrapper taskWrapper = new TimerTaskWrapper(task);
        wrappedTasks.put(task, taskWrapper);
        timer.scheduleAtFixedRate(taskWrapper, delay.toMillis(), period.toMillis());
    }

    /**
     * Schedules the specified task for repeated <i>fixed-rate execution</i>,
     * beginning at the specified time. Subsequent executions take place at
     * approximately regular intervals, separated by the specified period.
     *
     * <p>In fixed-rate execution, each execution is scheduled relative to the
     * scheduled execution time of the initial execution.  If an execution is
     * delayed for any reason (such as garbage collection or other background
     * activity), two or more executions will occur in rapid succession to
     * "catch up."  In the long run, the frequency of execution will be
     * exactly the reciprocal of the specified period (assuming the system
     * clock underlying {@code Object.wait(long)} is accurate).
     *
     * <p>Fixed-rate execution is appropriate for recurring activities that
     * are sensitive to <i>absolute</i> time, such as ringing a chime every
     * hour on the hour, or running scheduled maintenance every day at a
     * particular time.  It is also appropriate for recurring activities
     * where the total time to perform a fixed number of executions is
     * important, such as a countdown timer that ticks once every second for
     * ten seconds.  Finally, fixed-rate execution is appropriate for
     * scheduling multiple repeating timer tasks that must remain synchronized
     * with respect to one another.
     *
     * @param task task to be scheduled.
     * @param firstTime First time at which task is to be executed.
     * @param period time between successive task executions.
     * @throws IllegalArgumentException if {@code time.getTime()} is negative.
     * @throws IllegalStateException if task was already scheduled or
     *         cancelled, timer was cancelled, or timer thread terminated.
     */
    public void scheduleAtFixedRate(TimerTask task, Instant firstTime, Duration period) {
        TimerTaskWrapper taskWrapper = new TimerTaskWrapper(task);
        wrappedTasks.put(task, taskWrapper);
        timer.scheduleAtFixedRate(taskWrapper, Date.from(firstTime), period.toMillis());
    }

    /**
     * Cancels the execution of a scheduled task. {@link java.util.TimerTask#cancel()}
     *
     * @param task the scheduled task to cancel.
     */
    public void cancelScheduledTask(TimerTask task) {
        TaskEngine.TimerTaskWrapper taskWrapper = wrappedTasks.remove(task);
        if (taskWrapper != null) {
            taskWrapper.cancel();
        }
    }

    /**
     * Shuts down the task engine service.
     */
    public void shutdown() {
        if (objectName != null) {
            JMXManager.tryUnregister(objectName);
            objectName = null;
        }

        if (executor != null) {
            executor.shutdown();
            executor = null;
        }

        if (timer != null) {
            timer.cancel();
            timer = null;
        }
    }

    /**
     * Wrapper class for a standard TimerTask. It simply executes the TimerTask
     * using the executor's thread pool.
     */
    private class TimerTaskWrapper extends TimerTask {

        private TimerTask task;

        public TimerTaskWrapper(TimerTask task) {
            this.task = task;
        }

        @Override
        public void run() {
            try {
                submit(task);
            } catch (Throwable t) {
                // need to catch here to prevent Timer from canceling TimerThread
                Log.error("Failed to execute TimerTask", t);
            }
        }
    }
}
