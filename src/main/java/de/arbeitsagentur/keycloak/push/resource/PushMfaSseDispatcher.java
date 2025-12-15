package de.arbeitsagentur.keycloak.push.resource;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

final class PushMfaSseDispatcher {

    private final int maxConnections;
    private final Semaphore permits;
    private final ExecutorService executor;

    PushMfaSseDispatcher(int maxConnections) {
        this.maxConnections = maxConnections;
        this.permits = new Semaphore(maxConnections);
        this.executor = createExecutor(maxConnections);
    }

    int maxConnections() {
        return maxConnections;
    }

    boolean submit(Runnable task) {
        if (!permits.tryAcquire()) {
            return false;
        }
        try {
            executor.execute(() -> {
                try {
                    task.run();
                } finally {
                    permits.release();
                }
            });
            return true;
        } catch (RejectedExecutionException ex) {
            permits.release();
            return false;
        }
    }

    private static ExecutorService createExecutor(int maxConnections) {
        ThreadFactory factory = new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, "push-mfa-sse-" + counter.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            }
        };
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                maxConnections,
                maxConnections,
                60L,
                TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                factory,
                new ThreadPoolExecutor.AbortPolicy());
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }
}
