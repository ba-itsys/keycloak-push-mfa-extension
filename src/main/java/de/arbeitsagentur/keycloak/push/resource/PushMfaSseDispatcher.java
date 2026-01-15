/*
 * Copyright 2026 Bundesagentur für Arbeit
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
