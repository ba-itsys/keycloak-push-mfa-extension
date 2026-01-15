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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class PushMfaSseDispatcherTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    @Test
    void submitReturnsFalseWhenAtCapacity() throws Exception {
        PushMfaSseDispatcher dispatcher = new PushMfaSseDispatcher(1);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch unblock = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(1);
        AtomicReference<Throwable> workerFailure = new AtomicReference<>();

        try {
            assertTrue(dispatcher.submit(() -> {
                started.countDown();
                try {
                    // Don't use a timed await here: if it times out, the task would complete and release its permit,
                    // which can make the "at capacity" assertion below flaky.
                    unblock.await();
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    workerFailure.compareAndSet(null, ie);
                } finally {
                    finished.countDown();
                }
            }));

            assertTrue(started.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
            assertFalse(dispatcher.submit(() -> {}));
        } finally {
            unblock.countDown();
        }

        assertTrue(finished.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        assertNull(workerFailure.get(), () -> "Worker task failed: " + workerFailure.get());

        // `finished` only signals that the task's finally-block ran; the dispatcher releases the permit after
        // `task.run()` returns, so we may still race the permit release / executor scheduling. Retry to avoid
        // flakiness.
        CountDownLatch secondTaskFinished = new CountDownLatch(1);
        boolean accepted = false;
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (!accepted && System.nanoTime() < deadline) {
            accepted = dispatcher.submit(secondTaskFinished::countDown);
            if (!accepted) {
                Thread.sleep(5);
            }
        }
        assertTrue(accepted);
        assertTrue(secondTaskFinished.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
    }

    @Test
    void permitsAreReleasedWhenTaskThrows() throws Exception {
        PushMfaSseDispatcher dispatcher = new PushMfaSseDispatcher(1);
        CountDownLatch finished = new CountDownLatch(1);

        assertTrue(dispatcher.submit(() -> {
            try {
                throw new RuntimeException("boom");
            } catch (RuntimeException ignored) {
                // ignore
            } finally {
                finished.countDown();
            }
        }));
        assertTrue(finished.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));

        CountDownLatch secondTaskFinished = new CountDownLatch(1);
        boolean accepted = false;
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (!accepted && System.nanoTime() < deadline) {
            accepted = dispatcher.submit(secondTaskFinished::countDown);
            if (!accepted) {
                Thread.sleep(5);
            }
        }
        assertTrue(accepted);
        assertTrue(secondTaskFinished.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
    }

    @Test
    void doesNotExceedMaxConcurrency() throws Exception {
        PushMfaSseDispatcher dispatcher = new PushMfaSseDispatcher(2);
        CountDownLatch started = new CountDownLatch(2);
        CountDownLatch unblock = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(2);
        CountDownLatch rejectedTaskRan = new CountDownLatch(1);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        AtomicReference<Throwable> workerFailure = new AtomicReference<>();

        Runnable blockingTask = () -> {
            int current = active.incrementAndGet();
            peak.updateAndGet(previous -> Math.max(previous, current));
            started.countDown();
            try {
                unblock.await();
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                workerFailure.compareAndSet(null, ie);
            } finally {
                active.decrementAndGet();
                finished.countDown();
            }
        };

        try {
            assertTrue(dispatcher.submit(blockingTask));
            assertTrue(dispatcher.submit(blockingTask));
            assertTrue(started.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
            assertEquals(2, active.get());

            assertFalse(dispatcher.submit(rejectedTaskRan::countDown));
            assertEquals(1, rejectedTaskRan.getCount());
        } finally {
            unblock.countDown();
        }

        assertTrue(finished.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        assertNull(workerFailure.get(), () -> "Worker task failed: " + workerFailure.get());
        assertEquals(0, active.get());
        assertEquals(2, peak.get());
    }

    @Test
    void acceptsConcurrentTasksUpToLimit() throws Exception {
        int maxConnections = 4;
        PushMfaSseDispatcher dispatcher = new PushMfaSseDispatcher(maxConnections);
        CountDownLatch started = new CountDownLatch(maxConnections);
        CountDownLatch unblock = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(maxConnections);
        AtomicInteger active = new AtomicInteger();
        AtomicReference<Throwable> workerFailure = new AtomicReference<>();

        try {
            for (int i = 0; i < maxConnections; i++) {
                assertTrue(dispatcher.submit(() -> {
                    active.incrementAndGet();
                    started.countDown();
                    try {
                        unblock.await();
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        workerFailure.compareAndSet(null, ie);
                    } finally {
                        active.decrementAndGet();
                        finished.countDown();
                    }
                }));
            }

            assertTrue(started.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
            assertEquals(maxConnections, active.get());
        } finally {
            unblock.countDown();
        }

        assertTrue(finished.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        assertNull(workerFailure.get(), () -> "Worker task failed: " + workerFailure.get());
    }
}
