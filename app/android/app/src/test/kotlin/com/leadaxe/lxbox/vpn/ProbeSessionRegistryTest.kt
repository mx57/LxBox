package com.leadaxe.lxbox.vpn

import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ProbeSessionRegistryTest {
    @Test
    fun `capacity is two and a rejected start keeps both live sessions`() {
        val registry = ProbeSessionRegistry<Any>()
        val first = Any()
        val second = Any()

        assertTrue(registry.add(1, first))
        assertTrue(registry.add(2, second))
        assertFalse(registry.add(1, first))
        assertFalse(registry.add(3, Any()))
        assertEquals(2, registry.size)
        assertSame(first, registry.get(1))
        assertSame(second, registry.get(2))
    }

    @Test
    fun `stop removes only the expected session and stale IDs are no-ops`() {
        val registry = ProbeSessionRegistry<Any>()
        val first = Any()
        val replacement = Any()
        assertTrue(registry.add(1, first))
        assertTrue(registry.add(2, Any()))

        assertFalse(registry.remove(1, replacement))
        assertSame(first, registry.get(1))
        assertFalse(registry.remove(99, first))
        assertTrue(registry.remove(1, first))
        assertNull(registry.get(1))
        assertFalse(registry.remove(1, first))
        assertEquals(1, registry.size)
    }

    @Test
    fun `forced stop drains all sessions once`() {
        val registry = ProbeSessionRegistry<Any>()
        val first = Any()
        val second = Any()
        registry.add(1, first)
        registry.add(2, second)

        assertEquals(setOf(first, second), registry.drain().toSet())
        assertTrue(registry.drain().isEmpty())
        assertEquals(0, registry.size)
        assertFalse(registry.remove(1, first))
    }

    @Test
    fun `concurrent starts never exceed capacity`() {
        val registry = ProbeSessionRegistry<Any>()
        val ready = CountDownLatch(16)
        val start = CountDownLatch(1)
        val accepted = AtomicInteger()
        val threads = List(16) { id ->
            Thread {
                ready.countDown()
                start.await()
                if (registry.add(id.toLong(), Any())) accepted.incrementAndGet()
            }.apply { start() }
        }

        assertTrue(ready.await(2, java.util.concurrent.TimeUnit.SECONDS))
        start.countDown()
        threads.forEach { it.join(2_000) }
        assertTrue(threads.none { it.isAlive })
        assertEquals(2, accepted.get())
        assertEquals(2, registry.size)
    }
}
