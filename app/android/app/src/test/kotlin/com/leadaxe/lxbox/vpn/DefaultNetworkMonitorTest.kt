package com.leadaxe.lxbox.vpn

import io.nekohasekai.libbox.InterfaceUpdateListener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DefaultNetworkMonitorTest {
    private class Listener(val name: String) : InterfaceUpdateListener {
        val updates = mutableListOf<String>()

        override fun updateDefaultInterface(
            interfaceName: String,
            interfaceIndex: Int,
            metered: Boolean,
            test: Boolean,
        ) {
            updates += interfaceName
        }

        override fun updateNetworkPath(networkPath: String) {}

        override fun equals(other: Any?): Boolean = other is Listener && other.name == name
        override fun hashCode(): Int = name.hashCode()
    }

    @Test
    fun `identity based fanout reaches every listener and removal is independent`() {
        val fanout = InterfaceUpdateFanout()
        val first = Listener("same")
        val second = Listener("same")

        assertTrue(fanout.add(first))
        assertTrue(fanout.add(second))
        assertFalse(fanout.add(first))
        val targets = fanout.snapshot()
        assertEquals(2, targets.size)
        targets.forEach { it.updateDefaultInterface("wlan0", 1, false, false) }
        assertEquals(listOf("wlan0"), first.updates)
        assertEquals(listOf("wlan0"), second.updates)

        fanout.remove(first)
        assertFalse(fanout.contains(first))
        assertTrue(fanout.contains(second))
        fanout.snapshot().forEach { it.updateDefaultInterface("rmnet0", 2, true, false) }
        assertEquals(listOf("wlan0"), first.updates)
        assertEquals(listOf("wlan0", "rmnet0"), second.updates)
    }
}
