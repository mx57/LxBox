package com.leadaxe.lxbox.vpn

import java.util.concurrent.ConcurrentHashMap

internal class ProbeSessionRegistry<T>(private val capacity: Int = 2) {
    private val sessions = ConcurrentHashMap<Long, T>()

    @Synchronized
    fun add(runId: Long, session: T): Boolean {
        if (sessions.size >= capacity) return false
        return sessions.putIfAbsent(runId, session) == null
    }

    fun get(runId: Long): T? = sessions[runId]

    @Synchronized
    fun remove(runId: Long, expected: T): Boolean =
        sessions.remove(runId, expected)

    @Synchronized
    fun drain(): List<T> {
        val remaining = sessions.values.toList()
        sessions.clear()
        return remaining
    }

    val size: Int get() = sessions.size
}
