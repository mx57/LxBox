package com.leadaxe.lxbox.vpn

import android.util.Log
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandClientHandler
import io.nekohasekai.libbox.CommandClientOptions
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.CommandServerOptions
import io.nekohasekai.libbox.ConnectionEvents
import io.nekohasekai.libbox.DnsQuery
import io.nekohasekai.libbox.LogIterator
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OutboundGroupIterator
import io.nekohasekai.libbox.OutboundGroupItemIterator
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.SystemProxyStatus
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking

/// §236 — headless probe-сессия: ВРЕМЕННЫЙ CommandServer + конфиг БЕЗ tun,
/// чтобы гонять `urlTestOutbound` по нодам папки, пока VPN ВЫКЛЮЧЕН.
///
/// Каждая probe-сессия владеет своим TCP command endpoint, runtime-каталогом
/// и secret. Одновременно живы не более двух; VPN всегда имеет приоритет.
/// Обычный scanner остаётся последовательным, потому что закрывает свой run
/// перед следующим `probeStart`.
///
/// НЕ Android-сервис: VpnStatus-broadcast, уведомления и tun не затрагиваются.
/// Все колбэки из Go — no-throw (JNI: unchecked exception = Runtime::Abort).
object ProbeSession : CommandServerHandler {
    private const val TAG = "ProbeSession"

    /// §669 — живая сессия одним объектом: владелец прогона ([runId]),
    /// сервер и клиент меняются вместе, поэтому отмена/остановка с чужим
    /// runId не может задеть сессию, поднятую позже.
    private class Session(
        val runId: Long,
        val server: CommandServer,
        val client: CommandClient,
        val scope: CoroutineScope,
        val runtimeDirectory: File,
    ) {
        @Volatile var cancelled = false
        private val clientClosed = AtomicBoolean(false)

        fun disconnectClient() {
            if (clientClosed.compareAndSet(false, true)) {
                runCatching { client.disconnect() }
            }
        }
    }

    private val sessions = ProbeSessionRegistry<Session>()
    private val nextRunId = AtomicLong(0)
    private val secureRandom = SecureRandom()

    /// §669 — ответ на вызов с устаревшим/чужим runId: вызов ничего не делает.
    /// Dart сверяет строку дословно (`kProbeStaleRun`).
    const val STALE_RUN = "stale run"

    /// §669 — потолок закрытия сервера probe-сессии, как у остановки
    /// VPN-службы (§287/§668): `closeService` синхронно разбирает все
    /// WG-узлы конфига (10–17 с на устройстве).
    private const val CLOSE_TIMEOUT_MS = 3_000L

    val active: Boolean get() = sessions.size != 0

    /// Запуск независимой сессии с готовым probe-конфигом (без inbound'ов).
    /// Третья попытка при двух живых сессиях возвращает ошибку и не вытесняет их.
    @Synchronized
    fun start(config: String): Map<String, Any> {
        // §732 — гейт по статусу службы, а не только по commandClient: тот
        // появляется лишь на Started, а всё время Starting был null.
        if (probeMayStart(BoxService.commandClient != null, BoxVpnService.currentStatus)) {
            return startResult("VPN is running — test uses the live tunnel instead")
        }
        if (sessions.size >= 2) return startResult("probe session capacity reached")
        val id = nextRunId.incrementAndGet()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val runtimeDirectory = File(
            BoxApplication.application.filesDir,
            "probes/${java.util.UUID.randomUUID()}",
        )
        var cs: CommandServer? = null
        var cl: CommandClient? = null
        var monitorStarted = false
        return runCatching {
            if (!runtimeDirectory.mkdirs() && !runtimeDirectory.isDirectory) {
                error("cannot create probe runtime directory")
            }
            val secret = commandSecret()
            val options = CommandServerOptions().apply {
                commandServerListenPort = 0
                commandServerUseTCP = true
                commandServerSecret = secret
                basePath = runtimeDirectory.absolutePath
                workingPath = runtimeDirectory.absolutePath
                tempPath = File(runtimeDirectory, "temp").absolutePath
            }
            // Без монитора local-DNS (§049 F26) мертв → каждый lookup из
            // probe-конфига падал SERVFAIL (device-репро 04.07.2026).
            runBlocking { DefaultNetworkMonitor.start(id, scope) { } }
            monitorStarted = true
            val handler = object : CommandServerHandler by this@ProbeSession {
                override fun serviceStop() {
                    Thread { runCatching { stop(id) } }.start()
                }
            }
            val server = Libbox.newCommandServerWithOptions(handler, ProbePlatform, options)
            cs = server
            server.start()
            val port = server.listenPort()
            if (port == 0) error("probe command server did not select a TCP port")
            CacheDbLockRetry.startOrRetry("probe-$id", File(runtimeDirectory, "cache.db")) {
                server.startOrReloadService(config, OverrideOptions())
            }
            val client = CommandClient(
                ProbeClientHandler,
                CommandClientOptions().apply {
                    commandServerListenPort = port
                    commandServerUseTCP = true
                    commandServerSecret = secret
                },
            )
            cl = client
            client.connect()
            val created = Session(id, server, client, scope, runtimeDirectory)
            check(sessions.add(id, created)) { "probe session capacity reached" }
            Log.d(TAG, "probe session started (run=$id)")
            startResult("", id)
        }.getOrElse {
            Log.e(TAG, "probe start failed", it)
            cl?.let { c -> runCatching { c.disconnect() } }
            if (monitorStarted) runCatching { runBlocking { DefaultNetworkMonitor.stop(id) } }
            cs?.let { s -> closeServerBounded(s, "start failed", runtimeDirectory) }
            scope.cancel()
            if (cs == null) runtimeDirectory.deleteRecursively()
            startResult(it.message ?: "probe start failed")
        }
    }

    private fun commandSecret(): String = ByteArray(32).also { secureRandom.nextBytes(it) }
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun startResult(error: String, runId: Long = 0): Map<String, Any> =
        mapOf("error" to error, "runId" to runId)

    /// Сессия прогона [runId] либо `null` и причина отказа.
    private fun sessionFor(runId: Long): Pair<Session?, String> {
        val s = sessions.get(runId) ?: return null to STALE_RUN
        if (s.cancelled) return null to "probe run cancelled"
        return s to ""
    }

    /// Синхронный тест одной ноды (SPEC 014, Variant B: провал — в `error`
    /// результата, не в исключении). Конкурентные вызовы допустимы — unary
    /// gRPC мультиплексируется на одном клиенте (как pingClient §209).
    fun urlTest(runId: Long, tag: String, link: String, timeoutMs: Int): Map<String, Any> {
        val (s, why) = sessionFor(runId)
        if (s == null) return mapOf("delay" to 0, "error" to why)
        return runCatching {
            val r = s.client.urlTestOutbound(tag, link, timeoutMs)
            mapOf("delay" to r.delay, "error" to (r.error ?: ""))
        }.getOrElse {
            mapOf("delay" to 0, "error" to (it.message ?: "urlTestOutbound failed"))
        }
    }

    /// §669 — отмена прогона по образцу §175 (`BoxCommandClient.cancelPing`):
    /// disconnect клиента → ядро отменяет per-call ctx уже ушедших в dial
    /// замеров, они возвращаются сразу, не дожидаясь таймаута. Сервер живёт
    /// до [stop] своего владельца. Не synchronized: монитор может держать
    /// долгий [start]/[stop], отмена его ждать не должна.
    fun cancel(runId: Long) {
        val s = sessions.get(runId) ?: return
        s.cancelled = true
        s.disconnectClient()
        Log.d(TAG, "probe run $runId cancelled")
    }

    /// §392 — диагностический HTTP GET через узел probe-сессии (kernel SPEC
    /// 058). Тело ответа возвращается как есть; парсинг — сторона Dart.
    ///
    /// Провал обмена приезжает исключением (libbox-обёртка мапит payload-error
    /// в Go-error), не-2xx — обычный результат со статусом. Форма Map зеркалит
    /// [BoxCommandClient.getUrlViaOutbound]: у Dart один разбор на обе ветки.
    fun getUrl(
        runId: Long,
        tag: String,
        link: String,
        timeoutMs: Int,
        maxBytes: Int,
        userAgent: String,
    ): Map<String, Any> {
        val (s, why) = sessionFor(runId)
        if (s == null) return mapOf("error" to why)
        return runCatching {
            val r = s.client.getURLViaOutbound(
                tag, link, timeoutMs, maxBytes, userAgentHeaders(userAgent),
            )
            // Геттеры без `get`-префикса — см. BoxCommandClient.getUrlViaOutbound.
            mapOf(
                "status" to r.status(),
                "content" to r.content(),
                "truncated" to r.truncated(),
                "contentType" to r.contentType(),
                "remoteAddr" to r.remoteAddr(),
                "elapsedMs" to r.elapsedMs(),
                "error" to "",
            )
        }.getOrElse {
            mapOf("error" to (it.message ?: "getURLViaOutbound failed"))
        }
    }

    /// §669 — остановка своей сессии: чужой/устаревший [runId] — no-op.
    fun stop(runId: Long) {
        val s = sessions.get(runId) ?: return
        if (sessions.remove(runId, s)) releaseSession(s, "run=$runId")
    }

    /// Принудительная остановка всех сессий: старт VPN ([BoxService]).
    fun stop() = stopAll()

    @Synchronized
    fun stopAll() {
        sessions.drain().forEach { releaseSession(it, "forced") }
    }

    private fun releaseSession(session: Session, reason: String) {
        session.disconnectClient()
        runCatching { runBlocking { DefaultNetworkMonitor.stop(session.runId) } }
        closeServerBounded(session.server, reason, session.runtimeDirectory)
        session.scope.cancel()
    }

    /// §669 — закрытие сервера под потолком [CLOSE_TIMEOUT_MS] (образец —
    /// шаги `StopTrace` §668). Блокирующий JNI-вызов потолок не прерывает:
    /// зависший `closeService` остаётся в своём потоке-демоне, а сессия уже
    /// снята — монитор не держит `start`/`stop` и `BoxService.startCommandServer`.
    /// Runtime-каталог удаляется только после фактического завершения закрытия.
    private fun closeServerBounded(
        cs: CommandServer,
        reason: String,
        runtimeDirectory: File,
    ) {
        val done = CountDownLatch(1)
        Thread({
            runCatching { cs.close() }
            runCatching { cs.closeService() }
            runCatching { runtimeDirectory.deleteRecursively() }
            done.countDown()
        }, "lxbox-probe-close").apply { isDaemon = true }.start()
        if (done.await(CLOSE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            Log.d(TAG, "probe session stopped ($reason)")
        } else {
            Log.w(TAG, "probe close timed out after ${CLOSE_TIMEOUT_MS}ms ($reason), session released")
        }
    }

    // ─── CommandServerHandler (probe-инстанс) — минимальные no-op'ы ──────

    override fun serviceReload() {}

    /// Каждый server получает handler с собственным runId; общий callback
    /// не может остановить чужую сессию.
    override fun serviceStop() {}

    override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus()
    override fun setSystemProxyEnabled(isEnabled: Boolean) {}

    /// Error-метод: gomobile ловит исключение и вернёт его как Go error —
    /// до JNI Runtime::Abort не доходит (паттерн BoxService).
    override fun connectSSHAgent(): Int =
        throw UnsupportedOperationException("SSH agent not supported")

    override fun triggerNativeCrash() {}

    override fun writeDebugMessage(message: String) {
        runCatching { Log.d(TAG, "[core] $message") }
    }

    /// Платформа probe-инстанса: конфиг без tun → `openTun` не вызывается
    /// (§119-инвариант); дефолты `PlatformInterfaceWrapper` покрывают
    /// остальное. Уведомления глушим — сессия невидимая.
    private object ProbePlatform : PlatformInterfaceWrapper {
        override fun sendNotification(notification: io.nekohasekai.libbox.Notification) {}
    }

    /// Клиент без подписок — только unary urlTestOutbound (аналог PingHandler).
    private object ProbeClientHandler : CommandClientHandler {
        override fun connected() { runCatching { Log.d(TAG, "client connected") } }
        override fun disconnected(message: String) {
            runCatching { Log.d(TAG, "client disconnected: $message") }
        }
        override fun clearLogs() { runCatching { } }
        override fun setDefaultLogLevel(level: Int) { runCatching { } }
        override fun initializeClashMode(modeList: StringIterator?, currentMode: String?) {
            runCatching { }
        }
        override fun updateClashMode(newMode: String?) { runCatching { } }
        override fun writeLogs(messageList: LogIterator?) { runCatching { } }
        override fun writeStatus(message: StatusMessage?) { runCatching { } }
        override fun writeGroups(groups: OutboundGroupIterator?) { runCatching { } }
        override fun writeOutbounds(outbounds: OutboundGroupItemIterator?) { runCatching { } }
        override fun writeConnectionEvents(message: ConnectionEvents?) { runCatching { } }
        // §261 — CommandClientHandler расширен writeDNSQuery. Probe DNS не слушает.
        override fun writeDNSQuery(query: DnsQuery?) { runCatching { } }
    }
}

internal fun probeMayStart(vpnClientAlive: Boolean, vpnStatus: VpnStatus): Boolean =
    !vpnClientAlive && vpnStatus == VpnStatus.Stopped
