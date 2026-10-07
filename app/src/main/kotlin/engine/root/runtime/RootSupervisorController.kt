
// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0

package engine.root.runtime

import android.content.Context
import engine.proxy.ProxyEngineStatus
import engine.root.config.RootStartConfig
import engine.root.daemon.AsteriskdClient
import engine.root.daemon.config.AsteriskdConfig
import engine.root.daemon.config.AsteriskdConfigEncoder
import engine.root.daemon.config.AsteriskdMode
import engine.root.daemon.config.AsteriskdOwner
import engine.root.daemon.control.AsteriskdControlCodec
import engine.root.daemon.control.AsteriskdControlResponse
import engine.root.daemon.control.AsteriskdPhase
import engine.root.daemon.control.AsteriskdResultCode
import engine.root.daemon.control.AsteriskdSnapshot
import engine.root.publication.RootBootConfigWriter
import engine.root.publication.RootBootPublicationCommand
import engine.root.publication.RootPublicationBundle
import engine.root.publication.RootPublicationCommand
import engine.root.publication.RootPublicationWriter
import engine.mihomo.DefaultMihomoDnsFakeIpRange
import engine.mihomo.MihomoModuleDnsListen
import engine.root.daemon.config.AsteriskdAppPolicyMode
import engine.root.daemon.config.AsteriskdDnsHijackScope
import engine.root.publication.RootFakeIpModuleCommand
import engine.root.publication.RootPublicationLaunchMode
import engine.root.publication.RootServiceLogCleanupWarningPrefix
import engine.root.publication.prepareRootPublicationDirectories
import engine.root.publication.rootRuntimeLayout
import features.logs.AndroidAppLogger
import features.logs.clearServiceLogRepositories
import features.subscription.runtime.mihomoCoreFetchLock
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import system.RootShellGateway
import system.ShellExecOptions
import system.ShellExecResult
import kotlin.time.Duration.Companion.milliseconds

internal class RootSupervisorController(
    context: Context,
    private val shell: RootShellGateway,
) {
    private val appContext = context.applicationContext
    private val runtimeLayout = appContext.rootRuntimeLayout()
    private val client = AsteriskdClient(shell)
    suspend fun status(): AsteriskdControlResponse = client.status(runtimeLayout.asteriskdPath)

    fun observeStatus(): Flow<AsteriskdSnapshot> = client.observeStatus(runtimeLayout.asteriskdPath)
        .onEach { snapshot -> observeRunningFailure(snapshot) }

    suspend fun preflightStart(expectedMode: AsteriskdMode, explicitRestart: Boolean): AsteriskdSnapshot? {
        return status().preflightStart(AsteriskdOwner.AsteriskMeta, expectedMode, explicitRestart)
            ?.also { snapshot -> observeRunningFailure(snapshot, explicitRootAction = true) }
    }

    suspend fun ownsRuntime(): Boolean = status().boundSnapshot()?.owner == AsteriskdOwner.AsteriskMeta

    suspend fun proxyStatus(runMode: Int, expectedMode: AsteriskdMode): ProxyEngineStatus {
        val snapshot = status().boundSnapshot() ?: return ProxyEngineStatus(running = false, runMode = runMode)
        observeRunningFailure(snapshot)
        return snapshot.toProxyEngineStatus(runMode, expectedMode)
    }

    private suspend fun observeRunningFailure(snapshot: AsteriskdSnapshot, explicitRootAction: Boolean = false) {
        if (snapshot.owner == AsteriskdOwner.AsteriskMeta && snapshot.phase == AsteriskdPhase.Running) {
            RootFailureWatcher.ensureStarted(appContext, shell, runtimeLayout, explicitRootAction)
        }
    }

    fun proxyStatus(snapshot: AsteriskdSnapshot, runMode: Int, expectedMode: AsteriskdMode): ProxyEngineStatus =
        snapshot.toProxyEngineStatus(runMode, expectedMode)

    fun requireRunning(snapshot: AsteriskdSnapshot, expectedMode: AsteriskdMode) {
        snapshot.requireRunning(AsteriskdOwner.AsteriskMeta, expectedMode)
    }

    suspend fun start(
        root: RootStartConfig,
        config: AsteriskdConfig,
    ): AsteriskdSnapshot {
        RootFailureWatcher.beginAttempt()
        status().boundSnapshot()?.let { snapshot ->
            val disposition = snapshot.ordinaryStartDisposition(AsteriskdOwner.AsteriskMeta, config.mode)
            if (disposition == RootOrdinaryStartDisposition.Reuse) {
                observeRunningFailure(snapshot, explicitRootAction = true)
                // The running daemon keeps the rules it was launched with, so a scope
                // change reaches the wire only after a restart. The module is read per
                // application start instead, so it can already follow the new setting.
                publishFakeIpModuleLink(config)
                return snapshot
            }
            if (disposition.shutdownBeforeLaunch) shutdownOwn()
            return launch(
                root = root,
                config = config,
                restartExpectedOwner = snapshot.owner,
                launchMode = RootPublicationLaunchMode.Service,
            )
        }

        return launch(root, config, restartExpectedOwner = null, RootPublicationLaunchMode.Service)
    }

    suspend fun restart(
        root: RootStartConfig,
        config: AsteriskdConfig,
    ): AsteriskdSnapshot {
        RootFailureWatcher.beginAttempt()
        val snapshot = status().boundSnapshot()
        if (snapshot != null && snapshot.owner != AsteriskdOwner.AsteriskMeta) {
            throw RootRuntimeConflictException(snapshot)
        }
        return launch(
            root = root,
            config = config,
            restartExpectedOwner = snapshot?.owner,
            launchMode = RootPublicationLaunchMode.Service,
        )
    }

    suspend fun reconfigureServiceControl(
        root: RootStartConfig,
        config: AsteriskdConfig,
    ): Boolean {
        RootFailureWatcher.beginAttempt()
        val snapshot = status().boundSnapshot()
        if (snapshot != null && snapshot.owner != AsteriskdOwner.AsteriskMeta) {
            throw RootRuntimeConflictException(snapshot)
        }
        val plan = try {
            serviceControlReconfigurePlan(snapshot?.phase, config.serviceControl.enabled)
        } catch (_: IllegalArgumentException) {
            throw RootRuntimeBusyException(requireNotNull(snapshot))
        }
        if (plan.shutdownRequired) shutdownOwn()
        when (plan.launchMode) {
            RootPublicationLaunchMode.Service -> launch(
                root,
                config,
                restartExpectedOwner = snapshot?.owner,
                launchMode = RootPublicationLaunchMode.Service,
            )
            RootPublicationLaunchMode.Monitor -> launch(
                root,
                config,
                restartExpectedOwner = snapshot?.owner,
                launchMode = RootPublicationLaunchMode.Monitor,
            )
            RootPublicationLaunchMode.None -> RootFailureWatcher.stop()
        }
        return plan.launchMode == RootPublicationLaunchMode.Service
    }

    // The module configuration follows the daemon configuration it was compiled
    // from, so the list the module answers for is the list the rules enforce. A
    // failure here only costs the module its list, and the module fails open, so
    // it never keeps the proxy from starting.
    private suspend fun publishFakeIpModuleLink(config: AsteriskdConfig) {
        val moduleEnabled = config.network.dnsHijackScope == AsteriskdDnsHijackScope.Module
        val scope = when (config.network.appPolicy.mode) {
            AsteriskdAppPolicyMode.Blacklist -> "deny"
            else -> "allow"
        }
        val command = RootFakeIpModuleCommand.buildLink(
            moduleEnabled = moduleEnabled,
            endpoint = MihomoModuleDnsListen,
            pool = config.network.fakeDnsIpv4Pool ?: DefaultMihomoDnsFakeIpRange,
            scope = scope,
            uids = config.network.appPolicy.uids,
        )
        runCatching {
            val result = shell.exec(command, ShellExecOptions(logFailure = false))
            if (result.errno != 0) {
                AndroidAppLogger.warn(LogTag, "module_link_write failed errno=" + result.errno)
            }
        }
    }

    // The endpoint the module was handed is going away with the proxy. Leaving the
    // list in place would cost every resolution a failed attempt at a dead port
    // before the module falls back to the system resolver, so it is turned off.
    private suspend fun retireFakeIpModuleLink() {
        val command = RootFakeIpModuleCommand.buildLink(
            moduleEnabled = false,
            endpoint = MihomoModuleDnsListen,
            pool = DefaultMihomoDnsFakeIpRange,
            scope = "allow",
            uids = emptyList(),
        )
        runCatching {
            shell.exec(command, ShellExecOptions(logFailure = false))
        }
    }

    private suspend fun launch(
        root: RootStartConfig,
        config: AsteriskdConfig,
        restartExpectedOwner: AsteriskdOwner?,
        launchMode: RootPublicationLaunchMode,
    ): AsteriskdSnapshot {
        var stage = "prepare_directories"
        RootFailureWatcher.ensureStarted(appContext, shell, runtimeLayout, explicitRootAction = true, running = false)
        runCatching { AndroidAppLogger.info(LogTag, "root_start mode=${config.mode.wireValue} launch=$launchMode stage=$stage") }
        try {
            preparePublication()
            stage = "encode_config"
            val daemonConfigBytes = AsteriskdConfigEncoder.encode(config).toByteArray(Charsets.UTF_8)
            val publication = RootPublicationBundle(
                runtimeLayout = runtimeLayout,
                bootEnabled = root.enableBoot,
                launchMode = launchMode,
                restartExpectedOwner = restartExpectedOwner?.wireValue,
                manageProviders = root.manageProviders,
            )
            clearInMemoryServiceLogs()
            stage = "root_prepare"
            val preparationResult = shell.exec(
                RootPublicationCommand.buildPreparation(publication),
                ShellExecOptions(logFailure = false),
            )
            reportServiceLogCleanupFailures(preparationResult.stderr)
            if (preparationResult.errno != 0 || preparationResult.stdout.isNotBlank()) {
                throw launchFailure(preparationResult)
            }
            stage = "config_write"
            RootPublicationWriter.write(runtimeLayout, root.mihomoProfileBytes, daemonConfigBytes)
            runCatching { AndroidAppLogger.info(LogTag, "root_start stage=config_write result=ok") }
            stage = "module_link_write"
            publishFakeIpModuleLink(config)
            stage = "launch"
            val launchResult = mihomoCoreFetchLock.withLock {
                shell.exec(
                    RootPublicationCommand.buildLaunch(publication),
                    ShellExecOptions(logFailure = false),
                )
            }
            if (launchResult.errno != 0 || launchResult.stdout.isNotBlank()) {
                throw launchFailure(launchResult)
            }
            stage = "await_ready"
            runCatching { AndroidAppLogger.info(LogTag, "root_start stage=launch result=sent") }
            val snapshot = awaitPhase(launchMode)
            if (snapshot.owner != AsteriskdOwner.AsteriskMeta) throw RootRuntimeConflictException(snapshot)
            require(snapshot.mode == config.mode) { "Unexpected ROOT mode ${snapshot.mode.wireValue}" }
            if (launchMode == RootPublicationLaunchMode.Service) {
                observeRunningFailure(snapshot, explicitRootAction = true)
            } else {
                // A resident supervisor waiting for a trigger has no running core to monitor.
                RootFailureWatcher.stop()
            }
            runCatching { AndroidAppLogger.info(LogTag, "root_start stage=ready phase=${snapshot.phase}") }
            return snapshot
        } catch (error: Exception) {
            withContext(NonCancellable) { RootFailureWatcher.stop() }
            val outcome = if (error is kotlinx.coroutines.CancellationException) "cancelled" else "failed"
            runCatching { AndroidAppLogger.warn(LogTag, "root_start stage=$stage result=$outcome type=${error.javaClass.simpleName}") }
            throw error
        }
    }

    /**
     * Waits for the phase this launch asked for. The daemon applies its whole rule set before it
     * reports that phase, so a start that outlives the wait is not a failure by itself: the runtime
     * is asked what it actually is before one is reported. A start that ends by telling the user it
     * failed while the service runs is worse than a start that reports what it found, and the screen
     * behind it can then never contradict the service.
     */
    private suspend fun awaitPhase(launchMode: RootPublicationLaunchMode): AsteriskdSnapshot {
        val awaited = withTimeoutOrNull(StartTimeoutMilliseconds.milliseconds) {
            when (launchMode) {
                RootPublicationLaunchMode.Service -> client.awaitRunning(runtimeLayout.asteriskdPath)
                RootPublicationLaunchMode.Monitor -> client.awaitStopped(runtimeLayout.asteriskdPath)
                RootPublicationLaunchMode.None -> error("A non-launch publication has no runtime snapshot")
            }
        }
        if (awaited != null) return awaited
        val settled = runCatching { status().boundSnapshot() }.getOrNull()
        val reached = when (launchMode) {
            RootPublicationLaunchMode.Service -> settled?.phase == AsteriskdPhase.Running
            RootPublicationLaunchMode.Monitor -> settled?.phase == AsteriskdPhase.Stopped
            RootPublicationLaunchMode.None -> false
        }
        if (settled == null || !reached) {
            throw IllegalStateException("asteriskd did not reach the requested phase before timeout")
        }
        runCatching {
            AndroidAppLogger.warn(LogTag, "root_start stage=await_ready result=reconciled phase=" + settled.phase)
        }
        return settled
    }

    suspend fun stopOwn(): AsteriskdControlResponse {
        val initial = status()
        val initialSnapshot = initial.boundSnapshot() ?: run {
            RootFailureWatcher.stop()
            return initial
        }
        if (initialSnapshot.owner != AsteriskdOwner.AsteriskMeta) {
            throw RootRuntimeConflictException(initialSnapshot)
        }
        val result = shell.exec(RootStopOwnCommand.build(runtimeLayout), ShellExecOptions(logFailure = false))
        val response = AsteriskdControlCodec.decodeShellResponse(result)
        when (response.requestId) {
            "status" -> response.boundSnapshot()?.let { snapshot ->
                if (snapshot.owner != AsteriskdOwner.AsteriskMeta) throw RootRuntimeConflictException(snapshot)
            }
            "stop" -> Unit
            else -> error("Unexpected stop-own response id")
        }
        if (response.result.code == AsteriskdResultCode.Ok || response.result.code == AsteriskdResultCode.NotRunning) {
            RootFailureWatcher.stop()
            retireFakeIpModuleLink()
            return response
        }
        error(response.result.message ?: "Failed to stop asteriskd")
    }

    suspend fun shutdownOwn(): AsteriskdControlResponse {
        val initial = status()
        val initialSnapshot = initial.boundSnapshot() ?: run {
            RootFailureWatcher.stop()
            return initial
        }
        if (initialSnapshot.owner != AsteriskdOwner.AsteriskMeta) {
            throw RootRuntimeConflictException(initialSnapshot)
        }
        val result = shell.exec(
            RootShutdownOwnCommand.build(runtimeLayout),
            ShellExecOptions(logFailure = false),
        )
        val response = AsteriskdControlCodec.decodeShellResponse(result)
        when (response.requestId) {
            "status" -> response.boundSnapshot()?.let { snapshot ->
                if (snapshot.owner != AsteriskdOwner.AsteriskMeta) {
                    throw RootRuntimeConflictException(snapshot)
                }
            }
            "shutdown", "stop" -> Unit
            else -> error("Unexpected shutdown-own response id")
        }
        if (response.result.code == AsteriskdResultCode.Ok ||
            response.result.code == AsteriskdResultCode.NotRunning
        ) {
            RootFailureWatcher.stop()
            return response
        }
        error(response.result.message ?: "Failed to shutdown asteriskd")
    }

    suspend fun publishBoot(
        root: RootStartConfig,
        config: AsteriskdConfig,
    ) {
        preparePublication()
        RootBootConfigWriter.write(
            layout = runtimeLayout,
            coreConfigBytes = root.mihomoProfileBytes,
            encodedDaemonConfig = AsteriskdConfigEncoder.encode(config),
        )
        val result = shell.exec(
            RootBootPublicationCommand.buildInstallation(runtimeLayout),
            ShellExecOptions(logFailure = false),
        )
        requirePublicationSuccess(result)
    }

    private fun requirePublicationSuccess(result: ShellExecResult) {
        if (result.errno != 0 || result.stdout.isNotBlank()) throw launchFailure(result)
    }

    suspend fun removeBoot() {
        val result = shell.exec(
            RootBootPublicationCommand.buildRemoval(runtimeLayout),
            ShellExecOptions(logFailure = false),
        )
        requirePublicationSuccess(result)
    }

    private fun launchFailure(result: ShellExecResult): IllegalStateException {
        runCatching { AndroidAppLogger.warn(LogTag, "root_launcher exit=${result.errno} stderr=${sanitizeLauncherStderr(result.stderr).take(512)}") }
        val controlResponse = result.controlResponseOrNull()
        controlResponse?.result?.snapshot?.rejectBound(AsteriskdOwner.AsteriskMeta)
        val message = controlResponse?.result?.message ?: sanitizeLauncherStderr(result.stderr)
            .ifBlank { "asteriskd launcher exited with ${result.errno}" }
        return IllegalStateException(message)
    }

    private fun preparePublication() {
        appContext.prepareRootPublicationDirectories()
    }

    private fun clearInMemoryServiceLogs() {
        runCatching { clearServiceLogRepositories() }.onFailure { error ->
            runCatching { AndroidAppLogger.warn(LogTag, "Failed to clear in-memory service logs", error) }
        }
    }

    private fun reportServiceLogCleanupFailures(stderr: String) {
        stderr.lineSequence()
            .filter { line -> line.startsWith(RootServiceLogCleanupWarningPrefix) }
            .forEach { warning -> runCatching { AndroidAppLogger.warn(LogTag, warning) } }
    }

}

private const val LogTag = "RootSupervisorController"

internal fun sanitizeLauncherStderr(stderr: String): String {
    val retained = mutableListOf<String>()
    var readingFileContexts = false
    stderr.lineSequence().forEach { line ->
        if (line.startsWith(RootServiceLogCleanupWarningPrefix)) return@forEach
        if (line.trim() == "SELinux: Loaded file context from:") {
            readingFileContexts = true
            return@forEach
        }
        val trimmed = line.trim()
        if (
            readingFileContexts &&
            trimmed.startsWith('/') &&
            "/selinux/" in trimmed &&
            trimmed.endsWith("_file_contexts")
        ) {
            return@forEach
        }
        readingFileContexts = false
        retained += line
    }
    val stderrWithoutCleanupWarnings = stderr.lineSequence()
        .filterNot { line -> line.startsWith(RootServiceLogCleanupWarningPrefix) }
        .joinToString("\n")
        .trim()
    return retained.joinToString("\n").trim().ifBlank { stderrWithoutCleanupWarnings }
}

// The daemon applies its whole rule set before it reports the running phase, and a policy that names
// applications adds rules per application and transport, so the wait grows with the application list
// on the device. This bound only decides when a start the daemon never reports on is given up on; a
// phase the daemon does report arrives long before it.
private const val StartTimeoutMilliseconds = 60_000L
