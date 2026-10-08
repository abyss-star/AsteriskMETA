
// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0

package engine.root.runtime

import android.content.Context
import engine.proxy.ProxyEngineStatus
import engine.root.config.RootStartConfig
import engine.root.daemon.AsteriskdClient
import engine.root.daemon.config.AsteriskdConfig
import engine.root.daemon.config.AsteriskdConfigEncoder
import engine.root.daemon.config.AsteriskdAppPolicyMode
import engine.root.daemon.config.AsteriskdMode
import engine.root.daemon.config.AsteriskdOwner
import engine.root.daemon.control.AsteriskdControlCodec
import engine.root.daemon.control.AsteriskdControlResponse
import engine.root.daemon.control.AsteriskdPhase
import engine.root.daemon.control.AsteriskdResultCode
import engine.root.daemon.control.AsteriskdSnapshot
import engine.root.publication.RootBootConfigWriter
import engine.root.publication.RootBootPublicationCommand
import engine.root.publication.KpmDnsListScope
import engine.root.publication.RootKpmDnsModuleCommand
import engine.root.publication.RootPublicationBundle
import engine.root.publication.RootPublicationCommand
import engine.root.publication.RootPublicationWriter
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
                // A running daemon keeps the rules it was launched with, so a
                // policy change reaches the wire only after a restart. The module
                // is read per query instead, so it can already follow the setting.
                publishKpmDnsModule(root, config)
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
            stage = "kpm_dns_module_write"
            publishKpmDnsModule(root, config)
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
            val snapshot = withTimeoutOrNull(StartTimeoutMilliseconds.milliseconds) {
                when (launchMode) {
                    RootPublicationLaunchMode.Service -> client.awaitRunning(runtimeLayout.asteriskdPath)
                    RootPublicationLaunchMode.Monitor -> client.awaitStopped(runtimeLayout.asteriskdPath)
                    RootPublicationLaunchMode.None -> error("A non-launch publication has no runtime snapshot")
                }
            } ?: throw IllegalStateException("asteriskd did not reach the requested phase before timeout")
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
            retireKpmDnsModule()
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
            retireKpmDnsModule()
            return response
        }
        error(response.result.message ?: "Failed to shutdown asteriskd")
    }

    // The KPM module decides inside the kernel which application asked for a
    // query, and the rule it installs beside that decision lets the applications
    // the proxy does not serve through the interception. It needs the list the
    // daemon enforces for that, so both sides always agree on which applications
    // the proxy serves.
    //
    // A failure here only costs the attribution. The module keeps out of the way
    // and the proxy intercepts every application as it did before, so it never
    // keeps the proxy from starting.
    private suspend fun publishKpmDnsModule(root: RootStartConfig, config: AsteriskdConfig) {
        // A policy that serves every application has no list to work from: an empty
        // one would mark every application and take the fake answers away from all
        // of them, and a policy with no list has nothing to attribute either way.
        val policy = config.network.appPolicy
        val scope = policy.mode.toKpmDnsListScope()
        val command = if (root.kpmDnsModuleActive && scope != null) {
            RootKpmDnsModuleCommand.buildApply(scope = scope, uids = policy.uids)
        } else {
            RootKpmDnsModuleCommand.buildRetire()
        }
        runKpmDnsModuleCommand(command, "kpm_dns_module_write")
    }

    // A whitelist names the applications the proxy serves and a blacklist names the
    // ones it leaves alone, so the half the module has to mark is the complement of
    // the list in the first case and the list itself in the second. Reading a
    // blacklist as a whitelist marks exactly the wrong applications.
    private fun AsteriskdAppPolicyMode.toKpmDnsListScope(): KpmDnsListScope? = when (this) {
        AsteriskdAppPolicyMode.Whitelist -> KpmDnsListScope.MarksAppsOutsideList
        AsteriskdAppPolicyMode.Blacklist -> KpmDnsListScope.MarksAppsInsideList
        AsteriskdAppPolicyMode.Global -> null
    }

    // The interception the marked queries were let through is going away with the
    // proxy, and the module keeps its policy across restarts, so a configuration
    // left enabled would have the next start install rules for a proxy that is
    // not there.
    private suspend fun retireKpmDnsModule() {
        runKpmDnsModuleCommand(RootKpmDnsModuleCommand.buildRetire(), "kpm_dns_module_retire")
    }

    private suspend fun runKpmDnsModuleCommand(command: String, stage: String) {
        runCatching {
            val result = shell.exec(command, ShellExecOptions(logFailure = false))
            if (result.errno != 0) {
                AndroidAppLogger.warn(LogTag, stage + " failed errno=" + result.errno)
            }
        }
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
        // The boot script starts the daemon without the application, so the half
        // the module reads has to be on the device before that happens.
        publishKpmDnsModule(root, config)
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

// A TPROXY or TUN2SOCKS start installs one matching rule per application on the
// list, so a list of a hundred entries costs ten seconds and more before the
// daemon reports itself ready; a global policy, which has no list at all, is
// ready in about four. The budget has to cover the slow half, because giving up
// early does not stop the daemon: it reports a failure to the user and leaves
// the proxy running. Measured on the onyx device, launch to ready:
// global 3.9 s, whitelist with 139 uids 11.7 s, blacklist with 139 uids 6.6 s,
// TUN2SOCKS with 139 uids 14.4 s, and one TPROXY start over 15 s.
private const val StartTimeoutMilliseconds = 45_000L
