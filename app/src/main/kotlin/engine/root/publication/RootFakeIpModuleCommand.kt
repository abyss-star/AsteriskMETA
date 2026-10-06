// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0

package engine.root.publication

import utils.shellQuote

// The per application DNS module answers inside the application process, so it
// needs the list, the answer pool and the endpoint the proxy is running with.
// The proxy writes them here, which keeps one list in one place: the module
// follows the same application policy the daemon enforces, and a change that
// reaches the daemon reaches the module with it.
internal object RootFakeIpModuleCommand {
    internal const val ModuleDirectory = "/data/adb/modules/fakeip"
    internal const val ConfigDirectory = "/data/adb/fakeip"
    internal const val ConfigPath = ConfigDirectory + "/dns.conf"

    // The file is written by the same root shell that publishes the daemon
    // configuration, so it keeps root ownership and the label the zygote domain
    // can read. The copy inside the module directory is the fallback path the
    // module uses when the first one is not readable from its own domain.
    fun buildLink(
        moduleEnabled: Boolean,
        endpoint: String,
        pool: String,
        scope: String,
        uids: List<Int>,
    ): String = buildString {
        appendLine("set -eu")
        appendLine("[ -d " + ModuleDirectory.shellQuote() + " ] || exit 0")
        if (!moduleEnabled) {
            // Nothing to hand over, but a file left from an earlier run would
            // keep answering, so it is turned off rather than deleted: the module
            // treats a disabled configuration as not its own.
            appendLine("[ -f " + ConfigPath.shellQuote() + " ] || exit 0")
        }
        appendLine("mkdir -p " + ConfigDirectory.shellQuote())
        appendLine("temporary=" + ConfigPath.shellQuote() + ".tmp.$$")
        appendLine("printf '%s' " + encode(moduleEnabled, endpoint, pool, scope, uids).shellQuote() + " > \"\$temporary\"")
        appendLine("mv -f \"\$temporary\" " + ConfigPath.shellQuote())
        appendLine("chmod 0644 " + ConfigPath.shellQuote())
        appendLine("chcon u:object_r:system_file:s0 " + ConfigPath.shellQuote() + " 2>/dev/null || true")
        val moduleCopy = (ModuleDirectory + "/dns.conf").shellQuote()
        appendLine("cp -f " + ConfigPath.shellQuote() + " " + moduleCopy + " 2>/dev/null || true")
        appendLine("chmod 0644 " + moduleCopy + " 2>/dev/null || true")
    }.trimEnd()

    private fun encode(
        moduleEnabled: Boolean,
        endpoint: String,
        pool: String,
        scope: String,
        uids: List<Int>,
    ): String = buildString {
        val separator = endpoint.lastIndexOf(':')
        val host = if (separator > 0) endpoint.substring(0, separator) else endpoint
        val port = if (separator > 0) endpoint.substring(separator + 1) else "53"
        appendLine("{")
        appendLine("  \"version\": 1,")
        appendLine("  \"generated_at\": \"" + java.time.Instant.now() + "\",")
        appendLine("  \"source\": \"AsteriskMETA\",")
        appendLine("  \"dns\": { \"host\": \"" + host + "\", \"port\": " + port + ", \"proto\": \"udp\" },")
        appendLine("  \"fake_pool\": [\"" + pool + "\"],")
        appendLine("  \"scope\": \"" + scope + "\",")
        appendLine("  \"enabled\": " + moduleEnabled + ",")
        // Every application carries the root manager flag on some devices, and
        // the module reads that flag as its denylist. The list this file carries
        // is the scope decision, so the module must not give it up to the flag:
        // otherwise it stays out of scope everywhere and the scope answers nothing.
        appendLine("  \"ignore_denylist\": true,")
        appendLine("  \"apps\": [")
        val sorted = uids.distinct().sorted()
        sorted.forEachIndexed { index, uid ->
            val suffix = if (index == sorted.size - 1) "" else ","
            appendLine("    { \"uid\": " + uid + " }" + suffix)
        }
        appendLine("  ],")
        appendLine("  \"notes\": \"written by AsteriskMETA; restart the target applications\"")
        append("}")
    }
}
