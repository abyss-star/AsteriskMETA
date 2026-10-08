// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0

package engine.root.publication

import utils.shellQuote

// The platform resolver answers for every application at once, so the proxy cannot
// tell the queries one application made from the queries another one made: its
// interception is all or nothing. A KPM module running inside the kernel can tell
// them apart, because the query still carries the credentials of the application
// that asked for it when the module sees it.
//
// This command hands the module the half of the decision only the application side
// knows: the application list the proxy is enforcing. The module marks the queries of
// the applications that half leaves out -- or the ones it names, when the list is the
// blacklist and the half is the applications the proxy does not serve -- and the rule
// the module installs beside it lets them through the proxy's interception untouched,
// so they keep using the system resolver.
//
// The file is KPM specific on purpose. It carries only what this route reads, and
// it is written and read independently of every other route's configuration.
internal object RootKpmDnsModuleCommand {
    internal const val ConfigDirectory = "/data/adb/fakeip"
    internal const val ConfigPath = ConfigDirectory + "/kpm.conf"
    internal const val HelperPath = ConfigDirectory + "/fakeip-kpm.sh"

    // Bit 25. It has to miss every fwmark policy rule on the device, because a
    // packet that carries it is routed before any rule of the proxy sees it; the
    // helper checks that before it installs anything, and an earlier choice of
    // 0x08000000 was rejected on a device whose policy routing owns that bit.
    internal const val DefaultMark = "0x02000000"

    // The traffic the module is allowed to decide about. Only the port the
    // platform resolver uses: private DNS over TLS carries a name of its own and
    // redirecting it would break the certificate check.
    private val Ports = listOf(53)

    // The helper reads the file and does the kernel side: it configures the module
    // and installs the rule that lets the marked queries through. It is invoked
    // rather than reimplemented here so the module protocol stays in one place.
    // A device without the helper keeps working: nothing is installed, the proxy
    // intercepts every application as it did before, and the log says why.
    fun buildApply(scope: KpmDnsListScope, uids: List<Int>, mark: String = DefaultMark): String = buildString {
        appendLine("set -eu")
        // The helper is the whole test of whether a device can do this: the module's
        // flashable package is what puts it there, and it is what owns the kernel
        // protocol. Testing for a module directory instead would answer a different
        // question -- /data/adb/modules/fakeip belongs to the Zygisk route's module,
        // which shares the name but not the mechanism, so a device carrying only that
        // one would look ready and then do nothing.
        appendLine(ensureHelper())
        appendLine(writeConfig(enabled = true, mark = mark, scope = scope, uids = uids))
        appendLine("sh " + HelperPath.shellQuote() + " apply >/dev/null 2>&1 || true")
    }.trimEnd()

    // The proxy is going away with the rules the marked queries were let through,
    // and the module keeps its policy across restarts, so the configuration is
    // turned off rather than left behind: a file that still claims to be enabled
    // would have the next start install rules for a proxy that is not there.
    fun buildRetire(): String = buildString {
        appendLine("set -eu")
        appendLine(ensureHelper())
        appendLine(writeConfig(enabled = false, mark = DefaultMark, scope = ScopeOfRetiredConfig, uids = emptyList()))
        appendLine("sh " + HelperPath.shellQuote() + " off >/dev/null 2>&1 || true")
    }.trimEnd()

    private fun ensureHelper(): String = buildString {
        append("[ -f ")
        append(HelperPath.shellQuote())
        append(" ] || { echo ")
        append(("fakeip-kpm: helper missing at " + HelperPath).shellQuote())
        append("; exit 0; }")
    }

    private fun writeConfig(
        enabled: Boolean,
        mark: String,
        scope: KpmDnsListScope,
        uids: List<Int>,
    ): String = buildString {
        appendLine("mkdir -p " + ConfigDirectory.shellQuote())
        appendLine("temporary=" + ConfigPath.shellQuote() + ".tmp.\$\$")
        appendLine(
            "printf '%s' " + encode(enabled, mark, scope, uids).shellQuote() +
                " > \"\$temporary\""
        )
        appendLine("mv -f \"\$temporary\" " + ConfigPath.shellQuote())
        appendLine("chmod 0644 " + ConfigPath.shellQuote())
    }

    // The file carries both the list and the half it is, because the two policies
    // name opposite halves and the module cannot tell them apart on its own: a list
    // read the wrong way round marks exactly the applications it should leave alone.
    private fun encode(
        enabled: Boolean,
        mark: String,
        scope: KpmDnsListScope,
        uids: List<Int>,
    ): String = buildString {
        appendLine("{")
        appendLine("  \"version\": 1,")
        appendLine("  \"generated_at\": \"" + java.time.Instant.now() + "\",")
        appendLine("  \"source\": \"AsteriskMETA\",")
        appendLine("  \"enabled\": " + enabled + ",")
        appendLine("  \"mark\": \"" + mark + "\",")
        appendLine("  \"ports\": [" + Ports.joinToString(", ") + "],")
        appendLine("  \"scope\": \"" + scope.wireValue + "\",")
        appendLine("  \"apps\": [")
        val sorted = uids.distinct().sorted()
        sorted.forEachIndexed { index, uid ->
            val suffix = if (index == sorted.size - 1) "" else ","
            appendLine("    { \"uid\": " + uid + " }" + suffix)
        }
        appendLine("  ],")
        appendLine("  \"notes\": \"written by AsteriskMETA; scope names the half apps is\"")
        append("}")
    }
}

// The module reads two things: a list, and which half of the applications that list
// is. The daemon's two policies name opposite halves, so the scope has to follow the
// policy -- this is the only place where the direction is decided:
//
//   a whitelist names the applications the proxy serves, and the module marks the
//   ones outside it (deny);
//   a blacklist names the applications the proxy leaves alone, and the module marks
//   exactly those (allow).
//
// The module implements both (g_scope_deny in kpm/src/fakeip_dns.c). Hard-coding
// deny here turned a blacklist inside out: the applications the proxy served were
// taken out of the interception and lost their fake answers, while the ones it left
// alone were intercepted instead. The more accurate the list, the more inverted the
// result. Measured on the device -- see kpm/docs/04.
internal enum class KpmDnsListScope(val wireValue: String) {
    MarksAppsOutsideList("deny"),
    MarksAppsInsideList("allow"),
}

// A retired configuration carries no list, so the scope here is a placeholder: the
// helper reads enabled=0, removes the rules, clears the list and switches the module
// off, whichever half the list would have been.
private val ScopeOfRetiredConfig = KpmDnsListScope.MarksAppsOutsideList
