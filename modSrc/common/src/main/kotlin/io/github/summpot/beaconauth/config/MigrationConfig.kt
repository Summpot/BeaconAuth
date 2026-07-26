package io.github.summpot.beaconauth.config

import java.time.Instant
import java.time.format.DateTimeParseException

object MigrationConfig {
    enum class PromptMode { OFF, SOFT, FORCE_AFTER_DATE }
    enum class ClaimMode { OFF, AUTO, CONFIRM }
    enum class ClaimNameSource { BEACON_USERNAME, LAUNCHER_USERNAME, EITHER }

    @Volatile private var enabled: Boolean = false
    @Volatile private var promptMode: PromptMode = PromptMode.OFF
    @Volatile private var promptOnJoin: Boolean = true
    @Volatile private var promptIntervalMinutes: Int = 30
    @Volatile private var forceAuthAfter: String = ""
    @Volatile private var playerdataClaim: ClaimMode = ClaimMode.OFF
    @Volatile private var claimNameSource: ClaimNameSource = ClaimNameSource.BEACON_USERNAME
    @Volatile private var onlyIfTargetEmpty: Boolean = true
    @Volatile private var keepLegacyBackup: Boolean = true
    @Volatile private var dryRun: Boolean = false
    @Volatile private var autoForPremium: Boolean = false

    @Volatile private var forceAuthAfterInstant: Instant? = null

    @JvmStatic
    fun apply() {
        // No-op default apply for backwards compatibility; platform configs should call
        // the full apply(...) overload instead. Keeps defaults safe (migration off).
    }

    @JvmStatic
    fun apply(
        enabled: Boolean,
        promptMode: String,
        promptOnJoin: Boolean,
        promptIntervalMinutes: Int,
        forceAuthAfter: String,
        playerdataClaim: String,
        claimNameSource: String,
        onlyIfTargetEmpty: Boolean,
        keepLegacyBackup: Boolean,
        dryRun: Boolean,
        autoForPremium: Boolean
    ) {
        this.enabled = enabled
        this.promptMode = parsePromptMode(promptMode)
        this.promptOnJoin = promptOnJoin
        this.promptIntervalMinutes = promptIntervalMinutes.coerceAtLeast(1)
        this.forceAuthAfter = forceAuthAfter.trim()
        this.forceAuthAfterInstant = parseInstant(this.forceAuthAfter)
        this.playerdataClaim = parseClaimMode(playerdataClaim)
        this.claimNameSource = parseClaimNameSource(claimNameSource)
        this.onlyIfTargetEmpty = onlyIfTargetEmpty
        this.keepLegacyBackup = keepLegacyBackup
        this.dryRun = dryRun
        this.autoForPremium = autoForPremium
    }

    fun isEnabled(): Boolean = enabled
    fun getPromptMode(): PromptMode = promptMode
    fun shouldPromptOnJoin(): Boolean = promptOnJoin
    fun getPromptIntervalMinutes(): Int = promptIntervalMinutes
    fun getForceAuthAfter(): Instant? = forceAuthAfterInstant
    fun getPlayerdataClaim(): ClaimMode = playerdataClaim
    fun getClaimNameSource(): ClaimNameSource = claimNameSource
    fun shouldOnlyIfTargetEmpty(): Boolean = onlyIfTargetEmpty
    fun shouldKeepLegacyBackup(): Boolean = keepLegacyBackup
    fun isDryRun(): Boolean = dryRun
    fun shouldAutoForPremium(): Boolean = autoForPremium

    fun shouldClaim(): Boolean = enabled && playerdataClaim != ClaimMode.OFF

    fun isForceAuthDue(): Boolean {
        val instant = forceAuthAfterInstant ?: return false
        return Instant.now().isAfter(instant)
    }

    private fun parsePromptMode(raw: String): PromptMode = when (raw.trim().lowercase()) {
        "soft" -> PromptMode.SOFT
        "force_after_date" -> PromptMode.FORCE_AFTER_DATE
        "off", "" -> PromptMode.OFF
        else -> PromptMode.OFF
    }

    private fun parseClaimMode(raw: String): ClaimMode = when (raw.trim().lowercase()) {
        "auto" -> ClaimMode.AUTO
        "confirm" -> ClaimMode.CONFIRM
        "off", "" -> ClaimMode.OFF
        else -> ClaimMode.OFF
    }

    private fun parseClaimNameSource(raw: String): ClaimNameSource = when (raw.trim().lowercase()) {
        "launcher_username" -> ClaimNameSource.LAUNCHER_USERNAME
        "either" -> ClaimNameSource.EITHER
        "beacon_username", "" -> ClaimNameSource.BEACON_USERNAME
        else -> ClaimNameSource.BEACON_USERNAME
    }

    private fun parseInstant(raw: String): Instant? = if (raw.isEmpty()) null else try {
        Instant.parse(raw)
    } catch (e: DateTimeParseException) {
        null
    }
}