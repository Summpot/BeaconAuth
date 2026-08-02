package io.github.summpot.beaconauth.util

import net.minecraft.network.chat.Component

/**
 * Translation helper for BeaconAuth
 */
object TranslationHelper {
    private const val PREFIX = "chat.beaconauth."
    private const val COMMAND_PREFIX = "command.beaconauth."
    private const val HTML_PREFIX = "html.beaconauth."
    private const val SERVER_PREFIX = "server.beaconauth."

    // Chat messages
    fun welcome() = Component.translatable("$PREFIX${"welcome"}")
    fun welcomeTitle() = Component.translatable("$PREFIX${"welcome_title"}")
    fun loginPrompt() = Component.translatable("$PREFIX${"login_prompt"}")
    fun divider() = Component.translatable("$PREFIX${"divider"}")
    fun authenticated() = Component.translatable("$PREFIX${"authenticated"}")
    fun loginClick() = Component.translatable("$PREFIX${"login_click"}")
    fun loginUrl(url: String) = Component.translatable("$PREFIX${"login_url"}", url)
    fun success(message: String) = Component.translatable("$PREFIX${"success"}", message)
    fun failed(message: String) = Component.translatable("$PREFIX${"failed"}", message)
    fun serverNotReady() = Component.translatable("$PREFIX${"server_not_ready"}")
    fun generatingUrl() = Component.translatable("$PREFIX${"generating_url"}")
    fun autoLogin() = Component.translatable("$PREFIX${"auto_login"}")
    fun loginCancelled() = Component.translatable("$PREFIX${"login_cancelled"}")

    // Command messages
    fun mustBePlayer() = Component.translatable("${COMMAND_PREFIX}must_be_player")
    fun loginFailed(error: String) = Component.translatable("${COMMAND_PREFIX}login_failed", error)
    fun loginRequestSent() = Component.translatable("${COMMAND_PREFIX}login_request_sent")
    fun legacyTransferInvalid() = Component.translatable("${COMMAND_PREFIX}legacy_transfer_invalid")
    fun legacyTransferDone(name: String, beaconUsername: String) =
        Component.translatable("${COMMAND_PREFIX}legacy_transfer_done", name, beaconUsername)
    fun legacyTransferNotFound(name: String) =
        Component.translatable("${COMMAND_PREFIX}legacy_transfer_not_found", name)
    fun unmigratedScanNone() = Component.translatable("${COMMAND_PREFIX}unmigrated_none")
    fun unmigratedScanHeader(count: Int) = Component.translatable("${COMMAND_PREFIX}unmigrated_header", count)
    fun unmigratedScanEntry(name: String, uuid: String) =
        Component.translatable("${COMMAND_PREFIX}unmigrated_entry", name, uuid)
    fun unmigratedScanEntryUnknown(uuid: String) =
        Component.translatable("${COMMAND_PREFIX}unmigrated_entry_unknown", uuid)
    fun unmigratedScanHint() = Component.translatable("${COMMAND_PREFIX}unmigrated_hint")
    fun unmigratedScanLegacyDisabled() = Component.translatable("${COMMAND_PREFIX}unmigrated_legacy_disabled")
    fun unmigratedScanError(error: String) = Component.translatable("${COMMAND_PREFIX}unmigrated_error", error)

    // HTML translations (for client-side use, returns translation key)
    fun htmlSuccessTitle() = "${HTML_PREFIX}success.title"
    fun htmlSuccessHeading() = "${HTML_PREFIX}success.heading"
    fun htmlSuccessMessage() = "${HTML_PREFIX}success.message"
    fun htmlErrorTitle() = "${HTML_PREFIX}error.title"
    fun htmlErrorHeading() = "${HTML_PREFIX}error.heading"

    // Server log messages (returns raw translation key for manual formatting)
    fun serverPlayerJoined() = "${SERVER_PREFIX}player_joined"
    fun serverNotAuthenticated() = "${SERVER_PREFIX}not_authenticated"
    fun serverAlreadyAuthenticated() = "${SERVER_PREFIX}already_authenticated"
    fun serverAuthSuccessful() = "${SERVER_PREFIX}auth_successful"
    fun serverAuthFailed() = "${SERVER_PREFIX}auth_failed"
}
