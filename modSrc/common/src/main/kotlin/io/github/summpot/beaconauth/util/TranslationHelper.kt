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
    private const val MIGRATION_PREFIX = "migration.beaconauth."

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

    // Migration prompts and command feedback
    fun migrationPromptRegister() = Component.translatable("${MIGRATION_PREFIX}prompt_register")
    fun migrationPromptClaimAvailable(legacyName: String) =
        Component.translatable("${MIGRATION_PREFIX}prompt_claim_available", legacyName)
    fun migrationPromptClaimAccept(legacyName: String) =
        Component.translatable("${MIGRATION_PREFIX}prompt_claim_accept", legacyName)
    fun migrationClaimAccepted(legacyName: String) =
        Component.translatable("${MIGRATION_PREFIX}claim_accepted", legacyName)
    fun migrationClaimNoPending() = Component.translatable("${MIGRATION_PREFIX}claim_no_pending")
    fun migrationClaimFailed(reason: String) =
        Component.translatable("${MIGRATION_PREFIX}claim_failed", reason)
    fun migrationAutoClaimed(legacyName: String) =
        Component.translatable("${MIGRATION_PREFIX}auto_claimed", legacyName)
    fun migrationAutoClaimedPremium(legacyName: String) =
        Component.translatable("${MIGRATION_PREFIX}auto_claimed_premium", legacyName)
    fun migrationReclaimBlocked() = Component.translatable("${MIGRATION_PREFIX}reclaim_blocked")
    fun migrationStatusHeader() = Component.translatable("${MIGRATION_PREFIX}status_header")
    fun migrationStatusEntry(name: String, fromUuid: String, toUuid: String, actor: String) =
        Component.translatable("${MIGRATION_PREFIX}status_entry", name, fromUuid, toUuid, actor)
    fun migrationStatusNotFound(query: String) =
        Component.translatable("${MIGRATION_PREFIX}status_not_found", query)
    fun migrationAdminClaimed(legacyName: String, targetName: String) =
        Component.translatable("${MIGRATION_PREFIX}admin_claimed", legacyName, targetName)
    fun migrationAdminClaimSkipped(reason: String) =
        Component.translatable("${MIGRATION_PREFIX}admin_claim_skipped", reason)
    fun migrationUndoSuccess(claimId: String) =
        Component.translatable("${MIGRATION_PREFIX}undo_success", claimId)
    fun migrationUndoFailed(claimId: String) =
        Component.translatable("${MIGRATION_PREFIX}undo_failed", claimId)
    fun migrationListEmpty() = Component.translatable("${MIGRATION_PREFIX}list_empty")
    fun migrationListItem(id: String, name: String, fromUuid: String, toUuid: String) =
        Component.translatable("${MIGRATION_PREFIX}list_item", id, name, fromUuid, toUuid)
    fun migrationRequiresPermission() =
        Component.translatable("${COMMAND_PREFIX}migration_requires_permission")
    fun migrationInvalidUuid(value: String) =
        Component.translatable("${COMMAND_PREFIX}migration_invalid_uuid", value)
    fun migrationPlayerOnly() =
        Component.translatable("${COMMAND_PREFIX}migration_player_only")
}
