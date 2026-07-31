package io.github.summpot.beaconauth.command

import com.mojang.brigadier.CommandDispatcher
import com.mojang.brigadier.arguments.StringArgumentType
import com.mojang.brigadier.context.CommandContext
import io.github.summpot.beaconauth.server.IdentityMapping
import io.github.summpot.beaconauth.util.TranslationHelper
import net.minecraft.commands.CommandSourceStack
import net.minecraft.commands.Commands
import net.minecraft.commands.arguments.GameProfileArgument
import net.minecraft.network.chat.Component
import java.util.function.Supplier

/**
 * BeaconAuth commands for both client and server
 */
object AuthCommand {
    /**
     * Register client-side command
     * This runs on the logical client and triggers the local Ktor server
     */
    fun registerClient(dispatcher: CommandDispatcher<CommandSourceStack>) {
        dispatcher.register(
            Commands.literal("beaconauth")
                .then(
                    Commands.literal("login")
                        .executes { context -> executeClientLogin(context) }
                )
        )
    }

    /**
     * Register server-side command
     * This runs on the logical server and sends the RequestClientLogin packet
     */
    fun registerServer(dispatcher: CommandDispatcher<CommandSourceStack>) {
        dispatcher.register(
            Commands.literal("beaconauth")
                .then(
                    Commands.literal("login")
                        .executes { context -> executeServerLogin(context) }
                )
                .then(
                    Commands.literal("transfer-identity")
                        .requires { source -> source.hasPermission(2) }
                        .then(
                            Commands.argument("profile", GameProfileArgument.gameProfile())
                                .then(
                                    Commands.argument("beaconUsername", StringArgumentType.string())
                                        .executes { context -> executeTransferIdentity(context) }
                                )
                        )
                )
        )
    }

    private fun executeClientLogin(context: CommandContext<CommandSourceStack>): Int {
        sendSuccess(context.source, TranslationHelper.autoLogin(), false)
        return 1
    }

    private fun executeServerLogin(context: CommandContext<CommandSourceStack>): Int {
        sendSuccess(context.source, TranslationHelper.autoLogin(), false)
        return 1
    }

    /**
     * Transfers the legacy offline identity of [profile] to the BeaconAuth account whose username
     * is [beaconUsername], then rebinds it to that account on its next login.
     */
    private fun executeTransferIdentity(context: CommandContext<CommandSourceStack>): Int {
        val profileName = try {
            GameProfileArgument.getGameProfiles(context, "profile").first().name
        } catch (e: Exception) {
            sendFailure(context.source, TranslationHelper.legacyTransferInvalid())
            return 1
        }
        val beaconUsername = StringArgumentType.getString(context, "beaconUsername")
        val offlineUuid = IdentityMapping.offlineUuidFor(profileName)
        val transferred = IdentityMapping.transferToUsername(offlineUuid, beaconUsername)
        if (transferred) {
            sendSuccess(
                context.source,
                TranslationHelper.legacyTransferDone(profileName, beaconUsername),
                true
            )
        } else {
            sendFailure(context.source, TranslationHelper.legacyTransferNotFound(profileName))
        }
        return 1
    }

    private fun sendSuccess(source: CommandSourceStack, message: Component, broadcastToOps: Boolean) {
        val method = CommandSourceStack::class.java.methods.firstOrNull {
            it.name == "sendSuccess" &&
                it.parameterTypes.size == 2 &&
                it.parameterTypes[0] == Supplier::class.java
        }

        if (method != null) {
            method.invoke(source, Supplier { message }, broadcastToOps)
        } else {
            CommandSourceStack::class.java.getMethod(
                "sendSuccess",
                Component::class.java,
                Boolean::class.javaPrimitiveType
            ).invoke(source, message, broadcastToOps)
        }
    }

    private fun sendFailure(source: CommandSourceStack, message: Component) {
        val method = CommandSourceStack::class.java.methods.firstOrNull {
            it.name == "sendFailure" &&
                it.parameterTypes.size == 1 &&
                it.parameterTypes[0] == Component::class.java
        }
        if (method != null) {
            method.invoke(source, message)
        } else {
            source.sendSystemMessage(message)
        }
    }
}
