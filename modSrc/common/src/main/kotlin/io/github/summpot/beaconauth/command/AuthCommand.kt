package io.github.summpot.beaconauth.command

import com.mojang.brigadier.CommandDispatcher
import com.mojang.brigadier.context.CommandContext
import io.github.summpot.beaconauth.util.TranslationHelper
import net.minecraft.commands.CommandSourceStack
import net.minecraft.commands.Commands
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
}
