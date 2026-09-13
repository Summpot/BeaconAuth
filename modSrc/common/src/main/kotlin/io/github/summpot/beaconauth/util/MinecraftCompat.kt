package io.github.summpot.beaconauth.util

import net.minecraft.client.Minecraft
import net.minecraft.client.gui.screens.Screen
import net.minecraft.commands.CommandSourceStack
import net.minecraft.server.MinecraftServer
import java.lang.reflect.Modifier
import java.net.URI

/**
 * Cross-version accessors for Minecraft client/server APIs that changed between 1.21.x and 26.2.
 */
object MinecraftCompat {
    fun currentScreen(minecraft: Minecraft): Screen? {
        invokeNoArg(minecraft, "getScreen")?.let { return it as? Screen }
        readField(minecraft, "screen")?.let { return it as? Screen }
        val gui = readField(minecraft, "gui") ?: invokeNoArg(minecraft, "getGui") ?: return null
        invokeNoArg(gui, "screen")?.let { return it as? Screen }
        invokeNoArg(gui, "getScreen")?.let { return it as? Screen }
        return readField(gui, "screen") as? Screen
    }

    fun setScreen(minecraft: Minecraft, screen: Screen?) {
        if (invokeMaybe("setScreen", minecraft, screen) || invokeMaybe("setScreenAndShow", minecraft, screen)) {
            return
        }
        val gui = readField(minecraft, "gui") ?: invokeNoArg(minecraft, "getGui") ?: return
        invokeMaybe("setScreen", gui, screen)
    }

    fun openUri(uri: String) {
        try {
            val util = Class.forName("net.minecraft.Util")
            val platform = util.getMethod("getPlatform").invoke(null)
            val open = platform.javaClass.methods.firstOrNull { method ->
                method.name == "openUri" && method.parameterCount == 1
            }
            if (open != null) {
                val argType = open.parameterTypes[0]
                val argument: Any = if (argType == URI::class.java) URI(uri) else uri
                open.invoke(platform, argument)
                return
            }
        } catch (_: Throwable) {
        }
        java.awt.Desktop.getDesktop().browse(URI(uri))
    }

    fun glfwWindowHandle(minecraft: Minecraft): Long {
        val window = nativeWindow(minecraft)
        invokeNoArg(window, "handle")?.let { return (it as Number).toLong() }
        invokeNoArg(window, "getWindow")?.let { return (it as Number).toLong() }
        readField(window, "window")?.let { return (it as Number).toLong() }
        throw IllegalStateException("Unable to read GLFW window handle")
    }

    fun isFullscreen(minecraft: Minecraft): Boolean {
        val window = nativeWindow(minecraft)
        invokeNoArg(window, "isFullscreen")?.let { return it as Boolean }
        return readField(window, "fullscreen") as? Boolean ?: false
    }

    fun toggleFullScreen(minecraft: Minecraft) {
        invokeNoArg(nativeWindow(minecraft), "toggleFullScreen")
    }

    fun hasPermissionLevel(source: CommandSourceStack, level: Int): Boolean {
        val hasPermission = source.javaClass.methods.firstOrNull { method ->
            method.name == "hasPermission" &&
                method.parameterCount == 1 &&
                (method.parameterTypes[0] == Int::class.javaPrimitiveType || method.parameterTypes[0] == Integer::class.java)
        }
        if (hasPermission != null) {
            return hasPermission.invoke(source, level) as Boolean
        }

        val permissions = invokeNoArg(source, "permissions") ?: return false
        val permissionLevel = invokeNoArg(permissions, "level") ?: return false
        val id = invokeNoArg(permissionLevel, "id") as? Int ?: return false
        return id >= level
    }

    fun nameToIdCache(server: MinecraftServer): Any? {
        invokeNoArg(server, "getProfileCache")?.let { return it }
        readField(server, "profileCache")?.let { return it }
        val services = invokeNoArg(server, "services") ?: return null
        return invokeNoArg(services, "nameToIdCache")
    }

    fun profileRepository(server: MinecraftServer): Any? {
        invokeNoArg(server, "getProfileRepository")?.let { return it }
        readField(server, "profileRepository")?.let { return it }
        val services = invokeNoArg(server, "services") ?: return null
        invokeNoArg(services, "profileResolver")?.let { return it }
        return invokeNoArg(services, "profileRepository")
    }

    private fun nativeWindow(minecraft: Minecraft): Any {
        invokeNoArg(minecraft, "getWindow")?.let { return it }
        readField(minecraft, "window")?.let { return it }
        throw IllegalStateException("Unable to resolve Minecraft window")
    }

    private fun invokeNoArg(target: Any, name: String): Any? {
        val method = target.javaClass.methods.firstOrNull { it.name == name && it.parameterCount == 0 } ?: return null
        return method.invoke(target)
    }

    private fun invokeMaybe(name: String, target: Any, argument: Any?): Boolean {
        val method = target.javaClass.methods.firstOrNull { candidate ->
            candidate.name == name && candidate.parameterCount == 1
        } ?: return false
        method.invoke(target, argument)
        return true
    }

    private fun readField(target: Any, name: String): Any? {
        var type: Class<*>? = target.javaClass
        while (type != null && type != Any::class.java) {
            try {
                val field = type.getDeclaredField(name)
                if (!Modifier.isStatic(field.modifiers)) {
                    field.isAccessible = true
                    return field.get(target)
                }
            } catch (_: NoSuchFieldException) {
            }
            type = type.superclass
        }
        return null
    }

    fun createOpenUrlClickEvent(url: String): net.minecraft.network.chat.ClickEvent? {
        try {
            val actionClass = Class.forName("net.minecraft.network.chat.ClickEvent\$Action")
            val openUrlAction = java.lang.Enum.valueOf(actionClass.asSubclass(Enum::class.java), "OPEN_URL")
            val clickEventClass = net.minecraft.network.chat.ClickEvent::class.java
            val constructor = clickEventClass.getConstructor(actionClass, String::class.java)
            return constructor.newInstance(openUrlAction, url)
        } catch (_: Throwable) {
            try {
                val openUrlClass = Class.forName("net.minecraft.network.chat.ClickEvent\$OpenUrl")
                val constructor = openUrlClass.getConstructor(URI::class.java)
                return constructor.newInstance(URI.create(url)) as net.minecraft.network.chat.ClickEvent
            } catch (_: Throwable) {
                return null
            }
        }
    }
}
