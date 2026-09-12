package io.github.summpot.beaconauth.login

import io.github.summpot.beaconauth.BeaconAuthMod
import net.minecraft.resources.Identifier

/**
 * Identifiers for BeaconAuth cookie request keys (26.2).
 */
enum class LoginQueryType(private val path: String) {
    PROBE("probe"),
    INIT("init"),
    LOGIN_URL("login_url"),
    VERIFY("verify");

    fun id(): Identifier = Identifier.fromNamespaceAndPath(BeaconAuthMod.MOD_ID, path)
}
