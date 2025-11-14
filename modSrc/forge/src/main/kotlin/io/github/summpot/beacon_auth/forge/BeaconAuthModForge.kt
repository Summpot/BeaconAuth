package io.github.summpot.beacon_auth.forge

import dev.architectury.platform.forge.EventBuses
import io.github.summpot.beacon_auth.BeaconAuthMod
import io.github.summpot.beacon_auth.config.BeaconAuthConfig
import net.minecraftforge.api.distmarker.Dist
import net.minecraftforge.fml.common.Mod
import net.minecraftforge.fml.loading.FMLEnvironment
import net.minecraftforge.fml.ModLoadingContext
import net.minecraftforge.fml.config.ModConfig
import thedarkcolour.kotlinforforge.forge.MOD_CONTEXT

@Mod(BeaconAuthMod.MOD_ID)
object BeaconAuthModForge {
    init {
        // Submit our event bus to let Architectury API register our content on the right time.
        EventBuses.registerModEventBus(BeaconAuthMod.MOD_ID, MOD_CONTEXT.getKEventBus())
        
        // Register configuration
        val configPair = BeaconAuthConfig.buildConfig()
        ModLoadingContext.get().registerConfig(ModConfig.Type.SERVER, configPair.right)

        // Run common setup (network packet registration)
        BeaconAuthMod.init()

        // Initialize client or server based on distribution
        when (FMLEnvironment.dist) {
            Dist.CLIENT -> BeaconAuthMod.initClient()
            Dist.DEDICATED_SERVER -> BeaconAuthMod.initServer()
        }
    }
}
