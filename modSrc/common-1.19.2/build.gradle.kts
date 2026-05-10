val minecraftVersion = "1.19.2"
val architecturyVersion = "6.6.92"
val fabricLoaderVersion = "0.18.0"
val forgeConfigApiPortVersion = "5.0.11"
val nimbusJwtVersion = "10.6"

architectury {
    minecraft = minecraftVersion
    common(listOf("fabric", "forge"))
}

loom {
    accessWidenerPath.set(file("src/main/resources/beaconauth.accesswidener"))
}

dependencies {
    "minecraft"("net.minecraft:minecraft:$minecraftVersion")
    "mappings"(project.extensions.getByType<net.fabricmc.loom.api.LoomGradleExtensionAPI>().officialMojangMappings())

    modImplementation("net.fabricmc:fabric-loader:$fabricLoaderVersion")

    modImplementation("dev.architectury:architectury:$architecturyVersion")

    modImplementation("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")

    modApi("fuzs.forgeconfigapiport:forgeconfigapiport-common:$forgeConfigApiPortVersion")

    compileOnly("org.slf4j:slf4j-api:2.0.16")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile> {
    options.release.set(17)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// Reuse shared implementation from the unversioned common sources folder.
// Each Minecraft version still compiles these sources against its own mappings/dependencies.
sourceSets {
    named("main") {
        // IMPORTANT: setSrcDirs replaces the default src/main/** to avoid duplicate classes/resources.
        java.setSrcDirs(
            listOf(
                rootProject.file("common/src/main/java"),
                project.file("src/versioned/java")
            )
        )
        resources.setSrcDirs(
            listOf(
                project.file("src/main/resources")
            )
        )
    }
}

kotlin {
    sourceSets {
        named("main") {
            // IMPORTANT: setSrcDirs replaces the default src/main/** to avoid duplicate classes/resources.
            kotlin.setSrcDirs(
                listOf(
                    rootProject.file("common/src/main/kotlin"),
                    project.file("src/versioned/kotlin")
                )
            )
        }
    }
}
