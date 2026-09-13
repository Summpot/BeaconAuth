val minecraftVersion = "26.2"
val architecturyVersion = "21.1.9"
val fabricLoaderVersion = "0.19.5"
val forgeConfigApiPortVersion = "26.2.1"
val nimbusJwtVersion = "10.6"

architectury {
    minecraft = minecraftVersion
    common(listOf("fabric", "neoforge"))
}

loom {
    accessWidenerPath.set(file("src/main/resources/beaconauth.accesswidener"))
}

configure<JavaPluginExtension> {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
    sourceCompatibility = JavaVersion.VERSION_25
    targetCompatibility = JavaVersion.VERSION_25
}

tasks.withType<JavaCompile> {
    options.release.set(25)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        // Kotlin 2.2.21 has no JVM_25 target; 21 bytecode is valid on the Java 25 runtime Minecraft 26.2 requires.
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile>().configureEach {
    jvmTargetValidationMode.set(org.jetbrains.kotlin.gradle.dsl.jvm.JvmTargetValidationMode.WARNING)
}

dependencies {
    "minecraft"("com.mojang:minecraft:$minecraftVersion")

    implementation("net.fabricmc:fabric-loader:$fabricLoaderVersion")

    implementation("dev.architectury:architectury:$architecturyVersion")

    implementation("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")

    api("fuzs.forgeconfigapiport:forgeconfigapiport-common:$forgeConfigApiPortVersion")

    compileOnly("org.slf4j:slf4j-api:2.0.16")
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
                rootProject.file("common/src/main/resources")
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
