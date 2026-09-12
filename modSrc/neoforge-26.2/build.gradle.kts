plugins {
    id("com.gradleup.shadow")
}

val minecraftVersion = "26.2"
val neoForgeVersion = "26.2.0.87"
val architecturyVersion = "21.1.9"
val nimbusJwtVersion = "10.6"

configure<net.fabricmc.loom.api.LoomGradleExtensionAPI> {
    accessWidenerPath.set(project(":common-26.2").file("src/main/resources/beaconauth.accesswidener"))

    runs {
        named("server") {
            property("online-mode", "false")
        }
    }
}

architectury {
    minecraft = minecraftVersion
    platformSetupLoomIde()
    neoForge()
}

configure<JavaPluginExtension> {
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

val common: Configuration by configurations.creating {
    isCanBeResolved = true
    isCanBeConsumed = false
}

val shadowBundle: Configuration by configurations.creating {
    isCanBeResolved = true
    isCanBeConsumed = false
}

configurations {
    compileClasspath.get().extendsFrom(common)
    runtimeClasspath.get().extendsFrom(common)
    findByName("developmentNeoForge")?.extendsFrom(common)
}

repositories {
    maven {
        name = "Kotlin for Forge"
        url = uri("https://thedarkcolour.github.io/KotlinForForge/")
    }
}

dependencies {
    "minecraft"("com.mojang:minecraft:$minecraftVersion")

    neoForge("net.neoforged:neoforge:$neoForgeVersion")

    implementation("dev.architectury:architectury-neoforge:$architecturyVersion")

    common(project(":common-26.2")) {
        isTransitive = false
    }
    shadowBundle(project(path = ":common-26.2", configuration = "transformProductionNeoForge"))

    // NeoForge does not ship with a Kotlin language provider by default.
    // Bundle Kotlin stdlib directly to keep this jar self-contained.
    implementation(kotlin("stdlib"))
    shadowBundle(kotlin("stdlib"))

    implementation("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")
    shadowBundle("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")
}

tasks.processResources {
    inputs.property("version", project.version)

    filesMatching(listOf("META-INF/neoforge.mods.toml", "META-INF/mods.toml")) {
        expand("version" to project.version)
    }
}

tasks.shadowJar {
    configurations = listOf(shadowBundle)
    archiveClassifier.set("")

    // Keep bundled Kotlin private so ModLauncher's module resolver does not
    // see BeaconAuth exporting kotlin.* alongside the real kotlin.stdlib module.
    relocate("kotlin", "io.github.summpot.beaconauth.shadow.kotlin")
    relocate("org.jetbrains.annotations", "io.github.summpot.beaconauth.shadow.org.jetbrains.annotations")
}

tasks.named<Jar>("jar") {
    archiveClassifier.set("dev")
}

tasks.assemble {
    dependsOn(tasks.shadowJar)
}
