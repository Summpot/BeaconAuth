plugins {
    id("com.gradleup.shadow")
}

val minecraftVersion = "26.2"
val architecturyVersion = "21.1.9"
val fabricLoaderVersion = "0.19.5"
val fabricApiVersion = "0.160.0+26.2"
val forgeConfigApiPortVersion = "26.2.1"
val nimbusJwtVersion = "10.6"

architectury {
    minecraft = minecraftVersion
    platformSetupLoomIde()
    fabric()
}

loom {
    accessWidenerPath.set(project(":common-26.2").file("src/main/resources/beaconauth.accesswidener"))

    runs {
        named("server") {
            property("online-mode", "false")
        }
    }
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
    findByName("developmentFabric")?.extendsFrom(common)
}

dependencies {
    "minecraft"("com.mojang:minecraft:$minecraftVersion")

    implementation("net.fabricmc:fabric-loader:$fabricLoaderVersion")

    implementation("net.fabricmc.fabric-api:fabric-api:$fabricApiVersion")

    implementation("net.fabricmc:fabric-language-kotlin:1.13.7+kotlin.2.2.21")

    implementation("dev.architectury:architectury-fabric:$architecturyVersion")

    common(project(":common-26.2")) {
        isTransitive = false
    }
    shadowBundle(project(path = ":common-26.2", configuration = "transformProductionFabric"))

    api("fuzs.forgeconfigapiport:forgeconfigapiport-fabric:$forgeConfigApiPortVersion")

    implementation("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")

    "include"("fuzs.forgeconfigapiport:forgeconfigapiport-fabric:$forgeConfigApiPortVersion")
    "include"("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")
}

tasks.processResources {
    inputs.property("version", project.version)

    from(project(":common-26.2").file("src/main/resources/beaconauth.accesswidener"))

    filesMatching("fabric.mod.json") {
        expand("version" to project.version)
    }
}

// Minecraft 26.2 is unobfuscated, so there is no remapJar. Publish the shadowed jar.
tasks.named<Jar>("jar") {
    archiveClassifier.set("dev")
}

tasks.shadowJar {
    from(sourceSets.main.get().output)
    configurations = listOf(shadowBundle)
    archiveClassifier.set("")
    dependsOn(tasks.named("jar"))
    from(tasks.named("jar").map { zipTree(it.outputs.files.singleFile) }) {
        include("META-INF/jars/**")
    }
}

tasks.assemble {
    dependsOn(tasks.shadowJar)
}
