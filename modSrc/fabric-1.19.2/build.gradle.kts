plugins {
    id("com.gradleup.shadow")
}

val minecraftVersion = "1.19.2"
val architecturyVersion = "6.6.92"
val fabricLoaderVersion = "0.18.0"
val fabricApiVersion = "0.77.0+1.19.2"
val forgeConfigApiPortVersion = "5.0.11"
val nimbusJwtVersion = "10.6"

architectury {
    minecraft = minecraftVersion
    platformSetupLoomIde()
    fabric()
}

loom {
    runs {
        named("server") {
            property("online-mode", "false")
        }
    }
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
    named("developmentFabric") {
        extendsFrom(common)
    }
}

dependencies {
    "minecraft"("net.minecraft:minecraft:$minecraftVersion")
    "mappings"(project.extensions.getByType<net.fabricmc.loom.api.LoomGradleExtensionAPI>().officialMojangMappings())

    modImplementation("net.fabricmc:fabric-loader:$fabricLoaderVersion")

    modImplementation("net.fabricmc.fabric-api:fabric-api:$fabricApiVersion")
    
    modImplementation("net.fabricmc:fabric-language-kotlin:1.13.7+kotlin.2.2.21")

    modImplementation("dev.architectury:architectury-fabric:$architecturyVersion")

    common(project(path = ":common-1.19.2", configuration = "namedElements")) {
        isTransitive = false
    }
    shadowBundle(project(path = ":common-1.19.2", configuration = "transformProductionFabric"))

    modApi("fuzs.forgeconfigapiport:forgeconfigapiport-fabric:$forgeConfigApiPortVersion")

    implementation("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")

    include("fuzs.forgeconfigapiport:forgeconfigapiport-fabric:$forgeConfigApiPortVersion")
    include("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")
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

tasks.processResources {
    inputs.property("version", project.version)

    filesMatching("fabric.mod.json") {
        expand("version" to project.version)
    }
}

tasks.shadowJar {
    from(sourceSets.main.get().output)
    configurations = listOf(shadowBundle)
    archiveClassifier.set("dev-shadow")
}

tasks.remapJar {
    inputFile.set(tasks.shadowJar.get().archiveFile)
}
