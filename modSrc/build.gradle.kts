import org.gradle.jvm.JvmLibrary
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters
import org.gradle.language.base.artifact.SourcesArtifact
import org.gradle.api.file.DuplicatesStrategy
import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import java.net.URI
import java.nio.file.FileSystems
import java.nio.file.Files
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.readLines
import kotlin.io.path.writeLines

plugins {
    id("dev.architectury.loom") version "1.17-SNAPSHOT" apply false
    id("architectury-plugin") version "3.5-SNAPSHOT"
    id("com.gradleup.shadow") version "9.6.1" apply false
    kotlin("jvm") version "2.2.21" apply false
}

/**
 * Shadow 9 injects Multi-Release: true from deps like nimbus-jose-jwt, but drops
 * META-INF/versions (module-info). Forge SecureJar then crashes looking for /META-INF/versions.
 * Edit only the manifest attribute in-place; class files are left untouched.
 */
fun stripOrphanMultiReleaseAttribute(jarFile: java.io.File) {
    FileSystems.newFileSystem(URI.create("jar:${jarFile.toURI()}"), emptyMap<String, Any>()).use { fs ->
        val versions = fs.getPath("META-INF/versions")
        if (versions.exists() && versions.isDirectory()) return

        val manifest = fs.getPath("META-INF/MANIFEST.MF")
        if (!manifest.exists()) return

        val lines = manifest.readLines()
        if (lines.none { it.startsWith("Multi-Release:", ignoreCase = true) }) return

        manifest.writeLines(lines.filterNot { it.startsWith("Multi-Release:", ignoreCase = true) })
    }
}

/**
 * Architectury's TransformingTask writes transformer settings (including
 * architectury.srg.mappings) into JVM system properties for the duration of the task.
 * In a multi-Minecraft-version workspace those tasks must not run concurrently, or one
 * version can observe another version's mapping path (e.g. common-1.19.2 reading 1.21.1
 * mappings-srg.tiny and failing with NoSuchFileException).
 *
 * Two layers of serialization:
 * 1) BuildService maxParallelUsages=1 (resource lock while a transform runs)
 * 2) mustRunAfter chain after project evaluation (stable total order in the task graph)
 */
abstract class ArchitecturyTransformMutex : BuildService<BuildServiceParameters.None>

val architecturyTransformMutex = gradle.sharedServices.registerIfAbsent(
    "architecturyTransformMutex",
    ArchitecturyTransformMutex::class.java,
) {
    maxParallelUsages.set(1)
}

allprojects {
    group = project.property("maven_group").toString()
    version = project.property("mod_version").toString()
}

gradle.projectsEvaluated {
    // Use task names only — iterating TaskCollection.matching realizes every task,
    // and Loom 1.17's GenerateSourcesTask resolves configurations in its constructor.
    val transformTasks = subprojects
        .flatMap { subproject ->
            subproject.tasks.names
                .filter { it.startsWith("transformProduction") }
                .map { taskName ->
                    "${subproject.path}:$taskName" to subproject.tasks.named(taskName)
                }
        }
        .sortedBy { it.first }
        .map { it.second }

    for (index in 1 until transformTasks.size) {
        transformTasks[index].configure {
            mustRunAfter(transformTasks[index - 1])
        }
    }
}

subprojects {
    apply(plugin = "dev.architectury.loom")
    apply(plugin = "architectury-plugin")
    apply(plugin = "maven-publish")
    apply(plugin = "org.jetbrains.kotlin.jvm")

    // Serialize Architectury production transforms across all versioned subprojects.
    tasks.configureEach {
        if (name.startsWith("transformProduction")) {
            usesService(architecturyTransformMutex)
        }
    }

    extensions.configure<BasePluginExtension> {
        archivesName.set("${rootProject.property("archives_name")}-${project.name}")
    }

    repositories {
        mavenCentral()
        maven {
            name = "NeoForged"
            url = uri("https://maven.neoforged.net/releases")
        }
        maven {
            name = "Fuzs Mod Resources"
            url = uri("https://raw.githubusercontent.com/Fuzss/modresources/main/maven/")
        }
    }

    configure<net.fabricmc.loom.api.LoomGradleExtensionAPI> {
        silentMojangMappingsLicense()
    }

    configure<JavaPluginExtension> {
        withSourcesJar()
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    tasks.withType<JavaCompile> {
        options.release.set(21)
    }

    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        }
    }

    // Some shared source sets intentionally overlap between versioned modules.
    // Ensure jars (especially sourcesJar) remain buildable even if the same source file
    // is contributed from multiple roots.
    tasks.withType<Jar>().configureEach {
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    }

    // Applied when a platform module enables the Shadow plugin.
    pluginManager.withPlugin("com.gradleup.shadow") {
        tasks.withType<ShadowJar>().configureEach {
            // Drop JPMS multi-release payloads from shaded deps (nimbus-jose-jwt, etc.).
            exclude("META-INF/versions/**")
            exclude("module-info.class")
            exclude("META-INF/**/module-info.class")

            doLast {
                stripOrphanMultiReleaseAttribute(archiveFile.get().asFile)
            }
        }
    }

    // Architectury Transformer sometimes attempts to write debug logs into
    // <project>/.gradle/.architectury-transformer/ without ensuring the directory exists.
    // This can fail on Windows with FileNotFoundException.
    project.file(".gradle/.architectury-transformer").mkdirs()

    // Development helper only. Must not realize Loom's genSources* tasks during
    // configuration: Gradle 9 + Loom 1.17 resolve mappings while constructing
    // GenerateSourcesTask, which requires an exclusive lock.
    tasks.register<Copy>("unpackSources") {
        group = "development"
        description = "Unpacks the sources generated by the decompiler task."
        into(layout.buildDirectory.dir("minecraft-sources"))
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
        enabled = false
    }

    afterEvaluate {
        val decompileTaskName = tasks.names
            .firstOrNull { it.startsWith("genSourcesWith") }
            ?: tasks.names.firstOrNull { it == "genSources" }
            ?: return@afterEvaluate

        val decompile = tasks.named(decompileTaskName)
        tasks.named<Copy>("unpackSources").configure {
            enabled = true
            dependsOn(decompile)
            inputs.files(decompile.map { it.outputs.files })
            from(decompile.map { task ->
                task.outputs.files
                    .filter { it.name.endsWith(".jar") }
                    .map { zipTree(it) }
            }) {
                exclude("META-INF/**", "assets/**", "data/**", "*.json", "*.png", "*.class")
            }
            doFirst {
                val files = decompile.get().outputs.files.files
                println(">>> [unpackSources] Found source files in task '${decompileTaskName}':")
                files.forEach { println("    - ${it.absolutePath}") }
                if (files.isEmpty()) {
                    println(">>> [WARNING] No output files found for task '${decompileTaskName}'!")
                }
            }
        }
    }

    configure<PublishingExtension> {
        publications {
            create<MavenPublication>("mavenJava") {
                artifactId = extensions.getByType<BasePluginExtension>().archivesName.get()
                from(components["java"])
            }
        }
    }
}