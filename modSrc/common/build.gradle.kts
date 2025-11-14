architectury {
    common(rootProject.property("enabled_platforms").toString().split(","))
}

dependencies {
    modImplementation("net.fabricmc:fabric-loader:${rootProject.property("fabric_loader_version")}")

    modImplementation("dev.architectury:architectury:${rootProject.property("architectury_api_version")}")

    // Nimbus JOSE JWT library for JWT validation
    modImplementation("com.nimbusds:nimbus-jose-jwt:9.37.3")
    modImplementation("com.github.stephenc.jcip:jcip-annotations:1.0-1")

    modApi("fuzs.forgeconfigapiport:forgeconfigapiport-common:8.0.2")
    
    implementation("com.google.guava:guava:33.5.0-jre")

    compileOnly("org.slf4j:slf4j-api:2.0.16")
}
