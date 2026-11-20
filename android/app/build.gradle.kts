plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Έκδοση από το tag του GitHub (v1.2.0 → 1.2.0), αλλιώς 1.0-dev
val tagVersion = (System.getenv("NETWATCH_VERSION") ?: "").removePrefix("v").ifBlank { "1.0-dev" }
val buildNumber = (System.getenv("GITHUB_RUN_NUMBER") ?: "1").toInt()

android {
    namespace = "io.github.netwatch.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.netwatch.android"
        minSdk = 29
        targetSdk = 35
        versionCode = buildNumber
        versionName = tagVersion
    }

    signingConfigs {
        // Υπογραφή release: από secrets του GitHub (NETWATCH_KEYSTORE_B64 κ.λπ.).
        // Χωρίς αυτά, το release υπογράφεται με το debug κλειδί (εγκαθίσταται κανονικά, αλλά
        // κάθε build από άλλο μηχάνημα έχει άλλο κλειδί → χρειάζεται απεγκατάσταση πριν την αναβάθμιση).
        create("release") {
            val ks = System.getenv("NETWATCH_KEYSTORE")
            if (ks != null && file(ks).exists()) {
                storeFile = file(ks)
                storePassword = System.getenv("NETWATCH_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("NETWATCH_KEY_ALIAS") ?: "netwatch"
                keyPassword = System.getenv("NETWATCH_KEY_PASSWORD") ?: System.getenv("NETWATCH_KEYSTORE_PASSWORD")
            } else {
                initWith(getByName("debug"))
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = true }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
