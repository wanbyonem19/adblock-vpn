#!/bin/bash
# Build AdBlock VPN APK. Proven pipeline: aapt2 link -> javac --release 8 -> d8 -> zip dex -> zipalign -> apksigner.
set -e
cd "$(dirname "$0")"
BT="$HOME/android-sdk/build-tools/34.0.0"
JAR="$HOME/android-sdk/platforms/android-34/android.jar"

rm -rf gen classes dexout res.zip unsigned.apk aligned.apk
mkdir -p gen classes dexout

if [ ! -f app.keystore ]; then
  keytool -genkeypair -keystore app.keystore -alias app -keyalg RSA -keysize 2048 \
    -validity 10000 -storepass android -keypass android -dname "CN=AdBlock VPN" -noprompt
fi

"$BT/aapt2" compile --dir res -o res.zip
"$BT/aapt2" link -o unsigned.apk --manifest AndroidManifest.xml -I "$JAR" --java gen -A assets res.zip
javac --release 8 -parameters -cp "$JAR" -d classes $(find src gen -name "*.java")
# d8 rejects a bare directory input and NPEs on javac-21 classes without -parameters. Pass .class files explicitly.
"$BT/d8" --lib "$JAR" --output dexout $(find classes -name "*.class")
cd dexout && zip -q ../unsigned.apk classes.dex && cd ..
"$BT/zipalign" -f 4 unsigned.apk aligned.apk
"$BT/apksigner" sign --ks app.keystore --ks-pass pass:android --key-pass pass:android \
  --out adblock-vpn.apk aligned.apk
"$BT/apksigner" verify adblock-vpn.apk
echo "BUILD OK"
ls -la adblock-vpn.apk
