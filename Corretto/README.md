# Amazon Corretto 25 JDK (25.0.5.1.2+ / CVE-2026-114938 Patched)

Download **Amazon Corretto 25.0.5.1.2 or newer** (Windows x64 JDK — includes the **CVE-2026-114938 "Java4Shell"** security fix) from:
https://github.com/corretto/corretto-25/releases/latest

Either:
- Extract the portable JDK archive into this folder (e.g., `Corretto\jdk25.0.5_1\bin\java.exe`), **or**
- Install the `.msi` system-wide into `C:\Program Files\Amazon Corretto\`.

The scripts in `..\scripts\` automatically detect either location and pass `-XX:-UseBASE64Intrinsics` as defense in depth.
