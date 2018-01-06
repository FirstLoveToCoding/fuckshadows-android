#!/usr/bin/env bash

LOC=/opt/android-sdk/platform-tools

sudo $LOC/adb kill-server
sudo $LOC/adb start-server
$LOC/adb wait-for-device
$LOC/adb install -r $(pwd)/mobile/build/outputs/apk/release/mobile-universal-release.apk

