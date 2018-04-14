#!/bin/sh

export PATH=/home/prog/android/ndk/android-ndk-r16b:$PATH
export NDK_PROJECT_PATH=.
APP_ABI=armeabi-v7a #собирать только для 32-х битного арма а не для вообще всех возможных
BUILD_ARGS="APP_BUILD_SCRIPT=Android.mk APP_PLATFORM=android-25 APP_ABI=$APP_ABI"
#ndk-build clean $BUILD_ARGS
ndk-build $BUILD_ARGS

[ "${1}" = "nc" ] || exit 0
[ -x ./libs/armeabi-v7a/mstp_rules_wd ] && {
	echo "Running nc"
	cat ./libs/armeabi-v7a/mstp_rules_wd | nc -l -p 1111 -q 1
}
