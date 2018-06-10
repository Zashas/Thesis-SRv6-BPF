#!/bin/bash

export STAGING_DIR=/mnt/turris/openwrt-seg6/staging_dir/

/mnt/turris/openwrt-seg6/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi/bin/arm-openwrt-linux-muslgnueabi-gcc \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/target-arm_cortex-a9+vfpv3_musl_eabi/usr/include \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/target-arm_cortex-a9+vfpv3_musl_eabi/include \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi/usr/include \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi/include/fortify \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi/include \
	-Os -pipe -mcpu=cortex-a9 -mfpu=vfpv3-d16 \
	-Wno-error=unused-but-set-variable -Wno-error=unused-result -mfloat-abi=hard \
	-Wformat -Werror=format-security -fstack-protector -D_FORTIFY_SOURCE=1  \
	-Werror-implicit-function-declaration -Wno-system-headers \
	end_otp_usr.c -o end_otp_usr 

/mnt/turris/openwrt-seg6/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi/bin/arm-openwrt-linux-muslgnueabi-gcc \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/target-arm_cortex-a9+vfpv3_musl_eabi/usr/include \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/target-arm_cortex-a9+vfpv3_musl_eabi/include \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi/usr/include \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi/include/fortify \
	-isystem /mnt/turris/openwrt-seg6/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi/include \
	-fvisibility=hidden -Os -pipe -mcpu=cortex-a9 -mfpu=vfpv3-d16 -fno-caller-saves -fno-plt -fhonour-copts \
	-Wno-error=unused-but-set-variable -Wno-error=unused-result -mfloat-abi=hard \
	-Wformat -Werror=format-security -fstack-protector -D_FORTIFY_SOURCE=1 -Wl,-z,now -Wl,-z,relro -ffunction-sections \
	-Werror-implicit-function-declaration -Wno-system-headers -fpic -fPIC -DPIC \
	uplink_wrr_usr.c -o uplink_wrr_usr 

