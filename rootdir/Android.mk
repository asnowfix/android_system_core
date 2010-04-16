LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# files that live under /system/etc/...

copy_from := \
	etc/dbus.conf \
	etc/hosts

ifeq ($(BOARD_USES_QCOM_REF_HARDWARE), true)
copy_from += \
	etc/init.qcom.bt.sh \
	etc/init.qcom.coex.sh \
	etc/init.qcom.fm.sh \
	etc/init.qcom.sdio.sh
endif

ifeq ($(TARGET_PRODUCT),generic)
copy_from += etc/vold.conf
endif


# the /system/etc/init.goldfish.sh is needed to enable emulator support
# in the system image. In theory, we don't need these for -user builds
# which are device-specific. However, these builds require at the moment
# to run the dex pre-optimization *in* the emulator. So keep the file until
# we are capable of running dex preopt on the host.
#
copy_from += etc/init.goldfish.sh

copy_to := $(addprefix $(TARGET_OUT)/,$(copy_from))
copy_from := $(addprefix $(LOCAL_PATH)/,$(copy_from))

$(copy_to) : PRIVATE_MODULE := system_etcdir
$(copy_to) : $(TARGET_OUT)/% : $(LOCAL_PATH)/% | $(ACP)
	$(transform-prebuilt-to-target)

ALL_PREBUILT += $(copy_to)

ifeq ($(BOARD_USES_QCOM_REF_HARDWARE), true)
file := $(TARGET_OUT)/etc/vold.conf
$(file) : $(LOCAL_PATH)/etc/$(TARGET_PRODUCT)/vold.qcom.conf | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)
endif

# files that live under /...

# Only copy init.rc if the target doesn't have its own.
ifneq ($(TARGET_PROVIDES_INIT_RC),true)
file := $(TARGET_ROOT_OUT)/init.rc
$(file) : $(LOCAL_PATH)/init.rc | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)
endif

# Just like /system/etc/init.goldfish.sh, the /init.godlfish.rc is here
# to allow -user builds to properly run the dex pre-optimization pass in
# the emulator.
file := $(TARGET_ROOT_OUT)/init.goldfish.rc
$(file) : $(LOCAL_PATH)/etc/init.goldfish.rc | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)

ifeq ($(BOARD_USES_QCOM_REF_HARDWARE), true)

file := $(TARGET_ROOT_OUT)/init.qcom.rc
$(file) : $(LOCAL_PATH)/etc/init.qcom.rc | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)

file := $(TARGET_ROOT_OUT)/init.qcom.sh
$(file) : $(LOCAL_PATH)/etc/init.qcom.sh | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)

file := $(TARGET_ROOT_OUT)/init.qcom.post_boot.sh
$(file) : $(LOCAL_PATH)/etc/init.qcom.post_boot.sh | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)

endif

# create some directories (some are mount points)
DIRS := $(addprefix $(TARGET_ROOT_OUT)/, \
		sbin \
		dev \
		proc \
		sys \
		system \
		data \
		sd-ext \
		) \
	$(TARGET_OUT_DATA)

$(DIRS):
	@echo Directory: $@
	@mkdir -p $@

ALL_PREBUILT += $(DIRS)
