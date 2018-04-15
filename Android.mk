#включение отладочных сообщений
#DEBUG := 1
#запомним исходный путь
ORIG_LOCAL_PATH := $(call my-dir)
#путь к андроид исходнику iproute2
IPROUTE2_PATH :=$(ORIG_LOCAL_PATH)/../AOSP-examples/iproute2

#подключаем модули динамических библиотек iproute2
include $(IPROUTE2_PATH)/lib/Android.mk

#наш модуль
LOCAL_PATH := $(ORIG_LOCAL_PATH)
include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(IPROUTE2_PATH)/include
LOCAL_SHARED_LIBRARIES := libnetlink libiprouteutil
#module name
LOCAL_MODULE := mstp_rules_wd
#src файлы
LOCAL_SRC_FILES := libnetlink_modif.c mstp_rules_wd.c
ifdef DEBUG
  #так же добавим необходимые файлы из iproute2. они необходимы только для работы print_rule.
  LOCAL_SRC_FILES := $(LOCAL_SRC_FILES) $(IPROUTE2_PATH)/ip/iprule.c $(IPROUTE2_PATH)/ip/rtm_map.c
  LOCAL_CFLAGS += -DDEBUG
endif
#build executable
include $(BUILD_EXECUTABLE)
