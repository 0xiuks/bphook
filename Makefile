TARGET = iphone:clang:latest:11.0
ARCHS = arm64
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = example

$(TWEAK_NAME)_FILES = Tweak.xm \
                      bphook/bphook.c \
                      bphook/bp_image_addr.c \
                      bphook/fishhook.c \
                      bphook/trampoline.s \
                      bphook/mach_excServer.c
$(TWEAK_NAME)_CFLAGS = -fobjc-arc -Wno-error -I. -I./bphook

include $(THEOS_MAKE_PATH)/tweak.mk
