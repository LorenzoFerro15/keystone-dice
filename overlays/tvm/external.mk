
##############
## Packages ##
##############

# Packages
include $(sort $(wildcard $(BR2_EXTERNAL_TVM_PATH)/package/*/*.mk))

###############
## Overrides ##
###############

# TVM requires a compiler on the target, which Buildroot does not natively
# support. Luckily for us, a lab at UC Davis recently wrote some code to
# implement this (see sources at end). The patchset involves adding a new
# package for gcc-target, which essentially just builds a native target
# compiler and installs it. However, Buildroot has a cleaning step where
# it entirely removes /usr/include as well as all .a files in the /lib,
# /usr/lib/, and /usr/libexec directories. The original patch authors
# address this by modifying Buildroot directly, but I feel that this is not
# the cleanest approach since it would introduce a patch step for Buildroot
# in our new build system. Therefore, we add short hooks both here and in
# package/gcc-target/gcc-target.mk which rename the necessary files such
# that Buildroot will not delete them. The code below then restores these
# files to their expected names.
#
# https://luplab.cs.ucdavis.edu/2022/01/06/buildroot-and-compiler-on-target.html

.PHONY: gcc-target-post-finalize
gcc-target-post-finalize: target-finalize
	$(warning gcc-target-post-finalize)
	mv $(TARGET_DIR)/usr/include.bak $(TARGET_DIR)/usr/include
	for f in $$(find $(TARGET_DIR)/lib/ $(TARGET_DIR)/usr/lib/ \
                        $(TARGET_DIR)/usr/libexec/ -name '*.a.bak' ); \
                do rename .bak '' $$f ; done

$(TARGETS_ROOTFS): gcc-target-post-finalize