#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright 2020 Joyent, Inc.
# Copyright 2026 Edgecast Cloud LLC.
#

NAME = ipxe

TOP :=	$(shell pwd)
ROOT =	$(TOP)/proto

RELEASE_TARBALL =	$(NAME)-$(STAMP).tar.gz

# ipxe doesn't quite clean up after itself
CLEAN_FILES += \
	src/config/local/crypto.h \
	src/config/local/fault.h \
	src/config/local/reboot.h \
	src/config/local/usb.h \
	$(ROOT) \
	$(NAME)-*.tar.gz

#
# ipxe assumes GNU without using prefixed commands.
#
IPXE_ENV = \
	CC=/opt/local/bin/gcc \
	AS=/opt/local/bin/as \
	LD=/opt/local/bin/gld \
	AWK=/usr/bin/nawk \
	GREP=/usr/xpg4/bin/grep \
	V=1

TAR =		/usr/bin/gtar
MKDIR =		/usr/bin/mkdir
MKFILE =	/usr/sbin/mkfile
CP =		/usr/bin/cp
OBJCOPY =	/opt/local/bin/objcopy
CHMOD =		/usr/bin/chmod
RM =		/usr/bin/rm -f
INS =		/usr/sbin/install

FILEMODE =	644
DIRMODE =	755

INS.file =	$(RM) $@; $(INS) -s -m $(FILEMODE) -f $(@D) $<
INS.dir =	$(INS) -s -d -m $(DIRMODE) $@

EFI_BINS = ipxe.efi snponly.efi
EFI_SRC_BIN = src/bin-x86_64-efi
EFI_TARGETS = $(EFI_BINS:%=$(EFI_SRC_BIN)/%)

BOOT_BINS = \
	undionly.kpxe \
	default.ipxe \
	ipxe.lkrn \
	$(EFI_BINS)

BOOT_ROOT =	$(ROOT)/boot
ROOT_BOOT_BINS =	$(BOOT_BINS:%=$(BOOT_ROOT)/%)
ROOT_BOOT =	$(ROOT_BOOT_BINS)

$(BOOT_ROOT)/ipxe.lkrn :	FILEMODE = 755
$(BOOT_ROOT)/default.ipxe :	FILEMODE = 644
$(BOOT_ROOT)/undionly.kpxe :	FILEMODE = 644

ENGBLD_USE_BUILDIMAGE = false
ENGBLD_REQUIRE := $(shell git submodule update --init deps/eng)
include ./deps/eng/tools/mk/Makefile.defs
TOP ?= $(error Unable to access eng.git submodule Makefiles.)

# our base image is triton-origin-x86_64-24.4.1
BASE_IMAGE_UUID = 41bd4100-eb86-409a-85b0-e649aadf6f62
BUILD_PLATFORM = 20210826T002459Z

.PHONY: all
all: src/bin/ipxe.lkrn $(EFI_TARGETS)

.PHONY: install
install: all $(ROOT_BOOT)
	mkdir -p $(ROOT)/etc/version
	echo $(TIMESTAMP) >$(ROOT)/etc/version/ipxe

$(ROOT):
	$(INS.dir)

$(BOOT_ROOT): | $(ROOT)
	$(INS.dir)

$(BOOT_ROOT)/%: src/bin/% | $(BOOT_ROOT)
	$(INS.file)

$(BOOT_ROOT)/ipxe.efi: src/bin-x86_64-efi/ipxe.efi | $(BOOT_ROOT)
	$(INS.file)

$(BOOT_ROOT)/snponly.efi: src/bin-x86_64-efi/snponly.efi | $(BOOT_ROOT)
	$(INS.file)

$(BOOT_ROOT)/%: boot/% | $(BOOT_ROOT)
	$(INS.file)

src/bin/%:
	(cd src && $(MAKE) -j 6 bin/$(@F) $(IPXE_ENV))

src/bin-x86_64-efi/%:
	 (cd src && $(MAKE) -j 6 bin-x86_64-efi/$(@F) $(IPXE_ENV))

.PHONY: test
test:

.PHONY: pkg
pkg: install

clean:: ipxe.clean
	rm -rf $(CLEAN_FILES)

ipxe.clean:
	(cd src && $(MAKE) clean $(IPXE_ENV))

release: $(RELEASE_TARBALL)

$(RELEASE_TARBALL): pkg
	(cd $(ROOT); $(TAR) -I pigz -cf $(TOP)/$(RELEASE_TARBALL) .)

publish: release
	@if [[ -z "$(ENGBLD_BITS_DIR)" ]]; then \
		echo "error: 'ENGBLD_BITS_DIR' must be set for 'publish' target"; \
		exit 1; \
	fi
	mkdir -p $(ENGBLD_BITS_DIR)/ipxe
	cp $(RELEASE_TARBALL) $(ENGBLD_BITS_DIR)/ipxe/$(RELEASE_TARBALL)

include ./deps/eng/tools/mk/Makefile.deps
include ./deps/eng/tools/mk/Makefile.targ
