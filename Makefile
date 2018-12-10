#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2018, Joyent, Inc.
#

NAME = ipxe

TOP :=	$(shell pwd)
ROOT =	$(TOP)/proto

RELEASE_TARBALL =	$(NAME)-$(STAMP).tgz

# ipxe doesn't quite clean up after itself
CLEAN_FILES += \
	src/config/local/crypto.h \
	src/config/local/fault.h \
	src/config/local/reboot.h \
	src/config/local/usb.h \
	$(ROOT) \
	$(NAME)-*.tgz

#
# ipxe assumes GNU without using prefixed commands.
#
IPXE_ENV = \
	AS=/opt/local/bin/as \
	LD=/opt/local/bin/gld \
	AWK=/usr/bin/nawk \
	GREP=/usr/xpg4/bin/grep \
	GITVERSION= \
	V=1

CC =		/opt/local/bin/gcc
LD =		/usr/bin/ld
TAR =		/opt/local/bin/tar
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

BOOT_BINS = \
	undionly.kpxe \
	default.ipxe \
	ipxe.lkrn \
	ipxe.efi

BOOT_ROOT =	$(ROOT)/boot
ROOT_BOOT_BINS =	$(BOOT_BINS:%=$(BOOT_ROOT)/%)
ROOT_BOOT =	$(ROOT_BOOT_BINS)

include ./tools/mk/Makefile.defs

$(BOOT_ROOT)/ipxe.lkrn :	FILEMODE = 755
$(BOOT_ROOT)/default.ipxe :	FILEMODE = 644
$(BOOT_ROOT)/undionly.kpxe :	FILEMODE = 644

.PHONY: all
all: src/bin/ipxe.lkrn src/bin-x86_64-efi/ipxe.efi

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

$(BOOT_ROOT)/%: boot/% | $(BOOT_ROOT)
	$(INS.file)

src/bin/%:
	(cd src && $(MAKE) bin/$(@F) $(IPXE_ENV))

src/bin-x86_64-efi/%:
	 (cd src && $(MAKE) bin-x86_64-efi/$(@F) $(IPXE_ENV))

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
	(cd $(ROOT); $(TAR) czf $(TOP)/$(RELEASE_TARBALL) .)

publish: prepublish $(BITS_DIR)/$(NAME)/$(RELEASE_TARBALL)

.PHONY: prepublish
prepublish:
	@if [[ -z "$(BITS_DIR)" ]]; then \
		echo "error: 'BITS_DIR' must be set for 'publish' target"; \
		exit 1; \
	fi
	@if [[ ! -d "$(BITS_DIR)" ]]; then \
		echo "error: $(BITS_DIR) is not a directory"; \
		exit 1; \
	fi

$(BITS_DIR)/$(NAME)/$(RELEASE_TARBALL): $(RELEASE_TARBALL) | $(BITS_DIR)/$(NAME)
	$(INS.file)

$(BITS_DIR)/$(NAME):
	$(INS.dir)

include ./tools/mk/Makefile.targ
