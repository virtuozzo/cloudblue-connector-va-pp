# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************

NAME := cloudblue-connector
DESTDIR ?= /
SYSCONFDIR ?= /etc
BINDIR ?= /usr/bin
PYTHON ?= /usr/bin/python3
INSTALL ?= /usr/bin/install
UNITDIR ?= /usr/lib/systemd/system
SERVICE_UNITS = cloudblue-backup-removal.service
CONFIGS = config.json.example

all:
	$(PYTHON) setup.py build

install:
	curl https://bootstrap.pypa.io/pip/3.6/get-pip.py | $(PYTHON)
	pip install --upgrade pip setuptools
	for p in $$(cat ./requirements.txt | xargs); do \
		pip install "$$p"; \
	done
	$(PYTHON) setup.py install --skip-build --root $(DESTDIR) --install-scripts $(BINDIR)
	mkdir -p -m 0755 $(DESTDIR)/$(UNITDIR)
	for f in $(SERVICE_UNITS); do \
		 $(INSTALL) -m 0644 $$f $(DESTDIR)/$(UNITDIR); \
	done
	mkdir -p -m 0755 $(DESTDIR)/$(SYSCONFDIR)/$(NAME)
	for f in $(CONFIGS); do \
		$(INSTALL) -m 0644 $$f $(DESTDIR)/$(SYSCONFDIR)/$(NAME); \
	done

rpm:
	mkdir -p ./build/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}; \
	export VERSION=$$(sed -n -e  's/%define current_version //p' cloudblue-connector-backend.spec | sed -e 's/^[[:space:]]*//'); \
	rsync --exclude=build --exclude=dist -av `pwd`/ ./build/SOURCES/cloudblue-connector-backend-$$VERSION; \
	cd ./build/SOURCES && tar -cvjSf cloudblue-connector-backend-$$VERSION.tar.bz2 cloudblue-connector-backend-$$VERSION; cd -; \
	rpmbuild -ba --define "_topdir `pwd`/build" cloudblue-connector-backend.spec

.PHONY: all clean install test rpm
