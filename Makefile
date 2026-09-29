BINARY := gatewarden
DIST_DIR := dist
GO ?= go
GOARCH ?= amd64
DOCKER ?= docker
prefix ?= /usr
systemdunitdir ?= /usr/lib/systemd/system

DEB_BUILD_IMAGE ?= gatewarden-deb-build:22.04
RPM_BUILD_IMAGE ?= gatewarden-rpm-build:8

.DEFAULT_GOAL := build

.PHONY: build build-linux build-windows build-darwin build-all test check checksums \
	clean install uninstall deb rpm publish-deb publish-rpm package-images \
	package-image-deb package-image-rpm

build:
	@mkdir -p $(DIST_DIR)
	$(GO) build -trimpath -o $(DIST_DIR)/$(BINARY) .

build-linux:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) $(GO) build -trimpath \
		-o $(DIST_DIR)/$(BINARY)-linux-$(GOARCH) .

build-windows:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath \
		-o $(DIST_DIR)/$(BINARY)-windows-amd64.exe .

build-darwin:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -trimpath \
		-o $(DIST_DIR)/$(BINARY)-darwin-amd64 .

build-all: build-linux build-windows build-darwin

test:
	$(GO) test ./...

check: test
	./scripts/test-package-invariants.sh

checksums:
	@mkdir -p $(DIST_DIR)
	@cd $(DIST_DIR) && files=$$(find . -type f ! -name SHA256SUMS -print | sort); \
		test -n "$$files" || { echo "no artifacts to checksum" >&2; exit 1; }; \
		if command -v sha256sum >/dev/null 2>&1; then \
			printf '%s\n' "$$files" | xargs sha256sum > SHA256SUMS; \
		else \
			printf '%s\n' "$$files" | xargs shasum -a 256 > SHA256SUMS; \
		fi

install: build-linux
	install -d $(DESTDIR)$(prefix)/bin $(DESTDIR)$(systemdunitdir)
	install -m 0755 $(DIST_DIR)/$(BINARY)-linux-$(GOARCH) $(DESTDIR)$(prefix)/bin/$(BINARY)
	install -m 0644 deploy/systemd/$(BINARY).service $(DESTDIR)$(systemdunitdir)/$(BINARY).service

uninstall:
	rm -f $(DESTDIR)$(prefix)/bin/$(BINARY) \
		$(DESTDIR)$(systemdunitdir)/$(BINARY).service

package-images: package-image-deb package-image-rpm

package-image-deb:
	$(DOCKER) build --platform linux/amd64 -t $(DEB_BUILD_IMAGE) \
		-f deploy/docker/deb-build.Dockerfile deploy/docker

package-image-rpm:
	$(DOCKER) build --platform linux/amd64 -t $(RPM_BUILD_IMAGE) \
		-f deploy/docker/rpm-build.Dockerfile deploy/docker

deb:
	./scripts/build-deb.sh

rpm:
	./scripts/build-rpm.sh

publish-deb:
	@test -n "$$NEXUS_USER" && test -n "$$NEXUS_PASS" || { \
		echo "usage: NEXUS_USER=... NEXUS_PASS=... make publish-deb" >&2; exit 1; }
	./scripts/publish-deb.sh

publish-rpm:
	@test -n "$$NEXUS_USER" && test -n "$$NEXUS_PASS" || { \
		echo "usage: NEXUS_USER=... NEXUS_PASS=... make publish-rpm" >&2; exit 1; }
	./scripts/publish-rpm.sh

clean:
	rm -rf $(DIST_DIR)
