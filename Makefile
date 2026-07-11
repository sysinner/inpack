# Copyright 2015 Eryx <evorui at gmail dot com>, All rights reserved.
#

BINDATA_CMD = inpack

.PHONY: build_main install

all: build_main
	@echo ""
	@echo "build complete"
	@echo ""

build_main:
	go build -trimpath -ldflags="-s -w" -o ${BINDATA_CMD} cmd/inpack/main.go

install: build_main
	install ${BINDATA_CMD} ${GOPATH}/bin/${BINDATA_CMD}

clean:
	@echo ""
	@echo "clean complete"
	@echo ""
	rm -f ${BINDATA_CMD}
