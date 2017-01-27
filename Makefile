
VERSION := $(shell cat VERSION)
ARCHS := "darwin/amd64"
GLIDE := $(shell command -v glide 2> /dev/null)
CARPET := $(shell command -v go-carpet 2> /dev/null)
MT := $(shell command -v multitail 2> /dev/null)
PWD := $(shell cd .. && pwd)

default: build

setup:
	@go get github.com/jteeuwen/go-bindata/... 
ifndef GLIDE
	@brew install glide
endif

install:
	@glide install

build:
	@go build

release:
	@LDFLAGS='-X main.VERSION=${VERSION}' gox -osarch=${ARCHS} -output=build/arper_v${VERSION}_{{.OS}}_{{.Arch}}/arper github.com/jondot/arper/arper
	@cd build && find . -type d -mindepth 1 -exec tar czf {}.tar.gz {} \;
	@rm -rf release
	@mkdir release
	@mv build/*.tar.gz release/
	@rm -rf build
	ls -la release
	
brew_sha:
	@ls release | grep darwin | xargs -I{} shasum -a 256 release/{}

.PHONY: test build release setup install watch lint mocks coverage eject bench brew_sha
