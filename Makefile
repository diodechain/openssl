GOPATH= $(shell go env GOPATH)

.PHONY: default
default: test clean

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	# Since we save go struct pointer for SSL_CTX_set_ex_data data, it always failed to vet
	# go vet ./...
	GO111MODULE=on go get honnef.co/go/tools/cmd/staticcheck@2020.1.3
	$(GOPATH)/bin/staticcheck -go 1.14 ./...

# Lead to could not import C (no metadata for C)
# See https://github.com/golang/go/issues/36441
# Exclude rules from security check:
# G304 (CWE-22): Potential file inclusion via variable.
# G103 (CWE-242): Use of unsafe calls should be audited.
# G104 (CWE-703): Errors unhandled.
.PHONY: seccheck
seccheck:
	GO111MODULE=on go get github.com/securego/gosec/v2/cmd/gosec
	$(GOPATH)/bin/gosec -exclude=G304,G103,G104 ./...

.PHONY: build
build:
	go build ./...

.PHONY: clean
clean:
	go clean -cache ./...
	go mod tidy