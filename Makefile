GOPATH= $(shell go env GOPATH)

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	# Since we save go struct pointer for SSL_CTX_set_ex_data data, it always failed to vet
	# go vet ./...
	GO111MODULE=on go get honnef.co/go/tools/cmd/staticcheck@2020.1.3
	$(GOPATH)/bin/staticcheck -go 1.14 ./...
