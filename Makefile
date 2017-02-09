package = github.com/Kalsi13/mandeep123
TAG := $(shell git tag | sort -r | head -n 1)

test:
	go test github.com/Kalsi13/mandeep123/collector -cover -coverprofile=collector_coverage.out -short
	go tool cover -func=collector_coverage.out
	go test github.com/Kalsi13/mandeep123/shared -cover -coverprofile=shared_coverage.out -short
	go tool cover -func=shared_coverage.out
	@rm *.out

deps:
	glide install

build: deps
	go build mongodb_exporter.go

release: deps
	mkdir -p release
	perl -p -i -e 's/{{VERSION}}/$(TAG)/g' mongodb_exporter.go
	GOOS=darwin GOARCH=amd64 go build -o release/mongodb_exporter-darwin-amd64 $(package)
	GOOS=linux GOARCH=amd64 go build -o release/mongodb_exporter-linux-amd64 $(package)
	perl -p -i -e 's/$(TAG)/{{VERSION}}/g' mongodb_exporter.go
