.PHONY: test
test:
	go test -v -coverprofile cover.out ./...

.PHONY: cover
cover:
	go tool cover -html cover.out

.PHONY: vet
vet:
	go vet -v ./...

.PHONY: benchmark
benchmark:
	go test -v -run Benchmark -cpuprofile cpu.prof -memprofile mem.prof -bench ./...

.PHONY: clean
clean:
	rm cover.out
	rm cpu.prof
	rm mem.prof
