PROJECTNAME=$(shell basename "$(PWD)")

# Go related variables.
# Make is verbose in Linux. Make it silent.
MAKEFLAGS += --silent

.PHONY: help
## help: Prints this help message
help: Makefile
	@echo
	@echo " Choose a command run in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

.PHONY: setup
## setup: Setup installes dependencies
setup:
	@go mod tidy

.PHONY: run-rpc
## run: Run rpc example 
run-rpc: 
	@go run $$(ls -1 _example/rpc/*.go | grep -v _test.go)

.PHONY: run-console
## run: Run console example 
run-console: 
	@go run $$(ls -1 _example/console/*.go | grep -v _test.go)

.PHONY: test
## test: Runs go test with default values
test: 
	@go test -v -race -count=1  ./...
