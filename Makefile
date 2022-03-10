.PHONY: build
build:
	dune build

.PHONY: start
start:
	dune exec dream-totp-auth

.PHONY: fmt
fmt:
	dune build @fmt

.PHONY: clean
clean:
	dune clean
