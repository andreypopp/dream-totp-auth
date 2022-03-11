OCAML_VERSION ?= 4.12.1

.PHONY: init
init:
	opam switch create . -y --no-install $(OCAML_VERSION)
	opam install . -y --deps-only
	opam install -y ocaml-lsp-server ocamlformat

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
