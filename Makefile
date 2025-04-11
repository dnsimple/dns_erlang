all: build

.PHONY: build
build:
	rebar3 compile

.PHONY: doc
doc:
	rebar3 edoc

.PHONY: clean
clean:
	rebar3 clean
	@rm -rf doc

.PHONY: fresh
fresh: clean
	rm -rf _build

.PHONY: test
test: all
	rebar3 xref
	rebar3 dialyzer
	rebar3 eunit
	rebar3 do cover, covertool generate

.PHONY: format
format: build
	rebar3 fmt
