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
	rebar3 eunit
	rebar3 fmt --check
	rebar3 dialyzer

.PHONY: format
format: build
	rebar3 fmt
