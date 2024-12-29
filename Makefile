REBAR:=$(shell which rebar3 || echo ./rebar3)
REBAR_URL:="https://s3.amazonaws.com/rebar3/rebar3"

gh-pages : TMPDIR := $(shell mktemp -d -t dns_erlang.gh-pages.XXXX)
gh-pages : BRANCH := $(shell git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1 /')
gh-pages : STASH := $(shell (test -z "`git status --porcelain`" && echo false) || echo true)
gh-pages : VERSION := $(shell sed -n 's/.*{vsn,.*"\(.*\)"}.*/\1/p' src/dns_erlang.app.src)

all: build

$(REBAR):
	wget $(REBAR_URL) && chmod +x rebar3

.PHONY: build
build: $(REBAR)
	@$(REBAR) compile

.PHONY: doc
doc: $(REBAR)
	@$(REBAR) edoc

.PHONY: clean
clean: $(REBAR)
	@$(REBAR) clean
	@rm -fr doc/*

.PHONY: fresh
fresh: clean
	rm -fr _build/*

.PHONY: test
test: $(REBAR) all
	@$(REBAR) eunit
	@$(REBAR) fmt --check
	@$(REBAR) dialyzer

.PHONY: format
format: build
	@$(REBAR) fmt
