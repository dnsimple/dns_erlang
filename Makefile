REBAR:=$(shell which rebar3 || echo ./rebar3)
REBAR_URL:="https://s3.amazonaws.com/rebar3/rebar3"

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
	@rm -rf doc

.PHONY: fresh
fresh: clean
	rm -rf _build

.PHONY: test
test: $(REBAR) all
	@$(REBAR) eunit
	@$(REBAR) fmt --check
	@$(REBAR) dialyzer

.PHONY: format
format: build
	@$(REBAR) fmt
