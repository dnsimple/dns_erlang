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
test: all check-no-change-action
	rebar3 lint
	rebar3 xref
	rebar3 dialyzer
	rebar3 ct
	rebar3 do cover, covertool generate

.PHONY: format
format: build
	rebar3 fmt

# Will capture any reference to "(?i)RFC[\\s-]?(\\d+)" in src and include files.
# It runs on CI. When adding support for new RFCs, you should add any reference to it it code
# and regenerate the RFC list with `make rfc-list`.
.PHONY: rfc-list
rfc-list:
	./scripts/generate_rfc_list.escript --output ./SUPPORTED_RFCs.md

.PHONY: rfc-list-print
rfc-list-print:
	./scripts/generate_rfc_list.escript

.PHONY: check-no-change-action
check-no-change-action: rfc-list
	git diff --quiet --exit-code SUPPORTED_RFCS.md
