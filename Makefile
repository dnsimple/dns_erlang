REBAR:=$(shell which rebar3 || echo ./rebar3)
REBAR_URL:="https://s3.amazonaws.com/rebar3/rebar3"

gh-pages : TMPDIR := $(shell mktemp -d -t dns_erlang.gh-pages.XXXX)
gh-pages : BRANCH := $(shell git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1 /')
gh-pages : STASH := $(shell (test -z "`git status --porcelain`" && echo false) || echo true)
gh-pages : VERSION := $(shell sed -n 's/.*{vsn,.*"\(.*\)"}.*/\1/p' src/dns_erlang.app.src)

.PHONY: all doc clean test

all: compile

$(REBAR):
	wget $(REBAR_URL) && chmod +x rebar3	

compile: $(REBAR)
	@$(REBAR) compile

doc: $(REBAR)
	@$(REBAR) edoc

clean: $(REBAR)
	@$(REBAR) clean
	@rm -fr doc/*

fresh: clean
	rm -fr _build/*

gh-pages: $(REBAR) test doc
	@echo "Building gh-pages for ${VERSION} in ${TMPDIR} from branch ${BRANCH}. Branch dirty: ${STASH}."
	sed 's/{{VERSION}}/${VERSION}/g' priv/index.html > ${TMPDIR}/index.html
	rsync -a --remove-source-files doc/ ${TMPDIR}/doc
	rsync -a --remove-source-files .eunit/ ${TMPDIR}/coverage
	@$(REBAR) clean
	(${STASH} && git stash save) || true
	git checkout gh-pages
	rsync -a --delete ${TMPDIR}/* .
	git add .
	git commit -a -m "update auto-generated docs"
	git checkout ${BRANCH}
	(${STASH} && git stash pop) || true
	rm -fr ${TMPDIR}

test: $(REBAR) all
	@$(REBAR) eunit
	@$(REBAR) dialyzer
