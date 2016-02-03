REBAR:=$(shell which rebar3 || echo ./rebar3)
REBAR_URL:="https://github.com/downloads/basho/rebar/rebar3"

gh-pages : TMPDIR := $(shell mktemp -d -t dns_erlang.gh-pages.XXXX)
gh-pages : BRANCH := $(shell git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1 /')
gh-pages : STASH := $(shell (test -z "`git status --porcelain`" && echo false) || echo true)
gh-pages : VERSION := $(shell sed -n 's/.*{vsn,.*"\(.*\)"}.*/\1/p' src/dns.app.src)

.PHONY: all doc clean test

all: compile

$(REBAR):
	@echo "No rebar was found so a copy will be downloaded in 5 seconds."
	@echo "Source: ${REBAR_URL} Destination: ${REBAR}"
	@sleep 5
	@echo "Commencing download... "
	@erl -noshell -eval "\
[ application:start(X) || X <- [crypto,public_key,ssl,inets]],\
Request = {\"${REBAR_URL}\", []},\
HttpOpts = [],\
Opts = [{stream, \"$(REBAR)\"}],\
Result = httpc:request(get, Request, HttpOpts, Opts),\
Status = case Result of {ok, _} -> 0; _ -> 1 end,\
init:stop(Status)."
	@chmod u+x ./rebar
	@echo "ok"

compile: $(REBAR)
	@$(REBAR) compile

doc: $(REBAR)
	@$(REBAR) doc skip_deps=true

clean: $(REBAR)
	@$(REBAR) clean
	@rm -fr doc/*

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
	@$(REBAR) eunit skip_deps=true
