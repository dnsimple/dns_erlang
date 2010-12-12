.PHONY: all doc clean test

all:
	@./rebar compile

doc:	
	@./rebar doc skip_deps=true

clean:
	@./rebar clean
	@rm -fr doc/*

test:
	@./rebar eunit