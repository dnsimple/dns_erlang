# Contributing to dns_erlang

## Getting started

### 1. Clone the repository

Clone the repository and move into it:

```shell
git clone git@github.com:dnsimple/dns_erlang.git
cd dns_erlang
```

### 2. Install Erlang

### 3. Install the dependencies

```shell
make
```

#### Updating Dependencies

When dependencies are updated the rebar.lock file will need to be updated for the new dependency to be used. The following command does this:

```shell
./rebar3 upgrade --all
```

## Formatting

If your editor doesn't automatically format Erlang code using [erlfmt](https://github.com/WhatsApp/erlfmt), run:

```shell
make format
```

You should run this command before releasing.

### 3. Build and test

Compile the project and [run the test suite](#testing) to check everything works as expected.

## Testing

```shell
make test
```

## Releasing

The following instructions uses `$VERSION` as a placeholder, where `$VERSION` is a `MAJOR.MINOR.BUGFIX` release such as `1.2.0`.

1. Run the test suite and ensure all the tests pass.

2. Finalize the `## main` section in `CHANGELOG.md` assigning the version.

3. Commit and push the changes

    ```shell
    git commit -a -m "Release $VERSION"
    git push origin main
    ```

4. Wait for CI to complete.

5. Create a signed tag.

    ```shell
    git tag -a v$VERSION -s -m "Release $VERSION"
    git push origin --tags
    ```

6. GitHub actions will take it from there and release to <https://hex.pm/packages/dns_erlang>

## Code Guidelines

Follow the [Inaka Erlang Guidelines](https://github.com/inaka/erlang_guidelines) as the primary coding convention. The guidelines below supplement and emphasize project-specific patterns.

### Erlang Style

- **Pattern matching**: Prefer pattern matching and function-head dispatch over nested conditionals
  - Use `case ... of` or pattern-matching function heads instead of `if` expressions
  - Use `case {Cond1, Cond2, ...} of` for multiple conditionals where it helps instead of `if` expressions
- **Functions**: Keep functions short with single responsibilities; break complex logic into helpers
- **Traceability**: Favour named functions over anonymous ones, as naming enhances debugging

### Types & Specs

- Always provide `-spec` definitions for exported functions
- Always provide types in record definitions
- Dialyzer is required (runs in CI)

### Testing

- Common Test (ct): For unit and integration tests (strictly preferred over `eunit`), use parallel test cases when possible.

### Commit Messages

Use conventional, descriptive commit messages:

```gitcommit
Short summary (<= 72 chars)

Detailed description explaining:
- The reason for the change
- Any side effects
- How it was tested
```

## Submitting Changes

- Format code with `make format`
- Write tests for your changes, every change should be automatically tested comprehensively
- Ensure `make test` passes locally
- Submit a PR targeting `main`, CI will run the full test suite automatically
