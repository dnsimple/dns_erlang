# Contributing to DNSimple/dns_erlang

## Getting started

#### 1. Clone the repository

Clone the repository and move into it:

```shell
git clone git@github.com:dnsimple/dns_erlang.git
cd dns_erlang
```

#### 2. Install Erlang

#### 3. Create your own working branch

```shell
git checkout -b dev_new_feature_xyz
```

#### 3. Build and test

Compile the project and [run the test suite](#testing) to check everything works as expected.

```shell
make all
```


## Testing

```shell
make test
```


## Releasing

1. Run the test suite and ensure all the tests pass.

2. Commit and push the changes

    ```shell
    git commit -a -m "* <adding feature/enhancement X/Y/Z"
    git push origin dev_new_feature_xyz
    ```

3. Initiate PR for reviewing and merging upstream.

## Tests

Please be sure to submit unit tests for your changes. You can test your changes on your machine by [running the test suite](#testing).
