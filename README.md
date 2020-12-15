# ckb-passport-lock

[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/duanyytop/ckb-passport-lock/blob/develop/COPYING)
[![Github Actions CI](https://github.com/duanyytop/ckb-passport-lock/workflows/CI/badge.svg?branch=develop)](https://github.com/duanyytop/ckb-passport-lock/actions)

The lock script of e-passport on Nervos CKB using [Capsule](https://github.com/nervosnetwork/capsule)

### Pre-requirement

- [capsule](https://github.com/nervosnetwork/capsule) >= 0.4.3
- [ckb-cli](https://github.com/nervosnetwork/ckb-cli) >= 0.35.0
- [rsa_sighash_all](https://github.com/nervosnetwork/ckb-miscellaneous-scripts/blob/master/c/rsa_sighash_all.c) which supports loaded as a shared library.

> Note: Capsule uses docker to build contracts and run tests. https://docs.docker.com/get-docker/
> and docker and ckb-cli must be accessible in the PATH in order for them to be used by Capsule.

### Getting Started

- Init submodules:

```
git submodule init && git submodule update -r --init
```

- Build the shared binary `rsa_sighash_all`:

```
cd ckb-miscellaneous-scripts && git submodule init && git submodule update

make all-via-docker
```

- Build contracts:

```sh
# back to repo root directory
cd .. && capsule build
```

- Run tests

```sh
capsule test
```
