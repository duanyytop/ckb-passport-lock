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

make validate_signature_rsa-via-docker
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

### Deployment

#### 1. Update the deployment configurations

Open `deployment.toml` :

- cells describes which cells to be deployed.

  - `name`: Define the reference name used in the deployment configuration.
  - `enable_type_id` : If it is set to true means create a type_id for the cell.
  - `location` : Define the script binary path.
  - `dep_groups` describes which dep_groups to be created. Dep Group is a cell which bundles several cells as its members. When a dep group cell is used in cell_deps, it has the same effect as adding all its members into cell_deps. In our case, we don’t need dep_groups.

- `lock` describes the lock field of the new deployed cells.It is recommended to set lock to the address(an address that you can unlock) of deployer in the dev chain and in the testnet, which is easier to update the script.

#### 2. Build release version of the script

The release version of script doesn’t include debug symbols which makes the size smaller.

```sh
capsule build --release
```

#### 3. Deploy the script

```sh
capsule deploy --address <ckt1....> --fee 0.001
```

If the `ckb-cli` has been installed and `dev-chain` RPC is connectable, you will see the deployment plan:

new_occupied_capacity and total_occupied_capacity refer how much CKB to store cells and data.
txs_fee_capacity refers how much CKB to pay the transaction fee.

```
Deployment plan:
---
migrated_capacity: 0.0 (CKB)
new_occupied_capacity: 121348.0 (CKB)
txs_fee_capacity: 0.003 (CKB)
total_occupied_capacity: 121348.0 (CKB)
recipe:
  cells:
    - name: ckb-passport-lock
      index: 0
      tx_hash: "0x01a294bb922a9e9b217e82d9f7cabfe6a72fb9920cdc3bd6d64e436ac234a5c7"
      occupied_capacity: 58414.0 (CKB)
      data_hash: "0x2cdedab61ac07247d10d6889fda575a64d58151777938e4aec55f2a8cf4587c6"
      type_id: "0xc00226dfdeee4c3a160f2dde4be5dd5317e0b65e07858f2a285e96c312510331"
    - name: rsa_sighash_all
      index: 0
      tx_hash: "0xc9df0a7dd2f8cd1ba940f84a91b4b6dca45647f4ab25b2b8fb2f53c86c21b848"
      occupied_capacity: 62797.0 (CKB)
      data_hash: "0x131126b55109a5852910b7ef14f0331170cf49209f5369814574244cb546a324"
      type_id: ~
  dep_groups:
    - name: dep_group
      tx_hash: "0x8944b5149074321e5cad1c18dbf575d7d46acdc17974e7c2c8afa320b3b772db"
      index: 0
      occupied_capacity: 137.0 (CKB)
```

#### 4. Type yes or y and input the password to unlock the account.

```
(1/3) Sending tx 01a294bb922a9e9b217e82d9f7cabfe6a72fb9920cdc3bd6d64e436ac234a5c7
(2/3) Sending tx c9df0a7dd2f8cd1ba940f84a91b4b6dca45647f4ab25b2b8fb2f53c86c21b848
(3/3) Sending tx 8944b5149074321e5cad1c18dbf575d7d46acdc17974e7c2c8afa320b3b772db
Deployment complete
```

Now the passport lock script has been deployed, you can refer to this script by using `tx_hash: 0x8944b5149074321e5cad1c18dbf575d7d46acdc17974e7c2c8afa320b3b772db index: 0` as `out_point`(your tx_hash should be another value).
