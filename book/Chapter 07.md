# 第七章：Taproot 双叶脚本树——哈希锁与 Bob 脚本的完整实现

## 从单叶到双叶：Taproot 脚本树的真正力量

在上一章中，我们通过 Alice 的哈希锁合约掌握了单叶 Taproot Script Path 的完整实现。然而，Taproot 的真正力量在于其**多分支脚本树**架构——能够在一个地址内优雅地组织多个不同的花费条件，实现复杂的有条件逻辑。

想象这个业务场景：Alice 想创建一个数字托管合约，既支持基于秘密信息的自动解锁（哈希锁），又为 Bob 提供直接私钥控制权限。在传统 Bitcoin 中，这需要复杂的多重签名脚本或多个独立地址。Taproot 的双叶脚本树可以优雅地将这两个条件整合到一个地址中：

- **Script Path 1**：哈希锁脚本，任何知道"helloworld"的人都可以花费
- **Script Path 2**：Bob 脚本（`<pubkey> OP_CHECKSIG`），只有 Bob 的私钥持有者可以花费  
- **Key Path**：Alice 作为内部密钥持有者可以直接花费（最大隐私）

> **安全对比**：注意 Bob 脚本使用 `OP_CHECKSIG` 绑定了签名验证，即使见证数据在 mempool 中可见，他人也无法伪造 Bob 的签名来抢先花费——这正是第六章安全提示中针对 `OP_TRUE` 哈希锁建议的改进方向。同一棵脚本树中，两种脚本的安全模型截然不同。

这种设计的优雅之处在于，外部观察者无法区分这是简单支付还是复杂的三路径有条件合约。只有在实际花费时，使用的路径才会被选择性揭示。

## 双叶脚本树的 Merkle 结构

与直接使用 TapLeaf 哈希作为 Merkle 根的单叶树不同，双叶脚本树需要构建真正的 Merkle 树：

```
        Merkle Root
       /           \
  TapLeaf A    TapLeaf B
(Hash Script) (Bob Script)
```

**技术实现关键点**：

1. **TapLeaf 哈希计算**：每个脚本分别计算其 TapLeaf 哈希
2. **TapBranch 哈希计算**：在按字典序排序两个 TapLeaf 哈希后计算 TapBranch 哈希  
3. **控制块构建**：每个脚本需要包含其兄弟节点哈希作为 Merkle 证明

让我们通过实际链上交易数据深入理解这一切如何工作。

## 实际案例研究：基于链上交易的完整分析

我们将基于两个真实测试网交易分析双叶脚本树的完整实现：

### 交易 1：哈希脚本路径支出

- **交易 ID**：`b61857a05852482c9d5ffbb8159fc2ba1efa3dd16fe4595f121fc35878a2e430`
- **Taproot 地址**：`tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z`
- **支出方法**：Script Path（使用原像"helloworld"）

### 交易 2：Bob 脚本路径支出

- **交易 ID**：`185024daff64cea4c82f129aa9a8e97b4622899961452d1d144604e65a70cfe0`
- **Taproot 地址**：`tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z`
- **支出方法**：Script Path（使用 Bob 的私钥签名）

注意，这两笔交易使用**完全相同的 Taproot 地址**，证明它们确实来自同一个双叶脚本树！

## 代码演练：Commit 阶段——双叶脚本树构建

首先，让我们重建生成此 Taproot 地址的完整代码：

```python
def create_dual_leaf_taproot():
    """Build dual-leaf Taproot address containing Hash Lock and Bob Script"""
    setup('testnet')

    # Alice's internal key (Key Path controller)
    alice_private = PrivateKey('cRxebG1hY6vVgS9CSLNaEbEJaXkpZvc6nFeqqGT7v6gcW7MbzKNT')
    alice_public = alice_private.get_public_key()

    # Bob's key (Script Path 2 controller)
    bob_private = PrivateKey('cSNdLFDf3wjx1rswNL2jKykbVkC6o56o5nYZi4FUkWKjFn2Q5DSG')
    bob_public = bob_private.get_public_key()

    # Script 1: Hash Lock - verify preimage "helloworld"
    preimage = "helloworld"
    preimage_hash = hashlib.sha256(preimage.encode('utf-8')).hexdigest()
    hash_script = Script([
        'OP_SHA256',
        preimage_hash,  # 936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af
        'OP_EQUALVERIFY',
        'OP_TRUE'
    ])

    # Script 2: Bob Script - P2PK verify Bob's signature
    bob_script = Script([
        bob_public.to_x_only_hex(),  # 84b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5
        'OP_CHECKSIG'
    ])

    # Build dual-leaf script tree (flat structure)
    # 注意：第六章单叶用 [[script]]（嵌套列表），双叶用 [scriptA, scriptB]（扁平列表）。
    # get_taproot_address 对两种格式均支持：嵌套列表用于手动指定树结构，
    # 扁平列表则由库自动构建平衡 Merkle 树。
    all_leafs = [hash_script, bob_script]

    # Generate Taproot address
    taproot_address = alice_public.get_taproot_address(all_leafs)

    print(f"Dual-leaf Taproot address: {taproot_address.to_string()}")
    print(f"Hash Script: {hash_script}")
    print(f"Bob Script: {bob_script}")

    return taproot_address, hash_script, bob_script

# Actually generated address
# Output: tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z
```

**关键技术细节**：

1. **扁平结构**：`all_leafs = [hash_script, bob_script]` 表示两个脚本在同一级别
2. **索引顺序**：hash_script 是索引 0，bob_script 是索引 1
3. **地址一致性**：两个不同的 Script Path 支出使用相同地址证明脚本树构建正确

## 代码演练：Reveal 阶段——双叶脚本路径支出实现

掌握双叶脚本树构建原理后，让我们看看如何在 Reveal 阶段实现两个不同的 Script Path 支出。

### 哈希脚本路径支出核心代码

基于交易 `b61857a05852482c9d5ffbb8159fc2ba1efa3dd16fe4595f121fc35878a2e430` 实现：

```python
def hash_script_path_spending():
    """Hash Script Path spending - unlock using preimage"""
    setup('testnet')

    # Rebuild identical script tree
    alice_private = PrivateKey('cRxebG1hY6vVgS9CSLNaEbEJaXkpZvc6nFeqqGT7v6gcW7MbzKNT')
    alice_public = alice_private.get_public_key()

    bob_private = PrivateKey('cSNdLFDf3wjx1rswNL2jKykbVkC6o56o5nYZi4FUkWKjFn2Q5DSG')
    bob_public = bob_private.get_public_key()

    # Build same script tree
    preimage = "helloworld"
    preimage_hash = hashlib.sha256(preimage.encode('utf-8')).hexdigest()
    hash_script = Script(['OP_SHA256', preimage_hash, 'OP_EQUALVERIFY', 'OP_TRUE'])
    bob_script = Script([bob_public.to_x_only_hex(), 'OP_CHECKSIG'])

    all_leafs = [hash_script, bob_script]
    taproot_address = alice_public.get_taproot_address(all_leafs)

    # Build transaction
    txin = TxInput("f02c055369812944390ca6a232190ec0db83e4b1b623c452a269408bf8282d66", 0)
    txout = TxOutput(to_satoshis(0.00001034), alice_public.get_taproot_address().to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    # Key: Build Hash Script's Control Block (index 0)
    control_block = ControlBlock(
        alice_public,
        all_leafs,
        0,  # hash_script index
        is_odd=taproot_address.is_odd()
    )

    # Witness data: [preimage, script, control_block]
    preimage_hex = preimage.encode('utf-8').hex()
    tx.witnesses.append(TxWitnessInput([
        preimage_hex,
        hash_script.to_hex(),
        control_block.to_hex()
    ]))

    return tx
```

### Bob 脚本路径支出核心代码

基于交易 `185024daff64cea4c82f129aa9a8e97b4622899961452d1d144604e65a70cfe0` 实现：

```python
def bob_script_path_spending():
    """Bob Script Path spending - unlock using Bob's private key signature"""
    setup('testnet')

    # Same script tree construction
    alice_private = PrivateKey('cRxebG1hY6vVgS9CSLNaEbEJaXkpZvc6nFeqqGT7v6gcW7MbzKNT')
    alice_public = alice_private.get_public_key()

    bob_private = PrivateKey('cSNdLFDf3wjx1rswNL2jKykbVkC6o56o5nYZi4FUkWKjFn2Q5DSG')
    bob_public = bob_private.get_public_key()

    # Rebuild script tree
    preimage_hash = hashlib.sha256("helloworld".encode('utf-8')).hexdigest()
    hash_script = Script(['OP_SHA256', preimage_hash, 'OP_EQUALVERIFY', 'OP_TRUE'])
    bob_script = Script([bob_public.to_x_only_hex(), 'OP_CHECKSIG'])

    all_leafs = [hash_script, bob_script]
    taproot_address = alice_public.get_taproot_address(all_leafs)

    # Build transaction
    txin = TxInput("8caddfad76a5b3a8595a522e24305dc20580ca868ef733493e308ada084a050c", 1)
    txout = TxOutput(to_satoshis(0.00000900), bob_public.get_taproot_address().to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    # Key: Build Bob Script's Control Block (index 1)
    control_block = ControlBlock(
        alice_public,
        all_leafs,
        1,  # bob_script index
        is_odd=taproot_address.is_odd()
    )

    # Script Path signature — parameters differ from Key Path in Chapter 6
    sig = bob_private.sign_taproot_input(
        tx, 0,
        [taproot_address.to_script_pub_key()],
        [to_satoshis(0.00001111)],
        script_path=True,
        tapleaf_script=bob_script,  # 单数形式：指定正在执行的叶子脚本
        tweak=False                 # Script Path 使用原始私钥，不是调整后的
    )

    # Witness data: [signature, script, control_block]
    tx.witnesses.append(TxWitnessInput([
        sig,
        bob_script.to_hex(),
        control_block.to_hex()
    ]))

    return tx
```

**关键签名参数解析**：

Bob 的 `sign_taproot_input` 参数与第六章 Key Path 签名有两个本质区别：

- **`tapleaf_script=bob_script`（单数）vs 第六章的 `tapleaf_scripts=[tr_script]`（复数）**：Key Path 签名需要完整脚本树来计算 tweak（复数形式），而 Script Path 签名只需要指定**当前正在执行的那个叶子脚本**（单数形式），因为 BIP342 要求将 leaf hash 纳入签名消息的哈希计算中。

- **`tweak=False`**：这是两种路径的根本区别。Key Path 用**调整后的私钥** `d' = d + t` 签名，验证者用 output key 验证；Script Path 用**原始私钥** `d` 签名，安全性由控制块的 Merkle 证明和 sighash 中的 leaf hash 共同保证。

**关键技术对比**：

| Aspect | Hash Script Path | Bob Script Path |
|--------|------------------|-----------------|
| **Script Index** | 0 (first script) | 1 (second script) |
| **Input Data** | preimage hex | Schnorr signature |
| **Verification Method** | Hash matching | Digital signature verification |
| **Control Block** | Contains Bob Script's TapLeaf hash | Contains Hash Script's TapLeaf hash |

## 深入控制块分析

在双叶脚本树中，每个脚本的控制块包含其兄弟节点哈希作为 Merkle 证明。让我们分析实际链上数据：

### 哈希脚本路径控制块

**从交易 b61857a0... 提取的数据**：

```
Control Block: c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d32faaa677cb6ad6a74bf7025e4cd03d2a82c7fb8e3c277916d7751078105cf9df

Structure breakdown:
├─ c0: Leaf version (0xc0)
├─ 50be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3: Alice internal pubkey
└─ 2faaa677cb6ad6a74bf7025e4cd03d2a82c7fb8e3c277916d7751078105cf9df: Bob Script's TapLeaf hash
```

### Bob 脚本路径控制块

**从交易 185024da... 提取的数据**：

```
Control Block: c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3fe78d8523ce9603014b28739a51ef826f791aa17511e617af6dc96a8f10f659e

Structure breakdown:
├─ c0: Leaf version (0xc0)
├─ 50be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3: Alice internal pubkey (same!)
└─ fe78d8523ce9603014b28739a51ef826f791aa17511e617af6dc96a8f10f659e: Hash Script's TapLeaf hash
```

**重要观察**：

- 两个控制块使用**相同的内部公钥**
- Merkle 路径部分是**兄弟节点**TapLeaf 哈希
- 这正是 Merkle 树结构的体现！

### 控制块验证算法

验证控制块本质上意味着**地址重建验证**：

```python
# 概念演示：展示控制块验证和地址重建的完整逻辑。
# tagged_hash 定义见第六章；地址重建的椭圆曲线点运算
# 由 get_taproot_address() 内部封装，此处仅展示验证流程。
def verify_control_block_and_address_reconstruction():
    """Verify Control Block and reconstruct Taproot address"""

    # Hash Script Path data
    hash_control_block = "c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d32faaa677cb6ad6a74bf7025e4cd03d2a82c7fb8e3c277916d7751078105cf9df"
    hash_script_hex = "a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851"

    # Bob Script Path data
    bob_control_block = "c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3fe78d8523ce9603014b28739a51ef826f791aa17511e617af6dc96a8f10f659e"
    bob_script_hex = "2084b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5ac"

    # Parse Control Block structure
    def parse_control_block(cb_hex):
        cb_bytes = bytes.fromhex(cb_hex)
        leaf_version = cb_bytes[0] & 0xfe
        parity = cb_bytes[0] & 0x01
        internal_pubkey = cb_bytes[1:33]
        merkle_path = cb_bytes[33:]  # sibling node hash
        return leaf_version, parity, internal_pubkey, merkle_path

    # Parse Hash Script's Control Block
    hash_version, hash_parity, hash_internal_key, hash_sibling = parse_control_block(hash_control_block)

    # Parse Bob Script's Control Block
    bob_version, bob_parity, bob_internal_key, bob_sibling = parse_control_block(bob_control_block)

    print("Control Block verification:")
    print(f"✅ Internal pubkey consistent: {hash_internal_key == bob_internal_key}")
    print(f"✅ Alice internal pubkey: {hash_internal_key.hex()}")

    # Calculate respective TapLeaf hashes
    hash_tapleaf = tagged_hash("TapLeaf", bytes([hash_version]) + bytes([len(bytes.fromhex(hash_script_hex))]) + bytes.fromhex(hash_script_hex))
    bob_tapleaf = tagged_hash("TapLeaf", bytes([bob_version]) + bytes([len(bytes.fromhex(bob_script_hex))]) + bytes.fromhex(bob_script_hex))

    print(f"\nTapLeaf hash calculation:")
    print(f"✅ Hash Script TapLeaf: {hash_tapleaf.hex()}")
    print(f"✅ Bob Script TapLeaf:  {bob_tapleaf.hex()}")

    # Verify sibling node relationship
    print(f"\nSibling node verification:")
    print(f"✅ Hash Script's sibling is Bob TapLeaf: {hash_sibling.hex() == bob_tapleaf.hex()}")
    print(f"✅ Bob Script's sibling is Hash TapLeaf: {bob_sibling.hex() == hash_tapleaf.hex()}")

    # Calculate Merkle Root
    # Sort lexicographically then calculate TapBranch
    if hash_tapleaf < bob_tapleaf:
        merkle_root = tagged_hash("TapBranch", hash_tapleaf + bob_tapleaf)
    else:
        merkle_root = tagged_hash("TapBranch", bob_tapleaf + hash_tapleaf)

    print(f"\nMerkle Root calculation:")
    print(f"✅ Calculated Merkle Root: {merkle_root.hex()}")

    # Calculate output pubkey tweak
    tweak = tagged_hash("TapTweak", hash_internal_key + merkle_root)
    print(f"✅ Tweak value: {tweak.hex()}")

    # Address reconstruction (simplified concept display)
    target_address = "tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z"
    print(f"\nAddress verification:")
    print(f"✅ Target address: {target_address}")
    print(f"✅ Control Block valid: Can reconstruct same address")

    return True

verify_control_block_and_address_reconstruction()
```

## Script Path 1：哈希脚本执行分析

现在让我们详细分析哈希脚本路径的完整执行过程。基于交易 `b61857a0...` 的实际数据：

### 见证数据结构

```
Witness Stack:
[0] 68656c6c6f776f726c64                                                     (preimage_hex)
[1] a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851   (script_hex)
[2] c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d32faaa677cb6ad6a74bf7025e4cd03d2a82c7fb8e3c277916d7751078105cf9df (control_block)
```

### 脚本字节码解析

**哈希脚本**：`a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851`

```
Bytecode breakdown:
a8 = OP_SHA256
20 = OP_PUSHBYTES_32
936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af = SHA256("helloworld")
88 = OP_EQUALVERIFY
51 = OP_PUSHNUM_1 (OP_TRUE)
```

### 栈执行动画——哈希脚本路径

**执行脚本**：`OP_SHA256 OP_PUSHBYTES_32 936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af OP_EQUALVERIFY OP_PUSHNUM_1`

#### 0. 初始状态：加载脚本输入

```
│ 68656c6c6f776f726c64 (preimage_hex) │
└──────────────────────────────────────┘
```

**（原像"helloworld"的十六进制表示已在栈上）**

#### 1. OP_SHA256：计算栈顶元素的 SHA256 哈希

```
│ 936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af (computed_hash) │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

**（SHA256("helloworld") = 936a185c...07af）**

#### 2. OP_PUSHBYTES_32：推送预期哈希值

```
│ 936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af (expected_hash) │
│ 936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af (computed_hash) │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

**（栈顶现在有两个相同的哈希值）**

#### 3. OP_EQUALVERIFY：验证哈希相等

```
│ (empty_stack) │
└───────────────┘
```

**（验证成功：expected_hash == computed_hash，两个元素都被移除）**

#### 4. OP_PUSHNUM_1：推送成功标志

```
│ 01 (true_value) │
└─────────────────┘
```

**（脚本执行成功：栈顶是非零值）**

## Script Path 2：Bob 脚本执行分析

接下来，让我们分析 Bob 脚本路径的执行过程。基于交易 `185024da...` 的实际数据：

### 见证数据结构

```
Witness Stack:
[0] 26a0eadca0bba3d1bb6f82b8e1f76e2d84038c97a92fa95cc0b9f6a6a59bac5f9977d7cb33dbd188b1b84e6d5a9447231353590578f358b2f18a66731f9f1c5c (bob_signature)
[1] 2084b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5ac                                                               (script_hex)
[2] c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3fe78d8523ce9603014b28739a51ef826f791aa17511e617af6dc96a8f10f659e   (control_block)
```

### 脚本字节码解析

**Bob 脚本**：`2084b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5ac`

```
Bytecode breakdown:
20 = OP_PUSHBYTES_32
84b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5 = Bob's x-only pubkey
ac = OP_CHECKSIG
```

### 栈执行动画——Bob 脚本路径

**执行脚本**：`OP_PUSHBYTES_32 84b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5 OP_CHECKSIG`

#### 0. 初始状态：加载脚本输入

```
│ 26a0eadca0bba3d1bb6f82b8e1f76e2d84038c97a92fa95cc0b9f6a6a59bac5f9977d7cb33dbd188b1b84e6d5a9447231353590578f358b2f18a66731f9f1c5c (bob_signature) │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**（Bob 的 64 字节 Schnorr 签名已在栈上）**

#### 1. OP_PUSHBYTES_32：推送 Bob 的 x-only 公钥

```
│ 84b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5 (bob_pubkey)   │
│ 26a0eadca0bba3d1bb6f82b8e1f76e2d84038c97a92fa95cc0b9f6a6a59bac5f9977d7cb33dbd188b1b84e6d5a9447231353590578f358b2f18a66731f9f1c5c (bob_signature) │
└───────────────────────────────────────────────────────────────────────────────────┘
```

**（Bob 的 32 字节 x-only 公钥被推送到栈顶）**

#### 2. OP_CHECKSIG：验证 Schnorr 签名

```
│ 01 (signature_valid) │
└──────────────────────┘
```

**（签名验证成功：Bob 的私钥对应此公钥，签名对交易数据有效）**

**验证过程详情**：

1. 从栈弹出公钥：`84b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5`
2. 从栈弹出签名：`26a0eadca0bba3d1bb6f82b8e1f76e2d84038c97a92fa95cc0b9f6a6a59bac5f...`
3. 使用 BIP340 Schnorr 签名验证算法验证签名有效性
4. 验证成功，推送 1 表示 TRUE

## 双叶 vs 单叶：Merkle 计算差异

通过比较单叶和双叶实现，我们可以清楚地看到 Merkle 树计算的差异：

### 单叶脚本树

```
Merkle Root = TapLeaf Hash
            = Tagged_Hash("TapLeaf", 0xc0 + len(script) + script)
```

**特征**：

- 简单直接，TapLeaf 哈希作为 Merkle 根
- 控制块仅包含内部公钥，无 Merkle 路径
- 适用于简单的单条件验证场景

### 双叶脚本树

```
Merkle Root = TapBranch Hash
            = Tagged_Hash("TapBranch", sorted(TapLeaf_A, TapLeaf_B))

TapLeaf_A = Tagged_Hash("TapLeaf", 0xc0 + len(script_A) + script_A)
TapLeaf_B = Tagged_Hash("TapLeaf", 0xc0 + len(script_B) + script_B)
```

**特征**：

- 真正的 Merkle 树结构，需要 TapBranch 计算
- 字典序排序确保确定性结果
- 控制块包含兄弟节点哈希作为 Merkle 证明
- 支持复杂的多条件验证场景

### 控制块大小对比

| Script Tree Type | Control Block Size | Structure |
|------------------|-------------------|-----------|
| Single-leaf | 33 bytes | [version+parity] + [internal_pubkey] |
| Dual-leaf | 65 bytes | [version+parity] + [internal_pubkey] + [sibling_hash] |
| Four-leaf | 97 bytes | [version+parity] + [internal_pubkey] + [sibling_hash] + [parent_sibling_hash] |

随着脚本树深度增加，控制块线性增长，但仍比传统多重签名脚本高效得多。

## 编程最佳实践：构建双叶 Taproot 应用

基于前面的分析，让我们总结双叶 Taproot 应用的开发最佳实践：

### 1. 标准 Commit 阶段工作流

```python
def build_dual_leaf_taproot(alice_key, bob_key, preimage):
    # Build two different types of scripts
    hash_script = build_hash_lock_script(preimage)
    bob_script = build_bob_p2pk_script(bob_key)

    # Create script tree (index matters!)
    leafs = [hash_script, bob_script]  # Index 0 and 1

    # Generate Taproot address
    taproot_address = alice_key.get_taproot_address(leafs)

    return taproot_address, leafs
```

### 2. 通用 Script Path 支出模板

```python
def spend_script_path(script_index, input_data, leafs, internal_key, taproot_addr):
    # Build Control Block
    control_block = ControlBlock(
        internal_key,
        leafs,
        script_index,  # Key: specify which script to use
        is_odd=taproot_addr.is_odd()
    )

    # Build witness data (strict order!)
    witness = TxWitnessInput([
        *input_data,              # Inputs needed for script execution
        leafs[script_index].to_hex(),  # Script to execute
        control_block.to_hex()    # Merkle proof
    ])

    return witness
```

### 3. 常见错误和调试技巧

**脚本索引错误**：

```python
# ❌ Error: Control Block script index doesn't match actually used script
control_block = ControlBlock(..., leafs, 1, ...)  # Index 1
witness = [..., leafs[0].to_hex(), ...]           # But using index 0 script

# ✅ Correct: Ensure index consistency
script_index = 1
control_block = ControlBlock(..., leafs, script_index, ...)
witness = [..., leafs[script_index].to_hex(), ...]
```

**Merkle 路径验证失败**：

```python
# Debugging tip: Verify Control Block's sibling node hash
def debug_control_block(control_block_hex, script_hex, expected_sibling):
    cb = bytes.fromhex(control_block_hex)
    actual_sibling = cb[33:65]  # sibling node hash

    print(f"Expected sibling: {expected_sibling.hex()}")
    print(f"Actual sibling: {actual_sibling.hex()}")
    print(f"Match result: {actual_sibling == expected_sibling}")
```

## 性能和隐私对比分析

通过实际链上数据，我们可以定量分析不同支出方法的性能和隐私特征：

| Spending Method | Transaction Size | Witness Data | Computational Complexity | Privacy Level | Relative Fee Cost |
|-----------------|------------------|--------------|-------------------------|---------------|-------------------|
| **Key Path** | ~110 bytes | 64-byte signature | 1 signature verification | Complete privacy | Baseline (1.0x) |
| **Hash Script** | ~180 bytes | preimage+script+cb | Hash calculation+Merkle verification | Exposes Hash Lock | Medium (1.6x) |
| **Bob Script** | ~185 bytes | signature+script+cb | Signature verification+Merkle verification | Exposes P2PK structure | Medium (1.7x) |

**关键洞察**：

1. **Key Path 始终是最优选择**：无论脚本树复杂度如何，Key Path 具有最高效率和隐私
2. **Script Path 成本可控**：与传统复杂脚本相比，Taproot 的额外开销在可接受范围内
3. **选择性揭示的价值**：只有实际使用的路径被暴露，未使用的路径永远保持私有

## 章节总结

通过双叶脚本树的完整实现，我们掌握了 Taproot 多路径支出的关键技术：真正的 Merkle 树构建、包含兄弟节点证明的控制块，以及同一地址内不同脚本的协调机制。更重要的是，我们理解了 Taproot 的核心哲学——选择性揭示，只暴露使用的路径，在复杂功能和高隐私之间实现完美平衡。

在下一章中，我们将探索**多层嵌套脚本树**和**高级 Taproot 应用模式**，学习如何构建支持更多花费条件的企业级区块链应用，以及如何结合时间锁、多重签名和其他高级功能创建更复杂和实用的智能合约系统。

双叶脚本树是 Taproot 应用开发的重要里程碑——它们展示了如何在保持简单性的同时实现真正的功能复杂性。这就是 Bitcoin Taproot 技术的本质：**外观简单，内在强大**。

