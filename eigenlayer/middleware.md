# 深入解析 EigenLayer 的 Middleware 合约底层设计原理和源码

# 一. 概述

eigenlayer-contractsEigenLayer 是一组部署在以太坊上的智能合约，用于重新质押资产以保护称为 AVS（主动验证服务）的新服务。而 eigenlayer-middleware 是 Eigenlayer 的中间件合约部分，主要注册 operator 加入退出功能，在 eigenlayer-middleware 有以下这些重要的功能：

- 管理 BLS 聚合公钥，在 Operator 加入或者退出是更新 BLS 聚合公钥相关的信息，这个聚合公钥用于链下服务的签名验证。
- 管理 Operator 在 *quorum 中*的 index, Operator 加入给 Operator 分配 index, Operator 退出时更新对应的 index
- 管理 Operator 的质押历史，当 Operator 注册和退出注册时更新对应的质押份额
- 管理 Operator 通过 eigenlayer-contracts 合约中的 AVSDirectory 注册到 AVS 合约

# 二. eigenlayer-middleware 代码架构



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYRcBuaAAApAYD.png)



💡**BLSApkRegistry** 💡💡**registerBLSPublicKey**: 注册一个BLS公钥，确保该公钥未被注册过。该函数通过验证签名（证明操作员拥有公钥的所有权）来防止伪造公钥注册。具体的验证过程涉及配对检查和gamma值的计算，以确保公钥和签名匹配。 💡💡**registerOperator**: 注册操作员的公钥到指定的仲裁组（quorum）。每个仲裁组的编号是一个8位的整数（byte）。该函数通过从操作员处获取其已注册的公钥并更新每个仲裁组的聚合公钥来完成注册。此函数仅限RegistryCoordinator调用。 💡💡**deregisterOperator**: 撤销操作员在指定仲裁组中的注册，将其公钥从这些仲裁组的聚合公钥中移除。

💡**IndexRegistry** 💡💡**registerOperator** 函数用于将操作员注册到一个或多个指定的仲裁组中。该操作仅限于 RegistryCoordinator 执行。注册过程中，合约会验证仲裁组是否存在，并为该操作员分配一个新的操作员索引，维护操作员的历史记录，并返回每个仲裁组中操作员的数量。 💡💡**deregisterOperator** 函数用于从仲裁组中注销操作员，方法是将指定的操作员从其对应的操作员索引中移除，并将最后一个操作员填补空缺的位置，同时更新仲裁组的操作员数量。

💡**StakeRegistry** 💡💡**registerOperator** 函数允许将一个操作员注册到多个 quorum（投票组）中。在此过程中，合约会验证操作员的股份是否满足每个 quorum 的最小股份要求。如果满足要求，则更新该操作员在 quorum 中的股份并返回更新后的数据。 💡💡**deregisterOperator** 函数允许将操作员从指定的 quorum 中撤销。它会更新操作员在每个 quorum 中的股份，并对总股份进行相应的调整。

💡**ServiceManagerBase** 💡💡**registerOperatorToAVS**: 将操作员注册到 AVS 目录。只有 RegistryCoordinator 可以调用此函数。它将操作员地址和签名信息传递给 _avsDirectory 来进行注册 💡💡**deregisterOperatorFromAVS**: 将操作员从 AVS 目录中注销。仅允许 RegistryCoordinator 调用此函数。

💡**RegistryCoordinator** 💡💡**blsApkRegistry.registerOperator、stakeRegistry.registerOperator 和 indexRegistry.registerOperator** 用于将操作员注册到多个注册表中。 💡💡**blsApkRegistry.deregisterOperator、stakeRegistry.deregisterOperator 和 indexRegistry.deregisterOperator** 用于从注册表中注销操作员。

# 三. middleware 功能模块介绍

## 1.**IndexRegistry 核心功能**

IndexRegistry 合约是一个操作员管理系统，主要用于管理多个 quorum 的操作员注册、注销与索引的更新。它记录了每个操作员在每个 quorum 中的状态变化，并支持基于区块高度查询历史状态。这种设计可以实现对操作员管理的高效跟踪，同时支持基于历史数据进行查询，确保操作员信息的一致性和准确性。

**1.1.Index 注册流程**



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYRnCta8AA9xkZ.png)



**1.2.Index 退出注册流程**



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYRqfTacAEQ2oJ.png)



**1.3 IndexRegistry 代码核心功能**

1.3.1.**操作员注册 (registerOperator)**

- 该函数由 RegistryCoordinator 调用，用于将一个操作员注册到指定的多个 quorum（仲裁组）中。
- 需要传入操作员 ID (operatorId) 和 quorumNumbers（指定的多个 quorum 编号）。
- 对每个 quorum，合约会检查其是否存在，然后增加该 quorum 的操作员数量，并将操作员分配到当前 quorum 中的最后一个空位。
- 最后，函数返回每个 quorum 中操作员的数量。

**1.3.2.操作员注销 (deregisterOperator)**

- 该函数也是由 RegistryCoordinator 调用，用于注销操作员在指定的 quorumNumbers 中的注册。
- 对每个 quorum，合约会检查其存在性，并找出该操作员在每个 quorum 中的索引。
- 然后减少该 quorum 的操作员数量，将最后一个操作员移到被注销操作员的位置，并更新操作员的索引。

**1.3.3.初始化 quorum (initializeQuorum)**

- 该函数用于初始化一个新的 quorum，设置该 quorum 的初始状态。
- 通过 push 一个 QuorumUpdate 记录，标记该 quorum 从当前区块开始的操作员数量为 0。

**1.3.4.增加与减少操作员数量**

- **_increaseOperatorCount**：增加指定 quorum 的操作员数量，并更新其历史记录。
- **_decreaseOperatorCount**：减少指定 quorum 的操作员数量，并更新其历史记录。

**1.3.5.操作员索引管理**

- **_assignOperatorToIndex**：为操作员分配一个新的索引，并更新该索引的历史记录。
- **_popLastOperator**：从某个 quorum 中移除最后一个操作员，确保其索引被正确更新。
- **_updateOperatorIndexHistory**：更新某个操作员索引的历史记录。

**1.3.6.历史记录**

- _operatorCountHistory：记录每个 quorum 中操作员数量的变化。
- _operatorIndexHistory：记录每个 quorum 中每个操作员索引的变化。
- QuorumUpdate 和 OperatorUpdate 是用于存储操作员数量和索引变动的结构体。

## 2.BLSApkRegistry 核心功能

该合约的主要功能是处理与 BLS 公钥相关的操作，包括操作员的公钥注册、法定人数的管理、聚合公钥的更新和查询等。这是一个典型的加密共识或门限签名系统的一部分，确保多个操作员能够共同控制一个公钥，并且能够追踪和验证公钥的历史更新。通过这种方式，合约提供了一种可靠的机制来管理操作员和法定人数之间的公钥变更。

**2.1.registerBLSPublicKey流程**



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYR5-sasAEmD0P.png)



**2.2.deregisterOperator流程**



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYR9pMasAAcvto.png)



**2.3.合约核心功能**

- Apk（聚合公钥）： 每个法定人数的聚合公钥，在操作员被添加或移除时会更新。
- BN254： 使用的椭圆曲线，用于 BLS 签名。
- Quorum（法定人数）： 一组操作员共享的聚合公钥。

**2.3.1.注册管理：**

- **registerOperator:** 为指定的操作员注册 BLS 公钥，并将该公钥关联到指定的法定人数（quorum），同时更新每个法定人数的聚合公钥。
- **deregisterOperator:** 从指定的法定人数中注销操作员的 BLS 公钥，更新相关法定人数的聚合公钥。
- **initializeQuorum:** 初始化一个新的法定人数，添加其首个 APK 更新。

**2.3.2.公钥注册：**

- **registerBLSPublicKey:** 注册一个操作员的 BLS 公钥，确保通过签名验证公钥的合法性，并将公钥与操作员的地址关联。

**2.3.3.内部函数：**

- **_processQuorumApkUpdate:** 当操作员被添加或删除时，更新每个法定人数的聚合 APK（聚合公钥）。

**2.3.4.查询函数：**

- **getRegisteredPubkey:** 返回操作员的公钥和公钥哈希。
- **getApkIndicesAtBlockNumber:** 获取指定区块号时的 APK 更新索引。
- **getApk:** 返回某个法定人数当前的 APK。
- **getApkUpdateAtIndex:** 返回指定索引的 APK 更新。
- **getApkHashAtBlockNumberAndIndex:** 获取指定区块号和索引下的 APK 哈希。
- **getApkHistoryLength:** 返回某个法定人数 APK 更新的数量。
- **getOperatorFromPubkeyHash:** 根据公钥哈希获取操作员的地址。
- **getOperatorId:** 返回操作员的唯一标识符（即其公钥哈希）。

**2.3.5.安全性考虑：**

- **签名验证：** registerBLSPublicKey 函数通过加密操作验证公钥注册的有效性，确保操作员确实拥有该公钥。
- **状态检查：** 多个验证逻辑确保法定人数操作的有效性，例如确保法定人数已经存在并且操作员的公钥是唯一的。

## 3.StakeRegistry 核心功能

该 StakeRegistry 合约是一个质押管理系统，能够管理多个 quorum 中操作员的质押情况。它确保操作员的质押符合最低要求，并允许动态调整质押策略和规则。通过质押历史记录和事件机制，该系统确保了操作的透明性和可追溯性。

**关键概念**

- 操作员质押：操作员是法定人数中的实体，他们有质押（或权重）在法定人数中，通常用于确定他们在法定人数的决策或验证中的影响力。
- 法定人数（Quorum）：由多个操作员组成的一个群体，设有最小质押要求才能参与法定人数的活动。法定人数可用于去中心化治理模型，其中需要法定人数的确认或同意来达成决策。
- 策略乘数（Strategy Multipliers）：操作员质押的权重可能会被与不同策略关联的乘数调整。这些乘数决定了一个特定操作员的质押在法定人数决策中的影响力。
- 质押历史：质押历史记录对于理解操作员在法定人数中参与的演变至关重要。该合约允许查询在特定区块号下，操作员和法定人数的历史质押值。

**3.1. 注册流程**



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYSLfIakAAxi-Z.png)



**3.2.退出流程**



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYSOz1bQAAHJ_y.png)



**3.3. 核心功能**

**3.3.1.注册操作员：**

- registerOperator 函数允许注册操作员到一个或多个 quorum 中。每个操作员需要满足某个 quorum 的最低质押要求。
- 注册时，首先检查操作员是否已达到 quorum 的最低质押要求，如果没有，注册会失败。

**3.3.2.注销操作员：**

- deregisterOperator 函数允许注销操作员在一个或多个 quorum 中的注册，注销会更新该操作员在 quorum 中的质押，并减少该 quorum 的总质押。

**3.3.3.更新操作员质押：**

- updateOperatorStake 函数允许更新操作员在指定 quorum 中的质押。如果操作员的质押低于某个 quorum 的最低要求，该操作员会被标记为需要从该 quorum 中移除。

**3.3.4.管理 quorum：**

- initializeQuorum 函数用于初始化一个新的 quorum，并为其设置最低质押和策略。
- setMinimumStakeForQuorum 函数允许更新特定 quorum 的最低质押要求。
- addStrategies 和 removeStrategies 函数允许为 quorum 添加或移除策略。
- _weightOfOperatorForQuorum：计算特定法定人数中操作员的质押权重，考虑到操作员在每个策略下的份额，并乘以对应的乘数（来自strategyParams）。返回加权和，并检查操作员的质押是否满足法定人数的最小质押要求。
- _quorumExists：检查法定人数是否已初始化（即是否有质押历史）。
- weightOfOperatorForQuorum：用于获取操作员在特定法定人数下的质押总权重。如果法定人数不存在，则会回退。
- strategyParamsLength：返回特定法定人数下策略的数量，表示在加权计算中考虑了多少个策略。
- strategyParamsByIndex：返回指定法定人数下，给定索引位置的策略参数。

**3.3.5.记录质押变更：**

- 每次操作员的质押更新时，都会记录质押的历史数据，确保在任何时刻都能查询到某个操作员在特定 quorum 中的质押变动。

## 4.ServiceManagerBase 核心功能

管理和操作与EigenLayer AVS（自动验证服务）相关的功能。

**4.1.AVS 注册流程**



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYScZAasAMtCkw.png)



**4.2.AVS 退出注册流程**



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYSf4YasAAgRPL.png)



**4.3.关键功能**

- **合约初始化和所有权管理：**使用OwnableUpgradeable来管理合约的所有权，可以通过_transferOwnership函数将合约的所有权转交给指定地址。
- **注册协调器访问控制：**onlyRegistryCoordinator修饰符限制了只有RegistryCoordinator可以调用某些函数，确保操作员的注册和注销过程只能由合法方执行。
- **AVS元数据更新：**updateAVSMetadataURI：用于更新AVS的元数据URI，这可以用于更改关于AVS的额外信息。
- **操作员注册与注销** registerOperatorToAVS：将操作员注册到AVS目录。 deregisterOperatorFromAVS：将操作员从AVS目录注销。
- **获取质押策略** getRestakeableStrategies：返回AVS支持的所有可再质押策略。 getOperatorRestakedStrategies：返回某个操作员在AVS上可能已再质押的策略列表。
- **AVS目录地址：**avsDirectory：返回AVS目录的合约地址。

**4.4.核心功能详细解析**

- **getRestakeableStrategies**：此函数通过遍历RegistryCoordinator的法定人数，结合每个法定人数中在StakeRegistry中定义的策略，返回支持再质押的所有策略地址。
- **getOperatorRestakedStrategies**：此函数用于返回某个操作员在AVS中可能已再质押的所有策略。它通过操作员的位图来查找操作员参与的法定人数和策略。
- **位图操作**：位图（bitmap）用于跟踪操作员在各个法定人数中的参与情况。通过位图，可以高效地存储和处理操作员的参与信息。

## **5. RegistryCoordinator 核心功能**

**5.1.注册操作员**

- 操作员可以通过 registerOperator 方法为一个或多个 quorum 注册。每个 quorum 有其最大操作员数量，注册后会检查操作员数量是否超过上限。如果超过上限，需要通过 registerOperatorWithChurn 方法进行“换人”操作。
- 注册时，合约会验证操作员的公钥，并进行签名验证。

**5.2.更新操作员的状态**

- 合约支持通过 updateOperators 和 updateOperatorsForQuorum 来批量更新操作员在各个 quorum 中的状态和权益。
- updateSocket 方法允许操作员更新其 socket 地址。

**5.3.驱逐操作员**

- 合约的 ejectOperator 方法允许指定的 “ejector” 强制驱逐某个操作员。

**5.4.创建和配置 quorum**

- 合约支持创建新的 quorum，并且可以通过 createQuorum 方法指定其最大操作员数量、最小质押要求以及其他配置。
- 对于已经存在的 quorum，可以通过 setOperatorSetParams 更新其配置。

**5.5.几个核心函数**

**_getOrCreateOperatorId：**该函数用于检查是否已为操作员生成了operatorId，如果没有，则通过注册 BLS 公钥生成并返回一个新的 operatorId。

**_validateChurn：**该函数用于验证新加入的操作员是否有资格替换现有操作员。检查条件包括：

- 新操作员的抵押金额必须高于现有操作员的某个比例（由 kickBIPsOfOperatorStake 配置）。
- 现有操作员的抵押金额必须低于某个比例（由 kickBIPsOfTotalStake 配置）。

**_deregisterOperator：**该函数用于注销操作员，并更新操作员的相关注册信息。它会从 BLS、Stake 和 Index 注册中注销操作员，并更新其状态。

**_updateOperator：**用于更新操作员的抵押信息。如果操作员的抵押金额低于最低要求，它会注销该操作员。

- **_individualKickThreshold 和 _totalKickThreshold：**这两个函数分别计算单个操作员的退出门槛和所有操作员总抵押的退出门槛。
- **_verifyChurnApproverSignature：**验证操作员更替批准者的签名，并检查盐值是否已被使用以及签名是否过期。
- **_createQuorum：**用于创建并初始化一个新的 quorum（法定人数）。它设置了该 quorum 的最大操作员数量和相应的抵押参数。
- **_updateOperatorBitmap 和 _currentOperatorBitmap：**用于更新和查询操作员的 quorum 位图，跟踪该操作员当前参与的 quorum。
- **getOperatorSetParams, getOperator, getOperatorId 等函数：**这些是用于查询操作员信息、操作员 ID、状态和 quorum 位图的公共视图函数。
- **calculateOperatorChurnApprovalDigestHash 和 pubkeyRegistrationMessageHash：**用于计算特定消息的哈希，分别用于操作员更替批准和 BLS 公钥注册。

## 6.EigenDA 验证流程

EigenDAServiceManager 合约是用于与 EigenDA（数据可用性）协议进行交互的核心合约。它主要用于提交数据可用性证书、检查聚合签名的有效性，并确保一个仲裁小组确认了一批数据。下面数据校验的整个过程：



![](https://github.com/mars-yklzz/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GZYSpWRbkAAbQlc.png)



**confirmBatch 关键逻辑：**

- 仲裁小组验证：检查批次的仲裁小组签名，确保它们符合必要的阈值。
- 签名验证：使用 BLSSignatureChecker 工具验证批次头的签名。
- 元数据存储：确认成功后，批次的元数据哈希会被存储，并与批次 ID 关联。
- 事件触发：批次确认成功后，会触发 BatchConfirmed 事件。

# 四.总结

本文全面阐述了 **EigenLayer** 中间件合约（**eigenlayer-middleware**）的架构及其核心功能。它详细介绍了多个关键模块，包括 **BLSApkRegistry**、**IndexRegistry**、**StakeRegistry**、**ServiceManagerBase** 和 **RegistryCoordinator**，并且解析了如何管理 Operator、质押、BLS 公钥以及 Operator 在法定人数（quorum）中的动态管理。

下面是这些模块的一些主要功能和流程的总结：

- BLSApkRegistry 核心功能：**BLSApkRegistry** 负责管理操作员的 **BLS 公钥**，这是与链下服务交互的关键部分，确保合法操作员的公钥可以被注册和注销。 **registerBLSPublicKey**: 注册并验证操作员的 BLS 公钥，确保该公钥未被重复使用，并使用椭圆曲线 **BN254** 进行签名验证。 **deregisterOperator**: 从指定的法定人数中移除操作员，并更新法定人数的聚合公钥。
- IndexRegistry 核心功能：**IndexRegistry** 负责操作员在 **quorum** 中的注册和索引管理 **registerOperator**: 为操作员分配索引，并将其注册到指定的 quorum 中，同时更新操作员数量和索引历史记录。 **deregisterOperator**: 注销操作员并更新 quorum 中的索引。 **initializeQuorum**: 初始化新的 quorum 并设置其状态。
- StakeRegistry 核心功能：**StakeRegistry** 管理操作员的质押情况，确保其在 quorum 中的质押符合最低要求。 **registerOperator**: 检查并注册符合质押要求的操作员。 **deregisterOperator**: 注销操作员并调整其质押。 **updateOperatorStake**: 动态更新操作员质押，并确保其符合最低质押要求。
- ServiceManagerBase 核心功能：**ServiceManagerBase** 管理操作员与 **EigenLayer AVS**（主动验证服务）的交互。 **registerOperatorToAVS**: 将操作员注册到 AVS 目录。 **deregisterOperatorFromAVS**: 注销操作员。 **getRestakeableStrategies**: 获取支持再质押的策略。
- RegistryCoordinator 核心功能：**RegistryCoordinator** 作为中间件核心的协调者，管理所有注册、注销和 quorum 配置功能。它负责批量更新操作员状态，配置 quorum，注册或驱逐操作员。
- EigenDA 验证流程：**EigenDAServiceManager** 负责与 EigenDA（数据可用性协议）的交互。其核心功能是提交数据可用性证书、验证签名，并确保仲裁小组批准的数据批次。

通过这一系列功能，**EigenLayer** 中间件为操作员提供了强大的管理能力，涵盖了公钥注册、质押管理、历史查询等多个方面，确保系统的透明性、有效性与安全性。