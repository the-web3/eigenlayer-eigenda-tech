# 深入解析 EigenLayer 底层设计原理和源码

# 一. EigenLayer 的代码架构

![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtp5-DbUAA5bgG.jpg)

# 二. EigenLayer 的功能模块

## 1.注册成为 Operator

![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtqeykaIAAM-Hi.png)

- Operator 调用 registerAsOperator 的方法称为节点运营商
  - 将 operator 自己绑定成为了 staker
  - 将 operator  自质押的份额 delegate 给自己

## 2.Staking 流程

![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtrAaHbQAAx4Hk.jpg)

流程一： ETH 质押

- Staker 调用 EigenPodManager 创建一个 Pod, 可以不做，质押的时候会去判断是否已经创建了 pod
- Staker 调用 stake 方法把钱打入到对应的 Pod 里面去
- Staker 调用 verifyWithdrawalCredentials 验证信标链的状态跟，通过 EIP-4788 来获取信标链最新的区块投
- 若 stake 以前 Delegate 过，直接把质押产生的 shares 加给对应的 Operator, 若没有 delegate 过，直接调用 delegateTo 将质押份额 Delegate 给对应的 operator



流程二：ERC20 Token 质押(stETH, mETH, swETH, dETH(DappLink deth))

- Staker 调用 depositIntoStrategy 将 ERC20 Token 质押到对应代币策略
- 若 stake 以前 Delegate 过，直接把质押产生的 shares 加给对应的 Operator, 若没有 delegate 过，直接调用 delegateTo 将质押份额 Delegate 给对应的 operator

## 3.Delegate 流程

![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtrIlKbAAAMmCb.jpg)

## 4.排队取款

![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtrMpIaYAAJcwF.jpg)





## 5.完成排队

![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtrQv9a8AAJbx0.jpg)
  

## 6. Staker 从信标链（EigenLayer）



![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtrU2lbsAA_XKn.jpg)



# 三.EigenLayer 的源码解析

## 1.注册成为 Operator 源码解析

![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtrgwwaIAEXUpR.png)

```
function registerAsOperator(
    OperatorDetails calldata registeringOperatorDetails,
    string calldata metadataURI
) external {
    require(
        _operatorDetails[msg.sender].earningsReceiver == address(0),
        "DelegationManager.registerAsOperator: operator has already registered"
    );
    _setOperatorDetails(msg.sender, registeringOperatorDetails);
    SignatureWithExpiry memory emptySignatureAndExpiry;
    // delegate from the operator to themselves
    _delegate(msg.sender, msg.sender, emptySignatureAndExpiry, bytes32(0));
    // emit events
    emit OperatorRegistered(msg.sender, registeringOperatorDetails);
    emit OperatorMetadataURIUpdated(msg.sender, metadataURI);
}
```

- Operator 调用 registerAsOperator 信息，传入包含 OperatorDetails 和 metadataURI 数据
- 调用 _delegate 方法把自己和自己，即自己即是 Operator, 也是 staker
- 抛出 OperatorRegistered 和 OperatorMetadataURIUpdated 事件

```
function _delegate(
    address staker,
    address operator,
    SignatureWithExpiry memory approverSignatureAndExpiry,
    bytes32 approverSalt
) internal onlyWhenNotPaused(PAUSED_NEW_DELEGATION) {
    require(!isDelegated(staker), "DelegationManager._delegate: staker is already actively delegated");
    require(isOperator(operator), "DelegationManager._delegate: operator is not registered in EigenLayer");

    address _delegationApprover = _operatorDetails[operator].delegationApprover;
  
    if (_delegationApprover != address(0) && msg.sender != _delegationApprover && msg.sender != operator) {
       
        require(
            approverSignatureAndExpiry.expiry >= block.timestamp,
            "DelegationManager._delegate: approver signature expired"
        );

        require(
            !delegationApproverSaltIsSpent[_delegationApprover][approverSalt],
            "DelegationManager._delegate: approverSalt already spent"
        );
        delegationApproverSaltIsSpent[_delegationApprover][approverSalt] = true;


        bytes32 approverDigestHash = calculateDelegationApprovalDigestHash(
            staker,
            operator,
            _delegationApprover,
            approverSalt,
            approverSignatureAndExpiry.expiry
        );


        EIP1271SignatureUtils.checkSignature_EIP1271(
            _delegationApprover,
            approverDigestHash,
            approverSignatureAndExpiry.signature
        );
    }

    delegatedTo[staker] = operator;
    emit StakerDelegated(staker, operator);

    (IStrategy[] memory strategies, uint256[] memory shares)
        = getDelegatableShares(staker);

    for (uint256 i = 0; i < strategies.length;) {
        _increaseOperatorShares({
            operator: operator,
            staker: staker,
            strategy: strategies[i],
            shares: shares[i]
        });

        unchecked { ++i; }
    }
}
```

- delegatedTo[staker] = operator 这句代码是将 Operator 和 staker 进行绑定，当 operator 调用的时候， staker 和 operator 都是同一个，所以我们说 operator 既是 Operator, 也是 staker;
- 调用 getDelegatableShares 方法，获取到 staker 在对应策略里面质押份额，通过 _increaseOperatorShares 把对应的质押 shares 加给了 operator;

```
function getDelegatableShares(address staker) public view returns (IStrategy[] memory, uint256[] memory) {
    // Get currently active shares and strategies for `staker`
    int256 podShares = eigenPodManager.podOwnerShares(staker);
    (IStrategy[] memory strategyManagerStrats, uint256[] memory strategyManagerShares) 
        = strategyManager.getDeposits(staker);

    // Has no shares in EigenPodManager, but potentially some in StrategyManager
    if (podShares <= 0) {
        return (strategyManagerStrats, strategyManagerShares);
    }

    IStrategy[] memory strategies;
    uint256[] memory shares;

    if (strategyManagerStrats.length == 0) {
        // Has shares in EigenPodManager, but not in StrategyManager
        strategies = new IStrategy[](1);
        shares = new uint256[](1);
        strategies[0] = beaconChainETHStrategy;
        shares[0] = uint256(podShares);
    } else {
        // Has shares in both
        
        // 1. Allocate return arrays
        strategies = new IStrategy[](strategyManagerStrats.length + 1);
        shares = new uint256[](strategies.length);
        
        // 2. Place StrategyManager strats/shares in return arrays
        for (uint256 i = 0; i < strategyManagerStrats.length; ) {
            strategies[i] = strategyManagerStrats[i];
            shares[i] = strategyManagerShares[i];

            unchecked { ++i; }
        }

        // 3. Place EigenPodManager strat/shares in return arrays
        strategies[strategies.length - 1] = beaconChainETHStrategy;
        shares[strategies.length - 1] = uint256(podShares);
    }

    return (strategies, shares);
}
```

- 如果你在 EigenPod 的策略里面没有质押，那直接返回对应的非 eigenPod 策略的 strategyManagerStrats 和 strategyManagerShares
- 如果你在  EigenPod 的策略里面有质押 若在非 eigenPod 策略没有质押，将 beaconChainETHStrategy 策略及其 podShares 做为 strategies 和 shares 数组的第一项，直接返回去 若在非 eigenPod 策略有质押，把 beaconChainETHStrategy 和其 share 做为数组的最后一项返回去

```
function _increaseOperatorShares(address operator, address staker, IStrategy strategy, uint256 shares) internal {
    operatorShares[operator][strategy] += shares;
    emit OperatorSharesIncreased(operator, staker, strategy, shares);
}
```

- operatorShares[operator][strategy] += shares; 直接把策略里面对应的 shares 加给 operator

## 2.Strategies 管理流程源码解析

![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtsDSuacAA_7TL.jpg)

```
function addStrategiesToDepositWhitelist(
    IStrategy[] calldata strategiesToWhitelist,
    bool[] calldata thirdPartyTransfersForbiddenValues
) external onlyStrategyWhitelister {
    require(
        strategiesToWhitelist.length == thirdPartyTransfersForbiddenValues.length,
        "StrategyManager.addStrategiesToDepositWhitelist: array lengths do not match"
    );
    uint256 strategiesToWhitelistLength = strategiesToWhitelist.length;
    for (uint256 i = 0; i < strategiesToWhitelistLength; ) {
        // change storage and emit event only if strategy is not already in whitelist
        if (!strategyIsWhitelistedForDeposit[strategiesToWhitelist[i]]) {
            strategyIsWhitelistedForDeposit[strategiesToWhitelist[i]] = true;
            emit StrategyAddedToDepositWhitelist(strategiesToWhitelist[i]);
            _setThirdPartyTransfersForbidden(strategiesToWhitelist[i], thirdPartyTransfersForbiddenValues[i]);
        }
        unchecked {
            ++i;
        }
    }
}
```

- 参数是 Strategy 数组strategiesToWhitelist和第三方转账限制数组 thirdPartyTransfersForbiddenValues
- 将策略放到 strategyIsWhitelistedForDeposit Map 里面，并开启可质押权限
- 抛出 StrategyAddedToDepositWhitelist 事件



```text
function removeStrategiesFromDepositWhitelist(
    IStrategy[] calldata strategiesToRemoveFromWhitelist
) external onlyStrategyWhitelister {
    uint256 strategiesToRemoveFromWhitelistLength = strategiesToRemoveFromWhitelist.length;
    for (uint256 i = 0; i < strategiesToRemoveFromWhitelistLength; ) {
        // change storage and emit event only if strategy is already in whitelist
        if (strategyIsWhitelistedForDeposit[strategiesToRemoveFromWhitelist[i]]) {
            strategyIsWhitelistedForDeposit[strategiesToRemoveFromWhitelist[i]] = false;
            emit StrategyRemovedFromDepositWhitelist(strategiesToRemoveFromWhitelist[i]);
            // Set mapping value to default false value
            _setThirdPartyTransfersForbidden(strategiesToRemoveFromWhitelist[i], false);
        }
        unchecked {
            ++i;
        }
    }
}
```

- 将绑定关系的的策略的 value 置成 false, 这样这个策略就不能再接收 staker 的质押

## 3.质押流程源码解析

**3.1.ETH 质押**



![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtsQGTawAArbzn.png)





```text
function stake(
    bytes calldata pubkey,
    bytes calldata signature,
    bytes32 depositDataRoot
) external payable onlyWhenNotPaused(PAUSED_NEW_EIGENPODS) {
    IEigenPod pod = ownerToPod[msg.sender];
    if (address(pod) == address(0)) {
        //deploy a pod if the sender doesn't have one already
        pod = _deployPod();
    }
    pod.stake{value: msg.value}(pubkey, signature, depositDataRoot);
}
```

- 判断 pod 是否已经创建，如果没有创建，使用 create2 方式创建 pod
- Pod 创建完成之后，把对应的 ETH 质押到 pod 里面去



```text
function stake(
    bytes calldata pubkey,
    bytes calldata signature,
    bytes32 depositDataRoot
) external payable onlyEigenPodManager {
    // stake on ethpos
    require(msg.value == 32 ether, "EigenPod.stake: must initially stake for any validator with 32 ether");
    ethPOS.deposit{value: 32 ether}(pubkey, _podWithdrawalCredentials(), signature, depositDataRoot);
    emit EigenPodStaked(pubkey);
}
```

- 判断质押者是否有 32 个 ETH，如果有的话，将 32 个 ETH 打入到信标链合约



```text
function verifyWithdrawalCredentials(
    uint64 beaconTimestamp,
    BeaconChainProofs.StateRootProof calldata stateRootProof,
    uint40[] calldata validatorIndices,
    bytes[] calldata validatorFieldsProofs,
    bytes32[][] calldata validatorFields
) external onlyOwnerOrProofSubmitter onlyWhenNotPaused(PAUSED_EIGENPODS_VERIFY_CREDENTIALS) {
    require(
        (validatorIndices.length == validatorFieldsProofs.length)
            && (validatorFieldsProofs.length == validatorFields.length),
        "EigenPod.verifyWithdrawalCredentials: validatorIndices and proofs must be same length"
    );

    // Calling this method using a `beaconTimestamp` <= `currentCheckpointTimestamp` would allow
    // a newly-verified validator to be submitted to `verifyCheckpointProofs`, making progress
    // on an existing checkpoint.
    require(
        beaconTimestamp > currentCheckpointTimestamp,
        "EigenPod.verifyWithdrawalCredentials: specified timestamp is too far in past"
    );

    // Verify passed-in `beaconStateRoot` against the beacon block root
    // forgefmt: disable-next-item
    BeaconChainProofs.verifyStateRoot({
        beaconBlockRoot: getParentBlockRoot(beaconTimestamp),
        proof: stateRootProof
    });

    uint256 totalAmountToBeRestakedWei;
    for (uint256 i = 0; i < validatorIndices.length; i++) {
        // forgefmt: disable-next-item
        totalAmountToBeRestakedWei += _verifyWithdrawalCredentials(
            stateRootProof.beaconStateRoot,
            validatorIndices[i],
            validatorFieldsProofs[i],
            validatorFields[i]
        );
    }

    eigenPodManager.recordBeaconChainETHBalanceUpdate(podOwner, int256(totalAmountToBeRestakedWei));
}
```

- 验证信标链的 stateRootProof
- 验证 WithdrawalCredentials 并返回对应的资金数量
- 调用 recordBeaconChainETHBalanceUpdate 方法更新合约中的 Balance 信息，同时调度 DelegationManager 的方法完成质押 Share 分配对应质押者委托 Operator



```text
function recordBeaconChainETHBalanceUpdate(
    address podOwner,
    int256 sharesDelta
) external onlyEigenPod(podOwner) nonReentrant {
    require(
        podOwner != address(0), "EigenPodManager.recordBeaconChainETHBalanceUpdate: podOwner cannot be zero address"
    );
    require(
        sharesDelta % int256(GWEI_TO_WEI) == 0,
        "EigenPodManager.recordBeaconChainETHBalanceUpdate: sharesDelta must be a whole Gwei amount"
    );
    int256 currentPodOwnerShares = podOwnerShares[podOwner];
    int256 updatedPodOwnerShares = currentPodOwnerShares + sharesDelta;
    podOwnerShares[podOwner] = updatedPodOwnerShares;

    // inform the DelegationManager of the change in delegateable shares
    int256 changeInDelegatableShares = _calculateChangeInDelegatableShares({
        sharesBefore: currentPodOwnerShares,
        sharesAfter: updatedPodOwnerShares
    });
    // skip making a call to the DelegationManager if there is no change in delegateable shares
    if (changeInDelegatableShares != 0) {
        if (changeInDelegatableShares < 0) {
            delegationManager.decreaseDelegatedShares({
                staker: podOwner,
                strategy: beaconChainETHStrategy,
                shares: uint256(-changeInDelegatableShares)
            });
        } else {
            delegationManager.increaseDelegatedShares({
                staker: podOwner,
                strategy: beaconChainETHStrategy,
                shares: uint256(changeInDelegatableShares)
            });
        }
    }
    emit PodSharesUpdated(podOwner, sharesDelta);
    emit NewTotalShares(podOwner, updatedPodOwnerShares);
}
```

- 更新对应质押 shares
- 调用 DelegationManager 的 decreaseDelegatedShares 和 increaseDelegatedShares 去更新质押者绑定 operator 质押分额。

**3.2.ERC20**



![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtsj7Jb0AEGPQr.png)





```text
function depositIntoStrategy(
    IStrategy strategy,
    IERC20 token,
    uint256 amount
) external onlyWhenNotPaused(PAUSED_DEPOSITS) nonReentrant returns (uint256 shares) {
    shares = _depositIntoStrategy(msg.sender, strategy, token, amount);
}
```

- 该函数直接调度 _depositIntoStrategy 完成 ERC20 Token 质押过程



```text
function depositIntoStrategyWithSignature(
    IStrategy strategy,
    IERC20 token,
    uint256 amount,
    address staker,
    uint256 expiry,
    bytes memory signature
) external onlyWhenNotPaused(PAUSED_DEPOSITS) nonReentrant returns (uint256 shares) {
    require(
        !thirdPartyTransfersForbidden[strategy],
        "StrategyManager.depositIntoStrategyWithSignature: third transfers disabled"
    );
    require(expiry >= block.timestamp, "StrategyManager.depositIntoStrategyWithSignature: signature expired");

    uint256 nonce = nonces[staker];
    bytes32 structHash = keccak256(abi.encode(DEPOSIT_TYPEHASH, staker, strategy, token, amount, nonce, expiry));
    unchecked {
        nonces[staker] = nonce + 1;
    }

  
    bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

 
    EIP1271SignatureUtils.checkSignature_EIP1271(staker, digestHash, signature);

 
    shares = _depositIntoStrategy(staker, strategy, token, amount);
}
```

- 验证完成签名之后调用 _depositIntoStrategy 完成 ERC20 Token 质押流程



```text
function _depositIntoStrategy(
    address staker,
    IStrategy strategy,
    IERC20 token,
    uint256 amount
) internal onlyStrategiesWhitelistedForDeposit(strategy) returns (uint256 shares) {

    token.safeTransferFrom(msg.sender, address(strategy), amount);

    shares = strategy.deposit(token, amount);

    _addShares(staker, token, strategy, shares);

    delegation.increaseDelegatedShares(staker, strategy, shares);

    return shares;
}
```

- 第一步：将需要质押的 Token 转到对应策略合约
- 第二步：调度 strategy 合约的 deposit 方法算出质押的 Shares
- 第三步：将质押的 shares 加到对应质押者质押的策略里面
- 第四步：将质押者质押 shares 加给质押者绑定 operator



```text
function deposit(
    IERC20 token,
    uint256 amount
) external virtual override onlyWhenNotPaused(PAUSED_DEPOSITS) onlyStrategyManager returns (uint256 newShares) {

    _beforeDeposit(token, amount);


    uint256 priorTotalShares = totalShares;

 
    uint256 virtualShareAmount = priorTotalShares + SHARES_OFFSET;
    uint256 virtualTokenBalance = _tokenBalance() + BALANCE_OFFSET;

    uint256 virtualPriorTokenBalance = virtualTokenBalance - amount;
    newShares = (amount * virtualShareAmount) / virtualPriorTokenBalance;


    require(newShares != 0, "StrategyBase.deposit: newShares cannot be zero");


    totalShares = (priorTotalShares + newShares);

    require(totalShares <= MAX_TOTAL_SHARES, "StrategyBase.deposit: totalShares exceeds `MAX_TOTAL_SHARES`");

   
    _emitExchangeRate(virtualTokenBalance, totalShares + SHARES_OFFSET);

    return newShares;
}
```

- 该方法作用是根据当前质押情况和质押者质押的资金计算出对应质押份额



```text
function _addShares(address staker, IERC20 token, IStrategy strategy, uint256 shares) internal {

    require(staker != address(0), "StrategyManager._addShares: staker cannot be zero address");
    require(shares != 0, "StrategyManager._addShares: shares should not be zero!");


    if (stakerStrategyShares[staker][strategy] == 0) {
        require(
            stakerStrategyList[staker].length < MAX_STAKER_STRATEGY_LIST_LENGTH,
            "StrategyManager._addShares: deposit would exceed MAX_STAKER_STRATEGY_LIST_LENGTH"
        );
        stakerStrategyList[staker].push(strategy);
    }

    stakerStrategyShares[staker][strategy] += shares;

    emit Deposit(staker, token, strategy, shares);
}
```

- stakerStrategyShares[staker][strategy] += shares 该函数的核心代码，将质押者质押到策略的份额加给自己



```text
function increaseDelegatedShares(
    address staker,
    IStrategy strategy,
    uint256 shares
) external onlyStrategyManagerOrEigenPodManager {
    if (isDelegated(staker)) {
        address operator = delegatedTo[staker];
        _increaseOperatorShares({operator: operator, staker: staker, strategy: strategy, shares: shares});
    }
}
```

- 判断 stake 是否已经 delegate 给该 operator, 若已经 delegate 过了，直接调用 _increaseOperatorShares 将质押者的 shares 加给绑定的 operator



```text
function _increaseOperatorShares(address operator, address staker, IStrategy strategy, uint256 shares) internal {
    operatorShares[operator][strategy] += shares;
    emit OperatorSharesIncreased(operator, staker, strategy, shares);
}
```

- operatorShares[operator][strategy] += shares; 该函数的核心代码，将质押者的 shares 加给绑定的 operator 对应策略里面

## 4.Delegate 流程源码解析



![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYts75gasAAQhT-.png)





```text
function delegateTo(
    address operator,
    SignatureWithExpiry memory approverSignatureAndExpiry,
    bytes32 approverSalt
) external {
    require(!isDelegated(msg.sender), "DelegationManager.delegateTo: staker is already actively delegated");
    require(isOperator(operator), "DelegationManager.delegateTo: operator is not registered in EigenLayer");

    _delegate(msg.sender, operator, approverSignatureAndExpiry, approverSalt);
}
```

- 判断是不是 Delegate 过了
- 判断 Operator 是不是注册了
- 若要 Delegate 的 Operator 已经注册并且该 staker 还没有 Delegate 给过其他 Operator, 调用 _delegate 方法进行委托质押份额给 Operatort



```text
function _delegate(
    address staker,
    address operator,
    SignatureWithExpiry memory approverSignatureAndExpiry,
    bytes32 approverSalt
) internal onlyWhenNotPaused(PAUSED_NEW_DELEGATION) {

    address _delegationApprover = _operatorDetails[operator].delegationApprover;
  
    if (_delegationApprover != address(0) && msg.sender != _delegationApprover && msg.sender != operator) {
        // check the signature expiry
        require(
            approverSignatureAndExpiry.expiry >= block.timestamp,
            "DelegationManager._delegate: approver signature expired"
        );

        require(
            !delegationApproverSaltIsSpent[_delegationApprover][approverSalt],
            "DelegationManager._delegate: approverSalt already spent"
        );
        delegationApproverSaltIsSpent[_delegationApprover][approverSalt] = true;

        bytes32 approverDigestHash = calculateDelegationApprovalDigestHash(
            staker, 
            operator, 
            _delegationApprover, 
            approverSalt, 
            approverSignatureAndExpiry.expiry
        );


        EIP1271SignatureUtils.checkSignature_EIP1271(
            _delegationApprover, 
            approverDigestHash, 
            approverSignatureAndExpiry.signature
        );
    }


    delegatedTo[staker] = operator;
    emit StakerDelegated(staker, operator);

    (IStrategy[] memory strategies, uint256[] memory shares) = getDelegatableShares(staker);

    for (uint256 i = 0; i < strategies.length;) {
        // forgefmt: disable-next-item
        _increaseOperatorShares({
            operator: operator, 
            staker: staker, 
            strategy: strategies[i], 
            shares: shares[i]
        });

        unchecked {
            ++i;
        }
    }
}
```

- delegatedTo[staker] = operator: 将 Staker 和 Operator 绑定
- getDelegatableShares: 获取 staker 可以委托给 Operator 的份额
- _increaseOperatorShares: 将 staker 的质押份额加给绑定 Operator

## 5.排队流程和源码解析



![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYttHqLbsAABLdg.png)





```text
function undelegate(address staker)
    external
    onlyWhenNotPaused(PAUSED_ENTER_WITHDRAWAL_QUEUE)
    returns (bytes32[] memory withdrawalRoots)
{
    require(isDelegated(staker), "DelegationManager.undelegate: staker must be delegated to undelegate");
    require(!isOperator(staker), "DelegationManager.undelegate: operators cannot be undelegated");
    require(staker != address(0), "DelegationManager.undelegate: cannot undelegate zero address");
    address operator = delegatedTo[staker];
    require(
        msg.sender == staker || msg.sender == operator
            || msg.sender == _operatorDetails[operator].delegationApprover,
        "DelegationManager.undelegate: caller cannot undelegate staker"
    );

    (IStrategy[] memory strategies, uint256[] memory shares) = getDelegatableShares(staker);


    if (msg.sender != staker) {
        emit StakerForceUndelegated(staker, operator);
    }


    emit StakerUndelegated(staker, operator);
    delegatedTo[staker] = address(0);


    if (strategies.length == 0) {
        withdrawalRoots = new bytes32[](0);
    } else {
        withdrawalRoots = new bytes32[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            IStrategy[] memory singleStrategy = new IStrategy[](1);
            uint256[] memory singleShare = new uint256[](1);
            singleStrategy[0] = strategies[i];
            singleShare[0] = shares[i];

            withdrawalRoots[i] = _removeSharesAndQueueWithdrawal({
                staker: staker,
                operator: operator,
                withdrawer: staker,
                strategies: singleStrategy,
                shares: singleShare
            });
        }
    }
    return withdrawalRoots;
}
```

- getDelegatableShares 获取 staker 在所有策略里面可以删除的质押份额
- delegatedTo[staker] = address(0)：解除 Staker 和 Operator 的绑定关系
- _removeSharesAndQueueWithdrawal:移除对应质押者质押份额和委托给 Operator 份额，生成一笔对应 shares 的排队取款的交易



```text
function queueWithdrawals(QueuedWithdrawalParams[] calldata queuedWithdrawalParams)
    external
    onlyWhenNotPaused(PAUSED_ENTER_WITHDRAWAL_QUEUE)
    returns (bytes32[] memory)
{
    bytes32[] memory withdrawalRoots = new bytes32[](queuedWithdrawalParams.length);
    address operator = delegatedTo[msg.sender];

    for (uint256 i = 0; i < queuedWithdrawalParams.length; i++) {
        require(
            queuedWithdrawalParams[i].strategies.length == queuedWithdrawalParams[i].shares.length,
            "DelegationManager.queueWithdrawal: input length mismatch"
        );
        require(
            queuedWithdrawalParams[i].withdrawer == msg.sender,
            "DelegationManager.queueWithdrawal: withdrawer must be staker"
        );

        withdrawalRoots[i] = _removeSharesAndQueueWithdrawal({
            staker: msg.sender,
            operator: operator,
            withdrawer: queuedWithdrawalParams[i].withdrawer,
            strategies: queuedWithdrawalParams[i].strategies,
            shares: queuedWithdrawalParams[i].shares
        });
    }
    return withdrawalRoots;
}
```

- _removeSharesAndQueueWithdrawal:移除对应质押者质押份额和委托给 Operator 份额，生成一笔对应 shares 的排队取款的交易



```text
function _removeSharesAndQueueWithdrawal(
    address staker,
    address operator,
    address withdrawer,
    IStrategy[] memory strategies,
    uint256[] memory shares
) internal returns (bytes32) {
    require(
        staker != address(0), "DelegationManager._removeSharesAndQueueWithdrawal: staker cannot be zero address"
    );
    require(strategies.length != 0, "DelegationManager._removeSharesAndQueueWithdrawal: strategies cannot be empty");

    for (uint256 i = 0; i < strategies.length;) {
       
        if (operator != address(0)) {

            _decreaseOperatorShares({
                operator: operator, 
                staker: staker, 
                strategy: strategies[i], 
                shares: shares[i]
            });
        }

        if (strategies[i] == beaconChainETHStrategy) {
            eigenPodManager.removeShares(staker, shares[i]);
        } else {
            require(
                staker == withdrawer || !strategyManager.thirdPartyTransfersForbidden(strategies[i]),
                "DelegationManager._removeSharesAndQueueWithdrawal: withdrawer must be same address as staker if thirdPartyTransfersForbidden are set"
            );

            strategyManager.removeShares(staker, strategies[i], shares[i]);
        }

        unchecked {
            ++i;
        }
    }

    // Create queue entry and increment withdrawal nonce
    uint256 nonce = cumulativeWithdrawalsQueued[staker];
    cumulativeWithdrawalsQueued[staker]++;

    Withdrawal memory withdrawal = Withdrawal({
        staker: staker,
        delegatedTo: operator,
        withdrawer: withdrawer,
        nonce: nonce,
        startBlock: uint32(block.number),
        strategies: strategies,
        shares: shares
    });

    bytes32 withdrawalRoot = calculateWithdrawalRoot(withdrawal);

    pendingWithdrawals[withdrawalRoot] = true;

    emit WithdrawalQueued(withdrawalRoot, withdrawal);
    return withdrawalRoot;
}
```

- 调用 _decreaseOperatorShares 把 staker 委托给 operator 的质押份额移除
- 把 staker 在 EigenPodManager 和 strategyManager 里面的质押 shares 移除掉
- 根据移除的 shares 生成一笔排队取款的交易

## 6.完成取款流程和源码解析



![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYttdJEagAAx7-H.png)





```text
function completeQueuedWithdrawals(
    Withdrawal[] calldata withdrawals,
    IERC20[][] calldata tokens,
    uint256[] calldata middlewareTimesIndexes,
    bool[] calldata receiveAsTokens
) external onlyWhenNotPaused(PAUSED_EXIT_WITHDRAWAL_QUEUE) nonReentrant {
    for (uint256 i = 0; i < withdrawals.length; ++i) {
        _completeQueuedWithdrawal(withdrawals[i], tokens[i], middlewareTimesIndexes[i], receiveAsTokens[i]);
    }
}
```

传入要提现的交易信息，token 和 middlewareTimesIndexes 和是否接受 Tokens 参数，调用 _completeQueuedWithdrawal 遍历所需要提现的交易，并处理每一笔排队取款的交易



```text
function _completeQueuedWithdrawal(
    Withdrawal calldata withdrawal,
    IERC20[] calldata tokens,
    uint256, /*middlewareTimesIndex*/
    bool receiveAsTokens
) internal {
    bytes32 withdrawalRoot = calculateWithdrawalRoot(withdrawal);

    require(
        pendingWithdrawals[withdrawalRoot], "DelegationManager._completeQueuedWithdrawal: action is not in queue"
    );

    require(
        withdrawal.startBlock + minWithdrawalDelayBlocks <= block.number,
        "DelegationManager._completeQueuedWithdrawal: minWithdrawalDelayBlocks period has not yet passed"
    );

    require(
        msg.sender == withdrawal.withdrawer,
        "DelegationManager._completeQueuedWithdrawal: only withdrawer can complete action"
    );

    if (receiveAsTokens) {
        require(
            tokens.length == withdrawal.strategies.length,
            "DelegationManager._completeQueuedWithdrawal: input length mismatch"
        );
    }
  
    delete pendingWithdrawals[withdrawalRoot];

    if (receiveAsTokens) {


        for (uint256 i = 0; i < withdrawal.strategies.length;) {
            require(
                withdrawal.startBlock + strategyWithdrawalDelayBlocks[withdrawal.strategies[i]] <= block.number,
                "DelegationManager._completeQueuedWithdrawal: withdrawalDelayBlocks period has not yet passed for this strategy"
            );

            _withdrawSharesAsTokens({
                staker: withdrawal.staker,
                withdrawer: msg.sender,
                strategy: withdrawal.strategies[i],
                shares: withdrawal.shares[i],
                token: tokens[i]
            });
            unchecked {
                ++i;
            }
        }
    } else {
        address currentOperator = delegatedTo[msg.sender];
        for (uint256 i = 0; i < withdrawal.strategies.length;) {
            require(
                withdrawal.startBlock + strategyWithdrawalDelayBlocks[withdrawal.strategies[i]] <= block.number,
                "DelegationManager._completeQueuedWithdrawal: withdrawalDelayBlocks period has not yet passed for this strategy"
            );

            if (withdrawal.strategies[i] == beaconChainETHStrategy) {
                address staker = withdrawal.staker;
                uint256 increaseInDelegateableShares =
                    eigenPodManager.addShares({podOwner: staker, shares: withdrawal.shares[i]});
                address podOwnerOperator = delegatedTo[staker];

                if (podOwnerOperator != address(0)) {
                    _increaseOperatorShares({
                        operator: podOwnerOperator,
                        staker: staker,
                        strategy: withdrawal.strategies[i],
                        shares: increaseInDelegateableShares
                    });
                }
            } else {
                strategyManager.addShares(msg.sender, tokens[i], withdrawal.strategies[i], withdrawal.shares[i]);
                if (currentOperator != address(0)) {
                    _increaseOperatorShares({
                        operator: currentOperator,
                        // the 'staker' here is the address receiving new shares
                        staker: msg.sender,
                        strategy: withdrawal.strategies[i],
                        shares: withdrawal.shares[i]
                    });
                }
            }
            unchecked {
                ++i;
            }
        }
    }
    emit WithdrawalCompleted(withdrawalRoot);
}
```

- delete pendingWithdrawals[withdrawalRoot] 删除排队取款的交易
- 如果 receiveAsTokens 为 true, 执行 _withdrawSharesAsTokens 取资金，_withdrawSharesAsTokens 方便会去调用 strategyManager.withdrawSharesAsTokens 或者 eigenPodManager.withdrawSharesAsTokens 根据质押的 shares 计算出要提现的资金，将资金转到用户的提现地址
- 如果 receiveAsTokens 为 false,  将要移除的 shares 再给 staker 和 operator 加回去。

## 7.信标链 Validator 退出流程和源码解析



![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYttp2sbEAAbT3d.png)





```text
function startCheckpoint(bool revertIfNoBalance)
    external
    onlyOwnerOrProofSubmitter
    onlyWhenNotPaused(PAUSED_START_CHECKPOINT)
{
    _startCheckpoint(revertIfNoBalance);
}
```

- 创建一个检查点，用于证明此 pod 的活动验证器集。通过为每个活动验证器提交一个检查点证明来完成检查点。在检查点过程中，将跟踪活动验证器余额的总变化，并将任何余额为 0 的验证器标记为“WITHDRAWN”。
- 一旦完成，pod 所有者将获得与以下内容相对应的份额： 其活动验证器余额的总变化 pod 中尚未授予份额的任何 ETH
- 如果 pod 已经有一个未完成的检查点，则无法创建检查点。如果是这种情况，pod 所有者必须在开始新的检查点之前完成现有检查点。
- 如果 pod ETH 余额为 0，则强制恢复。这允许 pod 所有者防止意外启动不会增加其份额的检查点



```text
function _startCheckpoint(bool revertIfNoBalance) internal {
    require(
        currentCheckpointTimestamp == 0,
        "EigenPod._startCheckpoint: must finish previous checkpoint before starting another"
    );
    
    require(
        lastCheckpointTimestamp != uint64(block.timestamp),
        "EigenPod._startCheckpoint: cannot checkpoint twice in one block"
    );

    uint64 podBalanceGwei = uint64(address(this).balance / GWEI_TO_WEI) - withdrawableRestakedExecutionLayerGwei;


    if (revertIfNoBalance && podBalanceGwei == 0) {
        revert("EigenPod._startCheckpoint: no balance available to checkpoint");
    }

    Checkpoint memory checkpoint = Checkpoint({
        beaconBlockRoot: getParentBlockRoot(uint64(block.timestamp)),
        proofsRemaining: uint24(activeValidatorCount),
        podBalanceGwei: podBalanceGwei,
        balanceDeltasGwei: 0
    });

    currentCheckpointTimestamp = uint64(block.timestamp);
    _updateCheckpoint(checkpoint);

    emit CheckpointCreated(uint64(block.timestamp), checkpoint.beaconBlockRoot, checkpoint.proofsRemaining);
}
```

- 通过快照 pod 的 ETH 余额和当前块的父块根来启动检查点证明。在为pod 的每个 ACTIVE 验证器提供检查点证明后，pod 的 ETH 余额将获得份额并可以提取
- 验证器是具有经过验证的提取凭据的验证器（有关详细信息，请参阅verifyWithdrawalCredentials）
- 如果 pod 没有任何 ACTIVE 验证器，则检查点将自动完成
- 一旦启动，检查点必须完成！如果现有检查点不完整，则无法启动检查点
- 如果可用于检查点的 ETH 余额为 0 且此值为true，则此方法将恢复



```text
function _updateCheckpoint(Checkpoint memory checkpoint) internal {
    if (checkpoint.proofsRemaining == 0) {
        int256 totalShareDeltaWei =
            (int128(uint128(checkpoint.podBalanceGwei)) + checkpoint.balanceDeltasGwei) * int256(GWEI_TO_WEI);

        // Add any native ETH in the pod to `withdrawableRestakedExecutionLayerGwei`
        // ... this amount can be withdrawn via the `DelegationManager` withdrawal queue
        withdrawableRestakedExecutionLayerGwei += checkpoint.podBalanceGwei;

        // Finalize the checkpoint
        lastCheckpointTimestamp = currentCheckpointTimestamp;
        delete currentCheckpointTimestamp;
        delete _currentCheckpoint;

        eigenPodManager.recordBeaconChainETHBalanceUpdate(podOwner, totalShareDeltaWei);
        emit CheckpointFinalized(lastCheckpointTimestamp, totalShareDeltaWei);
    } else {
        _currentCheckpoint = checkpoint;
    }
}
```

- 完成检查点的进度并将其存储在状态中。
- 如果检查点没有剩余的证明，则最终确定： 计算共享增量并发送到 EigenPodManager 将检查点的 podBalanceGwei 添加到 withdrawableRestakedExecutionLayerGwei 更新 lastCheckpointTimestamp 删除 _currentCheckpoint 和 currentCheckpointTimestamp
- 调用 recordBeaconChainETHBalanceUpdate 更新 DelegationManager 里面的质押份额



![](https://github.com/the-web3/eigenlayer-eigenda-tech/blob/main/eigenlayer/imgs/GYtud0qbkAAaUit.png)





```text
function verifyCheckpointProofs(
    BeaconChainProofs.BalanceContainerProof calldata balanceContainerProof,
    BeaconChainProofs.BalanceProof[] calldata proofs
) external onlyWhenNotPaused(PAUSED_EIGENPODS_VERIFY_CHECKPOINT_PROOFS) {
    uint64 checkpointTimestamp = currentCheckpointTimestamp;
    require(
        checkpointTimestamp != 0,
        "EigenPod.verifyCheckpointProofs: must have active checkpoint to perform checkpoint proof"
    );

    Checkpoint memory checkpoint = _currentCheckpoint;

    BeaconChainProofs.verifyBalanceContainer({
        beaconBlockRoot: checkpoint.beaconBlockRoot,
        proof: balanceContainerProof
    });

    uint64 exitedBalancesGwei;
    for (uint256 i = 0; i < proofs.length; i++) {
        BeaconChainProofs.BalanceProof calldata proof = proofs[i];
        ValidatorInfo memory validatorInfo = _validatorPubkeyHashToInfo[proof.pubkeyHash];

        if (validatorInfo.status != VALIDATOR_STATUS.ACTIVE) {
            continue;
        }

    
        if (validatorInfo.lastCheckpointedAt >= checkpointTimestamp) {
            continue;
        }
        
        (int128 balanceDeltaGwei, uint64 exitedBalanceGwei) = _verifyCheckpointProof({
            validatorInfo: validatorInfo,
            checkpointTimestamp: checkpointTimestamp,
            balanceContainerRoot: balanceContainerProof.balanceContainerRoot,
            proof: proof
        });

        checkpoint.proofsRemaining--;
        checkpoint.balanceDeltasGwei += balanceDeltaGwei;
        exitedBalancesGwei += exitedBalanceGwei;


        _validatorPubkeyHashToInfo[proof.pubkeyHash] = validatorInfo;
        emit ValidatorCheckpointed(checkpointTimestamp, uint40(validatorInfo.validatorIndex));
    }

    checkpointBalanceExitedGwei[checkpointTimestamp] += exitedBalancesGwei;
    _updateCheckpoint(checkpoint);
}
```

- 通过提交一个或多个验证器来推进当前检查点的完成
- 检查点证明。任何人都可以调用此方法提交当前检查点的证明。
- 对于每个已证明的验证器，当前检查点的 proofsRemaining 都会减少。
- 如果检查点的 proofsRemaining 达到 0，则检查点完成。（有关更多详细信息，请参阅 _updateCheckpoint）仅当存在当前活动的检查点时才能调用此方法。
- balanceContainerProof 根据检查点的 beaconBlockRoot 证明信标的当前余额容器根
- proofs 根据 balanceContainerRoot 为一个或多个验证器当前余额提供证明
- 调度到 _updateCheckpoint 和上面的流程一样

# 四.总结

EigenLayer 是一个创新的 **以太坊重质押（restaking）** 协议，允许用户将他们在以太坊主网上的质押资产（如 ETH）再次质押，以用于新的服务。这些服务可能包括数据可用性、共识机制、或其他链外任务。EigenLayer 的核心理念是充分利用以太坊质押者的安全性和去中心化，同时为新的区块链服务和项目提供额外的安全保障。

## 核心机制

- **重质押（Restaking）**：EigenLayer 的核心功能是允许质押者将他们已经质押在以太坊上的资产再质押到 EigenLayer 提供的其他服务中。这使得质押者能够为多个项目提供支持，同时只使用他们的质押资产。
- **可扩展的验证人网络**：EigenLayer 拓展了现有的以太坊验证人网络，允许这些验证人不只为以太坊区块链服务，还可以为其他 L2 网络、跨链桥、或去中心化应用提供安全服务。
- **模块化服务**：EigenLayer 提供一个平台，允许开发者创建自己的去中心化服务，并将其接入 EigenLayer 的验证人网络。这些服务可能包括数据可用性证明、侧链验证等。
- **惩罚机制（Slashing）**：EigenLayer 中的质押者将面临双重惩罚风险。如果他们在执行任务时表现不佳（例如验证错误的数据），他们不仅会在原始质押的以太坊中受到惩罚，还可能在 EigenLayer 中遭遇资产削减。

## 关键优势

- **资源高效利用**：EigenLayer 通过允许重质押，使以太坊质押者能够多次利用同一份质押资产，而不必为每个新服务单独质押，从而提高了资本效率。
- **增强去中心化和安全性**：EigenLayer 利用了以太坊现有的去中心化网络和经济激励机制，帮助新的项目实现去中心化和安全性，而无需自己从头搭建验证人网络。
- **创新生态**：EigenLayer 为开发者提供了一个基础设施，可以构建各种新的去中心化服务，并轻松接入以太坊质押者网络。这为去中心化服务的快速扩展和创新提供了一个强大的平台。

## 发展前景

EigenLayer 通过将现有的以太坊质押网络扩展至新的服务领域，提升了区块链技术的经济和安全性，同时为开发者提供了灵活的基础设施。它有潜力在去中心化数据存储、跨链桥接、验证任务等领域推动新的创新，进一步增强以太坊生态系统的价值。