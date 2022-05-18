// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

interface IKeyringCache {

    event Deployed(address deployer, address trustedForwarder);
    event UpdateCache(address updater, bytes32 admissionPolicy, address user);

    function CACHE_UPDATER() external view returns(bytes32);
    function getCache(bytes32 admissionPolicy, address user) external view returns(uint256);
    function setCache(bytes32 admissionPolicy, address user) external;
}
