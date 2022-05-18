// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

interface IKeyringSignatureVerifier {

    event Deployed(address admin, address trustedForwarder);
    event SetGraceTime(address admin, uint256 timeSeconds);

    function setGraceTime(uint256 timeSeconds) external;
}
