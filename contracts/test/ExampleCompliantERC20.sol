// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

import "../integration/KeyringGuard.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ExampleCompliantERC20 is ERC20, KeyringGuard {

    /**
     In this simple example, one admission policy covers the whole contract and it is constant for best performance.
     The admission policy cannot be changed, but it's inclusions, exclusions, quorum and time-to-live can be managed
     through the AdmissionPolicyManager dashboard (requires admin access).

     Optionally, the admissionPolicyId can be editable for fast-switching between pre-configured admission policies. 

     Optionally, a contract can use multiple admission policies for granular control of discrete concerns, passing
     the policy to enforce into the modifier. 
     */
    bytes32 public constant keyringAdmissionPolicyId = 0x0000000000000000000000000000000000000000000000000000000000000000000000000; // actual admissionPolicyId

    constructor()
        ERC20("ExampleCompliantERC20", "EC20")

        /**
         The two upgradeable contract addresses are not expected to change and will likely be hard-coded into 
         the KeyringGuard when production addresses are known. KeyringGuard initializes immutables with
         constructor arguments.
         */
        // keyring cache, keyring AdmissionPolicyManager
        KeyringGuard(address(0x1234), address(0x5678))
    {}

    function transfer(
        address to, 
        uint256 amount
    ) 
        public 
        override 
        keyringCompliance(to, keyringAdmissionPolicyId) 
        returns (bool) 
    {
        return ERC20.transfer(to, amount);
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    )
        public 
        override 
        keyringCompliance(to, keyringAdmissionPolicyId) 
        returns (bool)
    {
        return ERC20.transferFrom(from, to, amount);
    }
}
