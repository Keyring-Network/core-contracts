// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.14;

import "./AddressSet.sol";
import "../interfaces/IRuleRegistry.sol";

/**
 @notice PolicyStorage attends to state management concerns for the PolicyManager. It establishes the
 storage layout and is responsible for internal state integrity and managing state transitions. The 
 PolicyManager is responsible for orchestration of the functions implemented here as well as access
 control. 
 */

library PolicyStorage {

    using AddressSet for AddressSet.Set;

    uint32 private constant MAX_POLICIES = 2 ** 20;
    address private constant NULL_ADDRESS = address(0);

    error Unacceptable(string reason);

    /// @dev The App struct contains the essential PolicyManager state including an array of Policies. 

    struct App {
        Policy[] policies;
        AddressSet.Set globalAttestorSet;
        mapping(address => string) attestorUris;
        AddressSet.Set globalWalletCheckSet;
    }

    /// @dev PolicyScalar contains the non-indexed values in a policy configuration.

    struct PolicyScalar {
        bytes32 ruleId;
        string descriptionUtf8;
        uint32 ttl;
        uint32 gracePeriod;
        uint16 acceptRoots;
        bool allowWhitelists;
        bool locked;
    }

    /// @dev PolicyAttestors contains the active policy attestors as well as scheduled changes. 

    struct PolicyAttestors {
        AddressSet.Set activeSet;
        AddressSet.Set pendingAdditionSet;
        AddressSet.Set pendingRemovalSet;
    }

    /// @dev PolicyWalletChecks contains the active policy wallet checks as well as scheduled changes.

    struct PolicyWalletChecks {
        AddressSet.Set activeSet;
        AddressSet.Set pendingAdditionSet;
        AddressSet.Set pendingRemovalSet;
    }

    /**
     @dev Policy contains the active and scheduled changes and the deadline when the changes will
    take effect.
    */
    
    struct Policy {
        uint256 deadline;
        PolicyScalar scalarActive;
        PolicyScalar scalarPending;
        PolicyAttestors attestors;
        PolicyWalletChecks walletChecks;
    }

    function insertGlobalAttestor(
        App storage self,
        address attestor,
        string memory uri
    ) public
    {
        if(attestor == NULL_ADDRESS)
            revert Unacceptable({
                reason: "attestor cannot be empty"
            });
        if(bytes(uri).length == 0) 
            revert Unacceptable({
                reason: "uri cannot be empty"
            });        
        self.globalAttestorSet.insert(attestor, "PolicyStorage:insertGlobalAttestor");
        self.attestorUris[attestor] = uri;
    }

    function updateGlobalAttestorUri(
        App storage self, 
        address attestor,
        string memory uri
    ) public
    {
        if(!self.globalAttestorSet.exists(attestor))
            revert Unacceptable({
                reason: "attestor not found"
            });
        if(bytes(uri).length == 0) 
            revert Unacceptable({
                reason: "uri cannot be empty"
            });  
        self.attestorUris[attestor] = uri;
    }

    function removeGlobalAttestor(
        App storage self,
        address attestor
    ) public
    {
        self.globalAttestorSet.remove(attestor, "PolicyStorage:removeGlobalAttestor");
    }

    function insertGlobalWalletCheck(
        App storage self,
        address walletCheck
    ) public
    {
        if(walletCheck == NULL_ADDRESS)
            revert Unacceptable({
                reason: "walletCheck cannot be empty"
            });
        self.globalWalletCheckSet.insert(walletCheck, "PolicyStorage:insertGlobalWalletCheck");
    }

    function removeGlobalWalletCheck(
        App storage self,
        address walletCheck
    ) public
    {
        self.globalWalletCheckSet.remove(walletCheck, "PolicyStorage:removeGlobalWalletCheck");
    }

    function newPolicy(
        App storage self,
        PolicyScalar calldata policyScalar,
        address[] memory attestors,
        address[] memory walletChecks,
        address ruleRegistry
    ) public returns (uint32 policyId) 
    {
        uint256 i;
        self.policies.push();
        policyId = uint32(self.policies.length - 1);
        if(policyId >= MAX_POLICIES)
            revert Unacceptable({
                reason: "max policies exceeded"
            });
        Policy storage policy = policyRawData(self, policyId);
        uint256 deadline = block.timestamp;

        writePolicyScalar(
            self,
            policyId,
            policyScalar,
            ruleRegistry,
            deadline
        );

        processStaged(policy);

        for(i=0; i<attestors.length; i++) {
            address attestor = attestors[i];
            if(!self.globalAttestorSet.exists(attestor))
                revert Unacceptable({
                    reason: "attestor not found"
                });
            policy.attestors.activeSet.insert(attestor, "PolicyStorage:newPolicy");
        }

        for(i=0; i<walletChecks.length; i++) {
            address walletCheck = walletChecks[i];
            if(!self.globalWalletCheckSet.exists(walletCheck))
                revert Unacceptable({
                    reason: "walletCheck not found"
                });
            policy.walletChecks.activeSet.insert(walletCheck, "PolicyStorage:newPolicy");
        }
}

    function policyRawData(
        App storage self, 
        uint32 policyId
    ) public view returns (Policy storage policyInfo) 
    {
        policyInfo = self.policies[policyId];
    }

    function processStaged(
        Policy storage self
    ) public
    {
        uint256 deadline = self.deadline;
        if(deadline > 0 && deadline <= block.timestamp) {
            self.scalarActive = self.scalarPending;
            while(self.attestors.pendingAdditionSet.count() > 0) {
                address attestor = self.attestors.pendingAdditionSet.keyAtIndex(
                    self.attestors.pendingAdditionSet.count() - 1
                );
                self.attestors.activeSet.insert(
                    attestor,
                    "policyStorage:processStaged"
                );
                self.attestors.pendingAdditionSet.remove(
                    attestor,
                    "policyStorage:processStaged"
                );
            }
            while(self.attestors.pendingRemovalSet.count() > 0) {
                address attestor = self.attestors.pendingRemovalSet.keyAtIndex(
                    self.attestors.pendingRemovalSet.count() - 1
                );
                self.attestors.activeSet.remove(
                    attestor,
                    "policyStorage:processStaged"
                );
                self.attestors.pendingRemovalSet.remove(
                    attestor,
                    "policyStorage:processStaged"
                );
            }
            while(self.walletChecks.pendingAdditionSet.count() > 0) {
                address walletCheck = self.walletChecks.pendingAdditionSet.keyAtIndex(
                    self.walletChecks.pendingAdditionSet.count() - 1
                );
                self.walletChecks.activeSet.insert(
                    walletCheck,
                    "policyStorage:processStaged"
                );
                self.walletChecks.pendingAdditionSet.remove(
                    walletCheck,
                    "policyStorage:processStaged"
                );
            }
            while(self.walletChecks.pendingRemovalSet.count() > 0) {
                address walletCheck = self.walletChecks.pendingRemovalSet.keyAtIndex(
                    self.walletChecks.pendingRemovalSet.count() - 1
                );
                self.walletChecks.activeSet.remove(
                    walletCheck,
                    "policyStorage:processStaged"
                );
                self.walletChecks.pendingRemovalSet.remove(
                    walletCheck,
                    "policyStorage:processStaged"
                );
            }
            self.deadline = 0;
        }
    }

    function checkLock(
        Policy storage policy
    ) public view 
    {
        if(isLocked(policy))
            revert Unacceptable({
                reason: "policy is locked"
            });
    }

    function isLocked(Policy storage policy) public view returns(bool isIndeed) {
        isIndeed = policy.scalarActive.locked;
    }

    function setDeadline(
        Policy storage self, 
        uint256 deadline
    ) public
    {
        processStaged(self);
        checkLock(self);

        // Deadline of 0 allows staging of changes with no implementation schedule.
        // Positive deadlines must be at least graceTime seconds in the future.
     
        if(deadline != 0 && 
            (deadline < block.timestamp + self.scalarActive.gracePeriod)
        )
            revert Unacceptable({
                reason: "deadline in the past or too soon"
        });
        self.deadline = deadline;
    }

    function writePolicyScalar(
        App storage self,
        uint32 policyId,
        PolicyStorage.PolicyScalar calldata policyScalar,
        address ruleRegistry,
        uint256 deadline
    ) public {
        PolicyStorage.Policy storage policyObj = policyRawData(self, policyId);
        processStaged(policyObj);
        writeRuleId(policyObj, policyScalar.ruleId, ruleRegistry);
        writeDescription(policyObj, policyScalar.descriptionUtf8);
        writeTtl(policyObj, policyScalar.ttl);
        writeGracePeriod(policyObj, policyScalar.gracePeriod);
        writeAcceptRoots(policyObj, policyScalar.acceptRoots);
        setDeadline(policyObj, deadline);
    }

    function writeRuleId(
        Policy storage self, 
        bytes32 ruleId, 
        address ruleRegistry
    ) public
    {
        if(!IRuleRegistry(ruleRegistry).isRule(ruleId))
            revert Unacceptable({
                reason: "rule not found"
            });
        self.scalarPending.ruleId = ruleId;
    }

    function writeDescription(
        Policy storage self, 
        string memory descriptionUtf8
    ) public
    {
        if(bytes(descriptionUtf8).length == 0) 
            revert Unacceptable({
                reason: "descriptionUtf8 cannot be empty"
            });
        self.scalarPending.descriptionUtf8 = descriptionUtf8;
    }

    function writeTtl(
        Policy storage self,
        uint32 ttl
    ) public
    {
        self.scalarPending.ttl = ttl;
    }

    function writeGracePeriod(
        Policy storage self,
        uint32 gracePeriod
    ) public
    {
        // 0 is acceptable
        self.scalarPending.gracePeriod = gracePeriod;
    }

    function writeAllowWhitelists(
        Policy storage self,
        bool allowWhitelists
    ) public
    {
        self.scalarPending.allowWhitelists = allowWhitelists;
    }

    function writePolicyLock(
        Policy storage self,
        bool setPolicyLocked
    ) public
    {
        self.scalarPending.locked = setPolicyLocked;
    }


    function writeAcceptRoots(
        Policy storage self,
        uint16 acceptRoots
    ) public
    {
        self.scalarPending.acceptRoots = acceptRoots;
    }

    function writeAttestorAdditions(
        App storage self,
        Policy storage policy,
        address[] memory attestors
    ) public
    {
        for(uint i = 0; i < attestors.length; i++) {
            _writeAttestorAddition(self, policy, attestors[i]);
        }        
    }

    function _writeAttestorAddition(
        App storage self,
        Policy storage policy,
        address attestor
    ) private
    {
        if(!self.globalAttestorSet.exists(attestor))
            revert Unacceptable({
                reason: "attestor not found"
            });
        if(policy.attestors.pendingRemovalSet.exists(attestor)) {
            policy.attestors.pendingRemovalSet.remove(attestor, "PolicyStorage:_writeAttestorAddition");
        } else {
            if(policy.attestors.activeSet.exists(attestor)) {
                revert Unacceptable({
                    reason: "attestor already in policy"
                });
            }
            policy.attestors.pendingAdditionSet.insert(attestor, "PolicyStorage:_writeAttestorAddition");
        }
    }

    function writeAttestorRemovals(
        Policy storage self,
        address[] memory attestors
    ) public
    {
        for(uint i = 0; i < attestors.length; i++) {
            _writeAttestorRemoval(self, attestors[i]);
        }
    }

    function _writeAttestorRemoval(
        Policy storage self,
        address attestor
    ) private
    {
        if(self.attestors.pendingAdditionSet.exists(attestor)) {
            self.attestors.pendingAdditionSet.remove(attestor, "PolicyStorage:_writeAttestorRemoval");
        } else {
            if(!self.attestors.activeSet.exists(attestor)) {
                revert Unacceptable({
                    reason: "attestor not found"
                });
            }
            self.attestors.pendingRemovalSet.insert(attestor, "PolicyStorage:_writeAttestorRemoval");
        }
    }

    function writeWalletCheckAdditions(
        App storage self,
        Policy storage policy,
        address[] memory walletChecks
    ) public
    {
        for(uint i = 0; i < walletChecks.length; i++) {
            _writeWalletCheckAddition(self, policy, walletChecks[i]);
        }
    }

    function _writeWalletCheckAddition(
        App storage self,
        Policy storage policy,
        address walletCheck
    ) private
    {
        if(!self.globalWalletCheckSet.exists(walletCheck))
            revert Unacceptable({
                reason: "walletCheck not found"
            });
        if(policy.walletChecks.pendingRemovalSet.exists(walletCheck)) {
            policy.walletChecks.pendingRemovalSet.remove(walletCheck, "PolicyStorage:_writeWalletCheckAddition");
        } else {
            if(policy.walletChecks.activeSet.exists(walletCheck)) {
                revert Unacceptable({
                    reason: "walletCheck already in policy"
                });
            }
            if(policy.walletChecks.pendingAdditionSet.exists(walletCheck)) {
                revert Unacceptable({
                    reason: "walletCheck addition already scheduled"
                });
            }
        }
        policy.walletChecks.pendingAdditionSet.insert(walletCheck, "PolicyStorage:_writeWalletCheckAddition");
    }

    function writeWalletCheckRemovals(
        Policy storage self,
        address[] memory walletChecks
    ) public
    {
        for(uint i = 0; i < walletChecks.length; i++) {
            _writeWalletCheckRemoval(self, walletChecks[i]);
        }
    }

    function _writeWalletCheckRemoval(
        Policy storage self,
        address walletCheck
    ) private
    {
        if(self.walletChecks.pendingAdditionSet.exists(walletCheck)) {
            self.walletChecks.pendingAdditionSet.remove(walletCheck, "PolicyStorage:_writeWalletCheckRemoval");
        } else {
            if(!self.walletChecks.activeSet.exists(walletCheck)) {
                revert Unacceptable({
                    reason: "walletCheck is not in policy"
                });
            }
            if(self.walletChecks.pendingRemovalSet.exists(walletCheck)) {
                revert Unacceptable({
                    reason: "walletCheck removal already scheduled"
                });
            }
        }
        self.walletChecks.pendingRemovalSet.insert(walletCheck, "PolicyStorage:_writeWalletCheckRemoval");
    }
}
