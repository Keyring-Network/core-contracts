// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

import "../access/KeyringAccessControl.sol";
import "../interfaces/IRuleRegistry.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @notice The RuleRegistry holds the global list of all existing Policy rules, which
 * can be applied in the PolicyManager contract via the createPolicy and updatePolicy
 * functions. Base Rules are managed by  the Rule Admin role. Anyone can create an
 * expression using an operator and existing Rules as operands.
 */

contract RuleRegistry is IRuleRegistry, KeyringAccessControl, Initializable {
    using Bytes32Set for Bytes32Set.Set;

    string private constant MODULE = "RuleRegistry";
    address private constant NULL_ADDRESS = address(0);
    bytes32 private constant ROLE_RULE_ADMIN = keccak256("role rule admin");
    bytes32 private _universeRule;
    bytes32 private _emptyRule;

    Bytes32Set.Set private ruleSet;
    mapping(bytes32 => Rule) private rules;

    /**
     * @param trustedForwarder Contract address that is allowed to relay message signers.
     */
    constructor(address trustedForwarder) KeyringAccessControl(trustedForwarder) {
        if (trustedForwarder == NULL_ADDRESS)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "constructor",
                reason: "trustedForwarder cannot be empty"
            });
        emit RuleRegistryDeployed(_msgSender(), trustedForwarder);
    }

    /**
     * @notice This upgradeable contract must be initialized.
     * @dev Initialiser function MUST be called directly after deployment
     because anyone can call it but overall only once.
     * @param universeDescription Description of the universal set Rule.
     * @param universeUri The universal set URI.
     * @param emptyDescription Description of the empty Rule.
     * @param emptyUri The empty Rule URI.
     */
    function init(
        string calldata universeDescription,
        string calldata universeUri,
        string calldata emptyDescription,
        string calldata emptyUri
    ) external override initializer {
        bytes32[] memory emptyOperands;
        if (bytes(universeDescription).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "init",
                reason: "universeDescription cannot be empty"
            });
        if (bytes(universeUri).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "init",
                reason: "universeUri cannot be empty"
            });
        if (bytes(emptyDescription).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "init",
                reason: "emptyDescription cannot be empty"
            });
        if (bytes(emptyUri).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "init",
                reason: "emptyUri cannot be empty"
            });
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(ROLE_RULE_ADMIN, _msgSender());
        _universeRule = createRule(universeDescription, universeUri, Operator.Base, emptyOperands);
        _emptyRule = createRule(emptyDescription, emptyUri, Operator.Base, emptyOperands);
        emit RuleRegistryInitialized(
            _msgSender(),
            universeDescription,
            universeUri,
            emptyDescription,
            emptyUri,
            _universeRule,
            _emptyRule
        );
    }

    /**
     * @notice Anyone can create expressions. Only the Rule Admin can create Base Rules.
     * @dev Interpretation of Expressions is deterministic.
     * @param description The description for a Base Rule. Empty for expressions.
     * @param uri Detailed information Uri for a Base Rule. Empty for expressions.
     * @param operator The expression operator (1-3, or Base (0)
     * @param operands The list of the ruleId’s in the expression. Empty for Base Rules.
     * @return ruleId The unique identifier of Rule. Each Policy has exactly one Rule.
     */
    function createRule(
        string memory description,
        string memory uri,
        Operator operator,
        bytes32[] memory operands
    ) public override returns (bytes32 ruleId) {
        if (operator == Operator.Base)
            _checkRole(
                ROLE_RULE_ADMIN,
                _msgSender(),
                "RuleRegistry:createRule: only the RuleAdmin role can create or edit base sets"
            );
        validateRule(description, uri, operator, operands.length);
        ruleId = generateRuleId(description, operator, operands);
        // insert header information
        ruleSet.insert(ruleId, "RuleRegistry:createRule: generated duplicated id.");
        Rule storage r = rules[ruleId];
        r.description = description;
        r.operator = operator;
        r.uri = uri;
        // insert operands
        bytes32 lastOperand;
        for (uint256 i = 0; i < operands.length; i++) {
            if (operands[i] <= lastOperand)
                revert Unacceptable({
                    sender: _msgSender(),
                    module: MODULE,
                    method: "createRule",
                    reason: "operands must be declared in ascending ruleId order"
                });
            if (!isRule(operands[i]))
                revert Unacceptable({
                    sender: _msgSender(),
                    module: MODULE,
                    method: "createRule",
                    reason: "operand not found"
                });
            lastOperand = operands[i];
            r.operandSet.insert(operands[i], "RuleRegistry:createRule: 500 duplicate operand");
        }
        emit CreateRule(_msgSender(), ruleId, description, uri, operator, operands);
    }

    /**
     * @notice Only the Rule Admin can update Base Rule URIs.
     * @param ruleId The unique identifier of a rule. Each Policy has exactly one rule.
     * @param uri The URI points to detailed information about the base rule.
     */
    function updateRuleUri(bytes32 ruleId, string calldata uri) external override {
        _checkRole(
            ROLE_RULE_ADMIN, 
            _msgSender(), 
            "RuleRegisty:updateRuleUri: only rule admin can set a base rule uri");
        if (!ruleSet.exists(ruleId))
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateRuleUri",
                reason: "ruleId not found"
            });
        if (bytes(uri).length == 0)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateRuleUri",
                reason: "uri cannot be empty"
            });
        Rule storage r = rules[ruleId];
        if (r.operator != Operator.Base)
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "updateRuleUri",
                reason: "not a base rule"
            });
        r.uri = uri;
        emit UpdateRuleUri(_msgSender(), ruleId, uri);
    }

    /**
     * @notice Checks the Rule definition validation rules.
     * @param description The rule description
     * @param uri The rule uri
     * @param operator The rule operator
     * @param operandCount The number of operands in the rule expression
     */
    function validateRule(
        string memory description,
        string memory uri,
        Operator operator,
        uint256 operandCount
    ) private view {
        if (operator == Operator.Complement) {
            if (operandCount != 1) _validationError("complement must have exactly one operand");
        } else if (operator == Operator.Union) {
            if (operandCount < 2) _validationError("union must have two or more operands");
        } else if (operator == Operator.Intersection) {
            if (operandCount < 2) _validationError("intersection must have two or more operands");
        } 
        
        if (operator != Operator.Base) {
            if (bytes(description).length != 0)
                _validationError("only base rules can have a description");
            if (bytes(uri).length != 0) _validationError("only base rules can have a uri");
        } else {
            if (operandCount != 0) _validationError("base rules cannot have operands");
            if (bytes(description).length == 0)
                _validationError("base rules must have a description");
            if (bytes(uri).length == 0) _validationError("base rules must have a uri");
        }
    }

    function _validationError(string memory reason) private view {
        revert Unacceptable({
            sender: _msgSender(),
            module: MODULE,
            method: "validateRule",
            reason: reason
        });
    }

    /**********************************************************
     VIEW FUNCTIONS
     **********************************************************/

    /**
     @return universeRuleId The id of the universal set (everyone) Rule.
     @return emptyRuleId The id of the empty (no one) Rule.
     */
    function genesis() external view override returns (bytes32 universeRuleId, bytes32 emptyRuleId) {
        universeRuleId = _universeRule;
        emptyRuleId = _emptyRule;
    }

    /**
     * @return count Number of existing Rules in the global list.
     */
    function ruleCount() external view override returns (uint256 count) {
        count = ruleSet.count();
    }

    /**
     * @param index Iterate rules in the global list.
     * @return ruleId The Id of a rule in the global list.
     */
    function ruleAtIndex(uint256 index) external view override returns (bytes32 ruleId) {
        if (index >= ruleSet.count())
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "ruleAtIndex",
                reason: "index out of range"
            });
        ruleId = ruleSet.keyAtIndex(index);
    }

    /**
     * @param ruleId The unique identifier of a rule. Each Policy has exactly one rule.
     * @return isIndeed True value if Rule exists, otherwise False.
     */
    function isRule(bytes32 ruleId) public view override returns (bool isIndeed) {
        isIndeed = ruleSet.exists(ruleId);
    }

    /**
     * @param ruleId The unique identifier of a rule. Each Policy has exactly one rule.
     * @dev Does not check existance.
     * @return description The description for a Base Rule.
     * @return uri Base Rule uri refers to detailed information about the Rule.
     * @return operator The expression operator (0-4), or Base (0)
     * @return operandCount The number of operands. 0 for Base rules.
     */
    function rule(bytes32 ruleId)
        external
        view
        override
        returns (
            string memory description,
            string memory uri,
            Operator operator,
            uint256 operandCount
        )
    {
        Rule storage r = rules[ruleId];
        return (r.description, r.uri, r.operator, r.operandSet.count());
    }

    /**
     * @param ruleId The Rule to inspect.
     * @dev Does not check existance.     
     * @return description The Rule description.
     */
    function ruleDescription(bytes32 ruleId)
        external
        view
        override
        returns (string memory description)
    {
        description = rules[ruleId].description;
    }

    /**
     * @param ruleId The Rule to inspect.
     * @dev Does not check existance.
     * @return uri The Rule uri.
     */
    function ruleUri(bytes32 ruleId) external view override returns (string memory uri) {
        uri = rules[ruleId].uri;
    }

    /**
     * @param ruleId The Rule to inspect.
     * @dev Does not check existance.     
     * @return operator The Rule operator.
     */
    function ruleOperator(bytes32 ruleId) external view override returns (Operator operator) {
        operator = rules[ruleId].operator;
    }

    /**
     * @param ruleId The Rule to inspect.
     * @dev Does not check Rule existance.
     * @return count The number of operands in the Rule expression.
     */
    function ruleOperandCount(bytes32 ruleId) external view override returns (uint256 count) {
        count = rules[ruleId].operandSet.count();
    }

    /**
     * @param ruleId The Rule to inspect.
     * @param index The operand list row to inspect.
     * @dev Does not check Rule existance.
     * @return operandId A Rule id.
     */
    function ruleOperandAtIndex(bytes32 ruleId, uint256 index)
        external
        view
        override
        returns (bytes32 operandId)
    {
        Rule storage r = rules[ruleId];
        if (index >= r.operandSet.count())
            revert Unacceptable({
                sender: _msgSender(),
                module: MODULE,
                method: "ruleOperandAtIndex",
                reason: "index out of range"
            });
        operandId = rules[ruleId].operandSet.keyAtIndex(index);
    }

    /**
     * @notice Generate a deterministic ruleId
     * @dev Warning: This does not validate the inputs
     * @return ruleId The ruleId that will be generated if the configuration is valid
     */
    function generateRuleId(
        string memory description,
        Operator operator,
        bytes32[] memory operands
    ) public pure override returns (bytes32 ruleId) {
        if (operands.length == 0) {
            // Base rule IDs are derived from immutable descriptions. No duplicates.
            ruleId = keccak256(bytes(description));
        } else {
            // algebraic rule IDs are derived from operator and operands. No duplicates.
            ruleId = keccak256(abi.encodePacked(operator, operands));
        }
    }

    /**
     * @return role The constant ROLE_RULE_ADMIN
     */
    function roleRuleAdmin() external pure override returns (bytes32 role) {
        role = ROLE_RULE_ADMIN;
    }
}
