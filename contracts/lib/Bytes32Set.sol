// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.14;

/**
 * @notice Key sets with enumeration. Uses mappings for random and existence checks
 * and dynamic arrays for enumeration. Key uniqueness is enforced.
 * @dev Sets are unordered.
 */

library Bytes32Set {
    struct Set {
        mapping(bytes32 => uint256) keyPointers;
        bytes32[] keyList;
    }

    string private constant MODULE = "Bytes32Set";

    error SetConsistency(string module, string method, string reason, string context);

    /**
     * @notice Insert a key to store.
     * @dev Duplicate keys are not permitted.
     * @param self A Bytes32Set struct - similar syntax to python classes.
     * @param key A value in the Bytes32Set.
     * @param context A message string about interpretation of the issue.
     */
    function insert(
        Set storage self,
        bytes32 key,
        string memory context
    ) internal {
        if (exists(self, key))
            revert SetConsistency({
                module: MODULE,
                method: "insert",
                reason: "exists",
                context: context
            });
        self.keyList.push(key);
        self.keyPointers[key] = self.keyList.length - 1;
    }

    /**
     * @notice Count the keys.
     * @param self A Bytes32Set struct - similar syntax to python classes.
     * @return uint256 Length of the `keyList`, which correspond to the number of elements
     * stored in the `keyPointers` mapping.
     */
    function count(Set storage self) internal view returns (uint256) {
        return (self.keyList.length);
    }

    /**
     * @notice Check if a key exists in the Set.
     * @param self A Bytes32Set struct - similar syntax to python classes.
     * @param key A value in the Bytes32Set.
     * @return bool True if key exists in the Set, otherwise false.
     */
    function exists(Set storage self, bytes32 key) internal view returns (bool) {
        if (self.keyList.length == 0) return false;
        return self.keyList[self.keyPointers[key]] == key;
    }

    /**
     * @notice Retrieve an bytes32 by its key.
     * @param self A Bytes32Set struct - similar syntax to python classes.
     * @param index The internal index of the keys
     * @return bytes32 The bytes32 value stored in a `keyList`.
     */
    function keyAtIndex(Set storage self, uint256 index) internal view returns (bytes32) {
        return self.keyList[index];
    }
}
