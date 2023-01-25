// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.14;

library PackLib {

    uint8 constant FIELD_SIZE = 20;
    uint256 constant MASK = 2 ** FIELD_SIZE - 1;

    /**
     @notice Pack 12 20-bit integers into a 240-bit object.
     @dev uint32 Inputs are truncated above 20 bits of magnitude.
     @param input Array of 20-bit integers to pack cast as an array of uint32. 
     **/
    function pack(uint32[12] calldata input) 
        internal pure returns(uint256 packed) 
    {
        packed = uint256(input[0]);
        packed = packed << FIELD_SIZE;
        packed = packed + input[1];
        packed = packed << FIELD_SIZE;
        packed = packed + input[2];
        packed = packed << FIELD_SIZE;
        packed = packed + input[3];
        packed = packed << FIELD_SIZE;
        packed = packed + input[4];
        packed = packed << FIELD_SIZE;
        packed = packed + input[5];
        packed = packed << FIELD_SIZE;
        packed = packed + input[6];
        packed = packed << FIELD_SIZE;
        packed = packed + input[7];
        packed = packed << FIELD_SIZE;
        packed = packed + input[8];
        packed = packed << FIELD_SIZE;
        packed = packed + input[9];
        packed = packed << FIELD_SIZE;
        packed = packed + input[10];
        packed = packed << FIELD_SIZE;
        packed = packed + input[11];        
    }

    /**
     @notice Unpack 12 20-bit integers from 240-bit input
     @dev Data beyond the first 240 bits is ignored.
     @param packed 12 20-bit integers packed into 240 bits.
     @return output 12 20-bit integers cast as an array of 32-bit integers.
     **/
    function unpack(uint256 packed) 
        public pure 
        returns(uint32[12] memory output)
    {
        output[11] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[10] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[9] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[8]= uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[7] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[6] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[5] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[4] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[3] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[2] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[1] = uint32(packed & MASK);
        packed = packed >> FIELD_SIZE;
        output[0] = uint32(packed);
    }
}
