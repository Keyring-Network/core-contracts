pragma circom 2.0.6;

include "./identity.circom";
include "./address.circom";

//Returns IdentityCommitment as poseidon Hash of identityTrapdoor, identityCreation, 
//policyCommitment and addressCommitment
template IdentityConstruction() {
    signal input identityTrapdoor;
    signal input identityCreation;
    signal input policyCommitment;
    
    signal input addresses[16];
    signal input max_addresses;
    
    signal output identityCommitment;
    
    component addresses_construction = AddressesConstruction();
    addresses_construction.max <== max_addresses;
    for(var i = 0; i < 16; i++) {
        addresses_construction.addresses[i] <== addresses[i];
    }
    
    component identity = Identity();
    identity.trapdoor <== identityTrapdoor;
    identity.creation <== identityCreation;
    identity.addressCommitment <== addresses_construction.out;
    identity.policyCommitment <== policyCommitment;
    
    identityCommitment <== identity.out;
}