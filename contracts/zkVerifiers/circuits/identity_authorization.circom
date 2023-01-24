pragma circom 2.0.6;

include "./identity.circom";
include "./address.circom";
include "./policy.circom";
include "./verify_nullifier.circom";

//Returns nothing but validates policyCommitment, addressCommitment
//nullifierHash is validated with generated identityCommitment and external nullifier
template IdentityAuthorisation(nPolicyElements, nDisclosureElements) {
    signal input identityTrapdoor;
    signal input identityCreation;
    signal input externalNullifier;
    signal input nullifierHash;
    
    //PolicyCommitment
    signal input policyElements[nPolicyElements];
    signal input policyDisclosures[nDisclosureElements];
    
    component policy_proof = Policies(nPolicyElements, nDisclosureElements);
    for(var i = 0; i < nPolicyElements; i++) {
        policy_proof.policyElements[i] <== policyElements[i];
    }
    for(var i = 0; i < nDisclosureElements; i++) {
        policy_proof.policyDisclosures[i] <== policyDisclosures[i];
    }
    
    //AddressCommitment
    signal input addresses[16];
    signal input address;
    
    component address_proof = Addresses();
    address_proof.address <== address;
    for(var i = 0; i < 16; i++) {
        address_proof.addresses[i] <== addresses[i];
    }
    
    component identity = IdentityNullifier();
    identity.trapdoor <== identityTrapdoor;
    identity.creation <== identityCreation;
    identity.policyCommitment <== policy_proof.out;
    identity.addressCommitment <== address_proof.out;
    
    component verify_nullifier = VerifyNullifier();
    verify_nullifier.identityNullifier <== identity.out;
    verify_nullifier.externalNullifier <== externalNullifier;
    verify_nullifier.nullifierHash <== nullifierHash;
}