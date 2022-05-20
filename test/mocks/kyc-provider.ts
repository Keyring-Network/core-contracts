import { ethers, waffle } from "hardhat"
import { string } from "hardhat/internal/core/params/argumentTypes"

export const checkUserKYC = async (user: string, forceFail: boolean, forceServerErr: boolean) => {
    if(forceServerErr) {
        return "{}"
    }

    const schema: any = {}
    schema.id = "ABC123"
    schema.entityName = "John Doe"
    schema.entityAddress = user
    schema.status = pickRandom(["complete", "processing", "invalid"])
    schema.result = {}
    schema.result.outcome = forceFail ? "attention" : pickRandom(["clear", "attention", "invalid"])
    schema.result.riskLevel = forceFail ? 0 : (Math.floor(Math.random() * 100) + 1)
    schema.result.screening = {}
    schema.result.screening.sanctionLists = forceFail ? "attention" : pickRandom(["clear", "attention", "invalid"])
    schema.result.screening.criminalRecords = forceFail ? "attention" : pickRandom(["clear", "attention", "invalid"])
    schema.result.screening.fiscalRecords = forceFail ? "attention" : pickRandom(["clear", "attention", "invalid"])
    schema.result.screening.pep = forceFail ? "class-1" : pickRandom(["clear", "class-1", "class-2", "class-3", "class-4", "invalid"])
    schema.result.screening.alive = forceFail ? "false" : (Math.random() < 0.5)
    schema.result.locations = [{}]
    schema.result.locations[0].type = "residentOf"
    schema.result.locations[0].country = forceFail ? "us" : pickRandom(["us", "uk", "it", "de", "ca"])
    schema.result.authentication = [{}]
    schema.result.authentication[0].id = "idkey:passport:ie"
    schema.result.authentication[0].type = "Ed25519VerificationKey2020"
    schema.result.authentication[0].controller = "keyring:abc/123"
    schema.result.authentication[0].publicKeyMultibase = "H$AlO"
    schema.created_at = Date.now()
    schema.updated_at = Date.now()

    const jsonMessage = JSON.stringify(schema)

    const provider = waffle.provider
    const [wallet] = provider.getWallets()
    let messageHash = ethers.utils.solidityKeccak256(['string'], [jsonMessage]);
    let signature = await wallet.signMessage(ethers.utils.arrayify(messageHash));

    let response: any = {}
    response.data = jsonMessage
    response.signature = signature

    return response
}

const pickRandom = (arr: any) => {
    return arr[Math.floor(Math.random() * arr.length)];
}
