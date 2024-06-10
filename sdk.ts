import { groth16 } from 'snarkjs';
import fs from 'fs';
import { attributeToPosition, countryCodes, DEFAULT_RPC_URL, REGISTER_ABI, REGISTER_CONTRACT_ADDRESS } from './utils/constants';
import { ethers } from 'ethers';
import { getCurrentDateYYMMDD } from './utils/utils';

const path_disclose_wasm = "./artifacts/disclose_js/disclose.wasm";
const path_disclose_zkey = "./artifacts/disclose_final.zkey";
const path_disclose_vkey = "./artifacts/disclose_vkey.json";

class ProofOfPassportWeb2Verifier {
    scope: string;
    attestationId: number;
    requirements: Array<[string, number | string]>;
    rpcUrl: string;

    constructor(scope: string, attestationId: number, requirements: Array<[string, number | string]>, rpcUrl: string = DEFAULT_RPC_URL) {
        this.scope = scope;
        this.attestationId = attestationId;
        this.requirements = requirements.map(requirement => {
            if (!attributeToPosition.hasOwnProperty(requirement[0])) {
                throw new Error(`Attribute ${requirement[0]} is not recognized.`);
            }
            return requirement;
        });
        this.rpcUrl = rpcUrl;
    }

    async verifyInputs(publicSignals, proof) {
        const parsedPublicSignals = parsePublicSignals(publicSignals);
        //1. Verify the scope
        if (parsedPublicSignals.scope !== this.scope) {
            throw new Error(`Scope ${parsedPublicSignals.scope} does not match the scope ${this.scope}`);
        }
        //2. Verify the merkle_root
        const merkleRootIsValid = await checkMerkleRoot(this.rpcUrl, parsedPublicSignals.merkle_root);
        if (!merkleRootIsValid) {
            throw new Error(`Merkle root ${parsedPublicSignals.merkle_root} does not match the merkle root ${parsedPublicSignals.merkle_root}`);
        }
        //3. Verify the attestation_id
        if (parsedPublicSignals.attestation_id !== this.attestationId) {
            throw new Error(`Attestation id ${parsedPublicSignals.attestation_id} does not match the attestation id ${this.attestationId}`);
        }
        //4. Verify the current_date
        if (parsedPublicSignals.current_date !== getCurrentDateFormatted) {
            throw new Error(`Current date ${parsedPublicSignals.current_date} does not match the current date ${new Date().toISOString()}`);
        }
        //5. Verify requirements
        for (const requirement of this.requirements) {
            const attribute = requirement[0];
            const value = requirement[1];

            const position = attributeToPosition[attribute];
            let attributeValue = '';
            for (let i = position[0]; i <= position[1]; i++) {
                attributeValue += String.fromCharCode(parsedPublicSignals.revealedData_packed[i]);
            }
            if (requirement[0] === "nationality" || requirement[0] === "issuing_state") {
                if (!countryCodes[attributeValue] || countryCodes[attributeValue] !== value) {
                    throw new Error(`Attribute ${attribute} does not match the value ${value}`);
                }
            }
            else {
                if (attributeValue !== value) {
                    throw new Error(`Attribute ${attribute} does not match the value ${value}`);
                }
            }
        }

        //6. Verify the proof
        const vkey_disclose = JSON.parse(fs.readFileSync(path_disclose_vkey) as unknown as string);
        const verified_disclose = await groth16.verify(
            vkey_disclose,
            publicSignals,
            proof
        )

        //7. Nullifier Management
        //...

    }
}

function getCurrentDateFormatted() {
    return getCurrentDateYYMMDD().map(datePart => BigInt(datePart).toString());
}

async function checkMerkleRoot(rpcUrl: string, merkleRoot: number) {
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const contract = new ethers.Contract(REGISTER_CONTRACT_ADDRESS, REGISTER_ABI, provider);
    return await contract.merkleRootsCreated(merkleRoot);
}

function parsePublicSignals(publicSignals) {
    return {
        nullifier: publicSignals[0],
        revealedData_packed: [publicSignals[1], publicSignals[2], publicSignals[3]],
        attestation_id: publicSignals[4],
        merkle_root: publicSignals[5],
        scope: publicSignals[6],
        current_date: publicSignals[7],
        user_identifier: publicSignals[8],
    }
}



