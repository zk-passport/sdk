import { PUBKEY_TREE_DEPTH } from "./constants";
import { PassportData } from "./types";
import {
    formatMrz,
    getCurrentDateYYMMDD,
    generateMerkleProof
} from "./utils";
import { LeanIMT } from "@zk-kit/lean-imt";
import { getLeaf } from "./pubkeyTree";
import { poseidon6 } from "poseidon-lite";
import { packBytes } from "./utils";


export function generateCircuitInputsDisclose(
    secret: string,
    attestation_id: string,
    passportData: PassportData,
    merkletree: LeanIMT,
    majority: string[],
    bitmap: string[],
    scope: string,
    user_identifier: string,
) {
    const pubkey_leaf = getLeaf({
        signatureAlgorithm: passportData.signatureAlgorithm,
        modulus: passportData.pubKey.modulus,
        exponent: passportData.pubKey.exponent,
    });

    const formattedMrz = formatMrz(passportData.mrz);
    const mrz_bytes = packBytes(formattedMrz);
    const commitment = poseidon6([
        secret,
        attestation_id,
        pubkey_leaf,
        mrz_bytes[0],
        mrz_bytes[1],
        mrz_bytes[2]
    ]);

    // console.log('commitment', commitment.toString());

    const index = findIndexInTree(merkletree, commitment);

    const { merkleProofSiblings, merkleProofIndices, depthForThisOne } = generateMerkleProof(merkletree, index, PUBKEY_TREE_DEPTH)

    return {
        secret: [secret],
        attestation_id: [attestation_id],
        pubkey_leaf: [pubkey_leaf.toString()],
        mrz: formattedMrz.map(byte => String(byte)),
        merkle_root: [merkletree.root.toString()],
        merkletree_size: [BigInt(depthForThisOne).toString()],
        path: merkleProofIndices.map(index => BigInt(index).toString()),
        siblings: merkleProofSiblings.map(index => BigInt(index).toString()),
        bitmap: bitmap,
        scope: [scope],
        current_date: getCurrentDateYYMMDD().map(datePart => BigInt(datePart).toString()),
        majority: majority.map(char => BigInt(char.charCodeAt(0)).toString()),
        user_identifier: [user_identifier],
    };
}
function findIndexInTree(tree: LeanIMT, commitment: bigint): number {
    let index = tree.indexOf(commitment);
    if (index === -1) {
        index = tree.indexOf(commitment.toString() as unknown as bigint);
    }
    if (index === -1) {
        throw new Error("This commitment was not found in the tree");
    } else {
        // console.log(`Index of commitment in the registry: ${index}`);
    }
    return index;
}