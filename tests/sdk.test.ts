import { assert, expect } from 'chai'
import { groth16 } from 'snarkjs';
import { generateCircuitInputsDisclose } from '../utils/generateInputs';
import { mockPassportData_sha256WithRSAEncryption_65537 } from '../utils/mockPassportData';
import { LeanIMT } from "@zk-kit/lean-imt";
import { poseidon2, poseidon6 } from "poseidon-lite";
import { PASSPORT_ATTESTATION_ID } from "../utils/constants";
import { formatMrz, packBytes } from '../utils/utils';
import { getLeaf } from '../utils/pubkeyTree';
import fs from 'fs';
const path_disclose_wasm = "./artifacts/disclose.wasm";
const path_disclose_zkey = "./artifacts/disclose_final.zkey";
const path_disclose_vkey = "./artifacts/disclose_vkey.json";

describe('Circuit Proving Tests', () => {
    it('should generate a valid proof for the disclose circuit', async () => {
        const passportData = mockPassportData_sha256WithRSAEncryption_65537;
        const imt = new LeanIMT((a: bigint, b: bigint) => poseidon2([a, b]), []);
        const bitmap = Array(90).fill("1");
        const scope = BigInt(1).toString();
        const majority = ["1", "8"];
        const secret = BigInt(0).toString();
        const attestation_id = PASSPORT_ATTESTATION_ID;
        const vKey = JSON.parse(fs.readFileSync(path_disclose_vkey) as unknown as string);

        const mrz_bytes = packBytes(formatMrz(passportData.mrz));
        const pubkey_leaf = getLeaf({
            signatureAlgorithm: passportData.signatureAlgorithm,
            modulus: passportData.pubKey.modulus,
            exponent: passportData.pubKey.exponent,
        }).toString();
        const commitment = poseidon6([
            secret,
            attestation_id,
            pubkey_leaf,
            mrz_bytes[0],
            mrz_bytes[1],
            mrz_bytes[2]
        ])
        imt.insert(commitment);

        const inputs = generateCircuitInputsDisclose(
            secret,
            attestation_id,
            passportData,
            imt as any,
            majority,
            bitmap,
            scope,
            BigInt(0).toString()
        );

        const { proof, publicSignals } = await groth16.fullProve(
            inputs,
            path_disclose_wasm,
            path_disclose_zkey
        );

        expect(proof).to.be.an('object');
        expect(publicSignals).to.be.an('array');
        const isProofValid = await groth16.verify(vKey, publicSignals, proof);
        expect(isProofValid).to.be.true;
    });
});
