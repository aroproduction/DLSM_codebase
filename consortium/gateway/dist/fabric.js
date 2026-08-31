import * as grpc from '@grpc/grpc-js';
import { connect, hash, signers } from '@hyperledger/fabric-gateway';
import { createPrivateKey } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
let connectionPromise;
function getTestNetworkPath() {
    const testNetworkPath = process.env.FABRIC_TEST_NETWORK;
    if (!testNetworkPath) {
        throw new Error('FABRIC_TEST_NETWORK must point to fabric-samples/test-network');
    }
    return testNetworkPath;
}
async function createConnection() {
    const testNetworkPath = getTestNetworkPath();
    const orgPath = path.join(testNetworkPath, 'organizations/peerOrganizations/org1.example.com');
    const identityName = process.env.FABRIC_IDENTITY ??
        'dlsm-gateway@org1.example.com';
    const identityPath = path.join(orgPath, 'users', identityName, 'msp');
    const certificate = await fs.readFile(path.join(identityPath, 'signcerts/cert.pem'));
    const keyDirectory = path.join(identityPath, 'keystore');
    const [keyFilename] = await fs.readdir(keyDirectory);
    if (!keyFilename) {
        throw new Error('No private key found for the Org1 gateway identity');
    }
    const privateKey = createPrivateKey(await fs.readFile(path.join(keyDirectory, keyFilename)));
    const tlsRootCertificate = await fs.readFile(path.join(orgPath, 'tlsca/tlsca.org1.example.com-cert.pem'));
    const client = new grpc.Client('localhost:7051', grpc.credentials.createSsl(tlsRootCertificate), {
        'grpc.ssl_target_name_override': 'peer0.org1.example.com'
    });
    const gateway = connect({
        client,
        identity: {
            mspId: 'Org1MSP',
            credentials: certificate
        },
        signer: signers.newPrivateKeySigner(privateKey),
        hash: hash.sha256
    });
    const contract = gateway
        .getNetwork('dlsmchannel')
        .getContract('dlsm');
    return {
        contract,
        close: () => {
            gateway.close();
            client.close();
        }
    };
}
export async function getDlsmContract() {
    connectionPromise ??= createConnection();
    return (await connectionPromise).contract;
}
export async function closeFabricConnection() {
    if (!connectionPromise) {
        return;
    }
    const connection = await connectionPromise;
    connection.close();
    connectionPromise = undefined;
}
