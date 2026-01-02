import { task } from 'hardhat/config'
import { MockZkVerifier, MockQueryDecrypter, MockNetwork, ACL, Example } from '../typechain-types'
import { execSync } from 'child_process'
import fs from 'fs/promises'
import { anvilSetCode, FHE_NETWORK_ADDRESS, ZK_VERIFIER_ADDRESS, QUERY_DECRYPTER_ADDRESS, EXAMPLE_FHE_COUNTER_ADDRESS } from './utils'
import { HardhatRuntimeEnvironment } from 'hardhat/types'

const deployMockNetwork = async (hre: HardhatRuntimeEnvironment) => {
	const [signer] = await hre.ethers.getSigners()

	console.log('FHE Network')

	// Deploy MockNetwork
	const networkBytecode = await fs.readFile('./out/MockNetwork.sol/MockNetwork.json', 'utf8')
	const networkJson = JSON.parse(networkBytecode)
	await anvilSetCode(FHE_NETWORK_ADDRESS, networkJson.deployedBytecode.object)
	const mockNetwork: MockNetwork = await hre.ethers.getContractAt('MockNetwork', FHE_NETWORK_ADDRESS)
	console.log('  - deployed')

	// Initialize MockNetwork
	const initTx = await mockNetwork.initialize(signer.address)
	await initTx.wait()
	console.log('  - initialized')

	const networkExists = await mockNetwork.exists()
	console.log('  - exists', networkExists ? 'yes' : 'no')

	console.log('  - address:', await mockNetwork.getAddress())

	return mockNetwork
}

const deployMockACL = async (hre: HardhatRuntimeEnvironment) => {
	// Get Signer
	const [signer] = await hre.ethers.getSigners()

	console.log('ACL')

	// Deploy ACL implementation
	const aclFactory = await hre.ethers.getContractFactory('ACL')
	const aclImplementation = await aclFactory.deploy()
	await aclImplementation.waitForDeployment()
	console.log('  - implementation deployed')

	// Encode initialization data
	const aclInitData = aclImplementation.interface.encodeFunctionData('initialize', [signer.address])

	// Deploy ERC1967 Proxy
	const ERC1967Proxy = await hre.ethers.getContractFactory('ERC1967Proxy')
	const proxy = await ERC1967Proxy.deploy(await aclImplementation.getAddress(), aclInitData)
	await proxy.waitForDeployment()
	console.log('  - proxy deployed')

	// Get ACL instance at proxy address
	const acl: ACL = await hre.ethers.getContractAt('ACL', await proxy.getAddress())
	console.log('  - address:', await acl.getAddress())

	return acl
}

const deployMockZkVerifier = async (hre: HardhatRuntimeEnvironment) => {
	console.log('ZkVerifier')

	const zkVerifierBytecode = await fs.readFile('./out/MockZkVerifier.sol/MockZkVerifier.json', 'utf8')
	const zkVerifierJson = JSON.parse(zkVerifierBytecode)
	await anvilSetCode(ZK_VERIFIER_ADDRESS, zkVerifierJson.deployedBytecode.object)
	const zkVerifier: MockZkVerifier = await hre.ethers.getContractAt('MockZkVerifier', ZK_VERIFIER_ADDRESS)
	console.log('  - deployed')

	const zkVerifierExists = await zkVerifier.exists()
	console.log('  - exists', zkVerifierExists ? 'yes' : 'no')

	console.log('  - address:', await zkVerifier.getAddress())

	return zkVerifier
}

const deployMockQueryDecrypter = async (hre: HardhatRuntimeEnvironment, acl: ACL) => {
	console.log('QueryDecrypter')

	const queryDecrypterBytecode = await fs.readFile('./out/MockQueryDecrypter.sol/MockQueryDecrypter.json', 'utf8')
	const queryDecrypterJson = JSON.parse(queryDecrypterBytecode)
	await anvilSetCode(QUERY_DECRYPTER_ADDRESS, queryDecrypterJson.deployedBytecode.object)
	const queryDecrypter: MockQueryDecrypter = await hre.ethers.getContractAt('MockQueryDecrypter', QUERY_DECRYPTER_ADDRESS)
	console.log('  - deployed')

	const queryDecrypterExists = await queryDecrypter.exists()
	console.log('  - exists', queryDecrypterExists ? 'yes' : 'no')

	// Initialize MockQueryDecrypter
	const initTx = await queryDecrypter.initialize(FHE_NETWORK_ADDRESS, await acl.getAddress())
	await initTx.wait()
	console.log('  - initialized')

	console.log('  - address:', await queryDecrypter.getAddress())

	return queryDecrypter
}

const deployExampleFHECounter = async (hre: HardhatRuntimeEnvironment) => {
	console.log('ExampleFHECounter')

	const exampleBytecode = await fs.readFile('./out/Example.sol/Example.json', 'utf8')
	const exampleJson = JSON.parse(exampleBytecode)
	await anvilSetCode(EXAMPLE_FHE_COUNTER_ADDRESS, exampleJson.deployedBytecode.object)
	const example: Example = await hre.ethers.getContractAt('Example', EXAMPLE_FHE_COUNTER_ADDRESS)
	console.log('  - deployed')

	console.log('  - address:', await example.getAddress())

	return example
}

const setNetworkACL = async (mockNetwork: MockNetwork, acl: ACL) => {
	const setAclTx = await mockNetwork.setACLContract(await acl.getAddress())
	await setAclTx.wait()
	console.log('FHE Network ACL set')
}

task('deploy-mocks-on-anvil', 'Runs a script on the Anvil network').setAction(async (taskArgs, hre) => {
	console.log('Deploy Mocks On Anvil... \n')

	const network = hre.network.name
	if (network !== 'anvil') {
		console.log(`This task is intended to run on the Anvil network. Current network: ${network}`)
		return
	}

	await hre.run('compile')
	await execSync('forge compile')

	const mockNetwork = await deployMockNetwork(hre)
	const acl = await deployMockACL(hre)

	console.log('FHE Network Exists', await mockNetwork.getAddress(), await mockNetwork.exists())
	await setNetworkACL(mockNetwork, acl)
	const zkVerifier = await deployMockZkVerifier(hre)
	const queryDecrypter = await deployMockQueryDecrypter(hre, acl)

	const example = await deployExampleFHECounter(hre)
	const [sender, backup, bob] = await hre.ethers.getSigners()
	console.log('Bob Address', await bob.getAddress())
	await example.connect(bob).setNumberTrivial(10)

	const numberHash = await example.numberHash()
	console.log('Number Hash', numberHash)

	console.log('Done!')
})
