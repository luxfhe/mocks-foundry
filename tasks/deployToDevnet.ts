import { task } from 'hardhat/config'
import { HardhatRuntimeEnvironment } from 'hardhat/types'

task('deploy-to-devnet', 'Deploy FHE contracts to devnet').setAction(async (taskArgs, hre: HardhatRuntimeEnvironment) => {
	console.log('Deploying to devnet...\n')

	const network = hre.network.name
	if (network !== 'devnet') {
		console.log(`This task is intended for devnet. Current network: ${network}`)
		return
	}

	await hre.run('compile')

	const [signer] = await hre.ethers.getSigners()
	console.log('Deployer:', await signer.getAddress())
	console.log('Balance:', hre.ethers.formatEther(await hre.ethers.provider.getBalance(signer.address)))

	// Deploy ACL implementation
	console.log('\nDeploying ACL...')
	const aclFactory = await hre.ethers.getContractFactory('ACL')
	const aclImplementation = await aclFactory.deploy()
	await aclImplementation.waitForDeployment()
	console.log('  Implementation:', await aclImplementation.getAddress())

	// Encode initialization data
	const aclInitData = aclImplementation.interface.encodeFunctionData('initialize', [signer.address])

	// Deploy ERC1967 Proxy
	const ERC1967Proxy = await hre.ethers.getContractFactory('ERC1967Proxy')
	const proxy = await ERC1967Proxy.deploy(await aclImplementation.getAddress(), aclInitData)
	await proxy.waitForDeployment()
	const aclAddress = await proxy.getAddress()
	console.log('  Proxy (ACL):', aclAddress)

	// Get ACL instance at proxy address
	const acl = await hre.ethers.getContractAt('ACL', aclAddress)

	console.log('\n=== Deployment Summary ===')
	console.log('ACL_CONTRACT_ADDRESS=' + aclAddress)
	console.log('KMS_VERIFIER_CONTRACT_ADDRESS=' + aclAddress)
	console.log('INPUT_VERIFIER_CONTRACT_ADDRESS=' + aclAddress)
	console.log('\nUpdate .env.devnet with these addresses')
})
