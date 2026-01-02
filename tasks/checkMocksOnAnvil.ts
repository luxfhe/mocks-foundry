import { task } from 'hardhat/config'
import { FHE_NETWORK_ADDRESS, ZK_VERIFIER_ADDRESS, QUERY_DECRYPTER_ADDRESS } from './utils'

task('check-mocks-on-anvil', 'Checks if the mocks are deployed on Anvil').setAction(async (taskArgs, hre) => {
	const network = hre.network.name
	if (network !== 'anvil') {
		console.log(`This task is intended to run on the Anvil network. Current network: ${network}`)
		return
	}

	const mockNetwork = await hre.ethers.getContractAt('MockNetwork', FHE_NETWORK_ADDRESS)
	const acl = await hre.ethers.getContractAt('ACL', await mockNetwork.acl())
	const zkVerifier = await hre.ethers.getContractAt('MockZkVerifier', ZK_VERIFIER_ADDRESS)
	const queryDecrypter = await hre.ethers.getContractAt('MockQueryDecrypter', QUERY_DECRYPTER_ADDRESS)

	console.log('\t! FHE Network exists:', await mockNetwork.exists())
	console.log('\t! ACL exists:', await acl.exists())
	console.log('\t! ZkVerifier exists:', await zkVerifier.exists())
	console.log('\t! QueryDecrypter exists:', await queryDecrypter.exists())
})
