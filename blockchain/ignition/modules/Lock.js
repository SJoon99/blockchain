const { ethers } = require("hardhat");

async function main() {
    console.log("Deploying S3LogStorage...");
    
    const [deployer] = await ethers.getSigners();
    console.log("Deployer:", deployer.address);
    
    const S3LogStorage = await ethers.getContractFactory("S3LogStorage");
    const contract = await S3LogStorage.deploy();
    await contract.waitForDeployment();
    
    console.log("Contract deployed to:", await contract.getAddress());
    
    // 테스트 저장
    const tx = await contract.storeLog("PUT", "test-bucket", "test.json", "admin", "test_data");
    await tx.wait();
    console.log("Test log stored!");
}

main().catch(console.error);