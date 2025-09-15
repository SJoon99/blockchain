const { ethers } = require("hardhat");
const fs = require('fs');

async function main() {
    console.log("Deploying S3LogStorage...");
    
    const [deployer] = await ethers.getSigners();
    console.log("Deployer:", deployer.address);
    
    const S3LogStorage = await ethers.getContractFactory("S3LogStorage");
    const contract = await S3LogStorage.deploy();
    await contract.waitForDeployment();

    const address = await contract.getAddress();
    console.log("S3LogStorage deployed to:", address);
    // 주소를 파일로 저장
    fs.writeFileSync('./contract-address.txt', address);
    
    // 테스트 저장
    const tx = await contract.storeLog("PUT", "test-bucket", "test.json", "admin", "test_data");
    await tx.wait();
    console.log("Test log stored!");
}

main().catch(console.error);