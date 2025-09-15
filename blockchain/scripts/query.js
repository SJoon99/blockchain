const { ethers } = require("hardhat");
const fs = require('fs');

async function queryLogs() {
    // 동적 주소 로드
    if (!fs.existsSync('./contract-address.txt')) {
        throw new Error("Contract not deployed! Run: npx hardhat run scripts/deploy.js --network localhost");
    }
    
    const contractAddress = fs.readFileSync('./contract-address.txt', 'utf8').trim();
    
    const [signer] = await ethers.getSigners();
    const S3LogStorage = await ethers.getContractFactory("S3LogStorage");
    const contract = S3LogStorage.attach(contractAddress);
    
    console.log("=== 저장된 로그 조회 ===");
    console.log(`Contract Address: ${contractAddress}`);
    
    const logCount = await contract.logCount();
    console.log(`총 로그 개수: ${logCount}`);
    
    for (let i = 0; i < logCount; i++) {
        const log = await contract.getLog(i);
        console.log(`\n로그 #${i}:`);
        console.log(`- 메서드: ${log.method}`);
        console.log(`- 버킷: ${log.bucket}`);
        console.log(`- 키: ${log.key}`);
        console.log(`- 사용자: ${log.akid}`);
        console.log(`- 시간: ${new Date(Number(log.timestamp) * 1000).toLocaleString()}`);
    }
}

queryLogs().catch(console.error);