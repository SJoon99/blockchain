const { ethers } = require("hardhat");
const net = require('net');
const fs = require('fs');

let contract;

async function init() {
    const [signer] = await ethers.getSigners();
    const contractAddress = fs.readFileSync('./contract-address.txt', 'utf8').trim();
    const S3LogStorage = await ethers.getContractFactory("S3LogStorage");
    contract = S3LogStorage.attach(contractAddress);
    console.log("Contract ready:", contractAddress);
}

// 핵심 정보만 추출
function parseRequest(requestData) {
    const firstLine = requestData.split('\n')[0];
    const methodMatch = firstLine.match(/^(GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)/);
    if (!methodMatch) return null;
    
    const method = methodMatch[1];
    const path = methodMatch[2].split('?')[0];
    const pathParts = path.split('/').filter(p => p);
    
    const bucket = pathParts[0] || '';
    const key = pathParts.slice(1).join('/') || '';
    
    // 사용자 ID 추출
    const credMatch = requestData.match(/Credential=([^/]+)/);
    const akid = credMatch ? credMatch[1] : 'unknown';
    
    // 타임스탬프 추출
    const dateMatch = requestData.match(/X-Amz-Date:\s*(\d{8}T\d{6}Z)/);
    const timestamp = dateMatch ? dateMatch[1] : '';
    
    return { method, bucket, key, akid, timestamp };
}

const server = net.createServer((socket) => {
    console.log('Client connected');
    
    socket.on('data', async (data) => {
        // HTTP 요청들을 분리
        const requests = data.toString().split(/(?=(?:GET|POST|PUT|DELETE|HEAD)\s+\/)/).filter(r => r.trim());
        
        let stored = 0;
        for (const request of requests) {
            const parsed = parseRequest(request);
            if (!parsed) continue;
            
            try {
                const tx = await contract.storeLog(
                    parsed.method,
                    parsed.bucket, 
                    parsed.key,
                    parsed.akid
                );
                await tx.wait();
                stored++;
                
                console.log(`${parsed.method} ${parsed.bucket}/${parsed.key} by ${parsed.akid}`);
                
            } catch (error) {
                console.log('Store failed:', error.message);
            }
        }
        
        const total = await contract.logCount();
        console.log(`Stored: ${stored}/${requests.length}, Total: ${total}`);
        socket.write(`OK: ${stored} stored\n`);
    });
    
    socket.on('end', () => console.log('Client disconnected'));
    socket.on('error', (err) => console.log('Error:', err.message));
});

init().then(() => {
    server.listen(8000, () => {
        console.log('MinIO Log Server running on port 8000');
    });
}).catch(console.error);