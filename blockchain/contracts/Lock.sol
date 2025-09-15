// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract S3LogStorage {
    struct S3Log {
        uint256 timestamp;
        string method;
        string bucket;
        string key;
        string akid;
    }
    
    event LogStored(uint256 indexed id, string method, string bucket, string akid);
    
    mapping(uint256 => S3Log) public logs;
    uint256 public logCount;
    
    function storeLog(
        string memory method,
        string memory bucket, 
        string memory key,
        string memory akid
    ) public returns (uint256) {
        logs[logCount] = S3Log({
            timestamp: block.timestamp,
            method: method,
            bucket: bucket,
            key: key,
            akid: akid
        });
        
        emit LogStored(logCount, method, bucket, akid);
        logCount++;
        
        return logCount - 1;
    }
    
    function getLog(uint256 id) public view returns (S3Log memory) {
        return logs[id];
    }
    
    // 특정 사용자의 로그 조회
    function getLogsByUser(string memory akid) public view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](logCount);
        uint256 count = 0;
        
        for (uint256 i = 0; i < logCount; i++) {
            if (keccak256(bytes(logs[i].akid)) == keccak256(bytes(akid))) {
                result[count] = i;
                count++;
            }
        }
        
        // 결과 배열 크기 조정
        uint256[] memory userLogs = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            userLogs[i] = result[i];
        }
        
        return userLogs;
    }
}