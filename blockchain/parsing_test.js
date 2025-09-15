// 간단한 파서 테스트
const sampleLog = `
GET /blockchain/?location= HTTP/1.1
Host: 10.197.0.11:9000
Authorization: AWS4-HMAC-SHA256 Credential=admin/20250831/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123
`;

function parseMinIOLog(rawData) {
    const httpMatch = rawData.match(/(GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)/);
    if (!httpMatch) return null;
    
    const method = httpMatch[1];
    const path = httpMatch[2];
    
    const pathParts = path.split('/').filter(p => p);
    const bucket = pathParts[0] || '';
    const key = pathParts.slice(1).join('/') || '';
    
    const authMatch = rawData.match(/Credential=([^/]+)/);
    const akid = authMatch ? authMatch[1] : 'unknown';
    
    return { method, bucket, key, akid };
}

// 테스트
const result = parseMinIOLog(sampleLog);
console.log("Parsed:", result);
// 출력: { method: 'GET', bucket: 'blockchain', key: '', akid: 'admin' }