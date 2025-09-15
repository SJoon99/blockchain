// tcp_server.js
const net = require('net');

// TCP 서버 생성
const server = net.createServer((socket) => {
    console.log('Client connected:', socket.remoteAddress, socket.remotePort);

    // 데이터 수신
    socket.on('data', (data) => {
        console.log('Received:', data.toString());

        // 응답 보내기 (필요시)
        socket.write('ACK from Node.js server');
    });

    // 클라이언트 종료 시
    socket.on('end', () => {
        console.log('Client disconnected');
    });

    // 에러 처리
    socket.on('error', (err) => {
        console.error('Socket error:', err);
    });
});

// 포트 8000에서 대기
server.listen(8000, '0.0.0.0', () => {
    console.log('TCP server listening on port 8000');
});
