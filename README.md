## MinIO S3 Log → Blockchain

- MinIO의 **S3 API 요청 로그**를 **DPU(DOCA/DPDK)**에서 와이어-스피드로 캡처
- 재조립된 **첫 번째 TCP 청크**(요청라인+헤더)를 TCP 소켓으로 블록체인 노드에 전송
- 블록체인 노드는 요청을 파싱해 **메서드 / 버킷 / 키 / AKID** 등 **핵심 메타데이터만 온체인 기록**

> **핵심 가치**
> 
> - **DPU 오프로딩**으로 네트워크 레이어의 재조립/청크/전송을 DPU가 수행 → **호스트 CPU 부하 최소**
> - **불변성**: 온체인 앵커(타임스탬프 포함)로 **사후 조작 불가** 감사 트레일 확보
> - **프라이버시/비용 균형**: 페이로드 대신 **메타데이터만** 저장

---

### 아키텍처

```
[S3 Client] → [MinIO]
         ↘ 
           (패킷 미러링)
        [DPU: 재조립·청크화]
               ↓ (첫 청크 TCP 전송)
        [Node.js 서버: 파싱 후 storeLog()]
               ↓
          [Ethereum/Hardhat]
```

- **DPU**: TCP 재조립, 16KB 청크, 첫 청크만 전송
- **Node.js**: 요청 파싱, `storeLog` 트랜잭션 실행
- **스마트컨트랙트**: 불변 메타데이터 저장 (`method`, `bucket`, `key`, `akid`, `timestamp`)

---

## 프로젝트 구조

```bash
blockchain_poc/
├── blockchain/
│   ├── contracts/  # Solidity 컨트렉트
│   │   └── Lock.sol
│   ├── scripts/  # 베포/서버/조회 스크립트
│   │   ├── deploy.js
│   │   ├── socketToBlockchain.js
│   │   └── query.js
│   ├── test/
│   │   └── Lock.js
│   ├── hardhat.config.js
│   └── package.json
└── DOCA/
    └── projects
        ├── dpu
        │   ├── dataplane.c
        │   ├── main.c
        │   ├── meson.build
        │   └── README.md
        ├── flow_common.c
        ├── flow_common.h
        ├── host
        └── meson.build

```

---

## 실행 방법

### 1) 환경 설정

```bash
cd blockchain
npm init -y
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npm install ws
npx hardhat init  # JavaScript 프로젝트 선택
```

---

### 2) 테스트 실행

```bash
# 컨트랙트 로직 검증
npx hardhat test
```

---

### 3) 배포 및 실행

**터미널 1** — 로컬 블록체인 네트워크

```bash
npx hardhat node
```

**터미널 2** — 컨트랙트 배포(최초 1회)

```bash
npx hardhat run scripts/deploy.js --network localhost
```

**터미널 3** — TCP 서버 실행(블록체인 노드 측)

```bash
npx hardhat run scripts/socketToBlockchain.js --network localhost
```

> 이 TCP 서버가 DPU의 전송을 먼저 받아야 하므로, 반드시 터미널 3을 먼저 실행

---

### **4) DPU 실행 (컨테이너)**

```bash
sudo docker run \
  -v /mnt/src:/doca \
  -v /dev/hugepages:/dev/hugepages \
  --privileged --net=host -it \
  nvcr.io/nvidia/doca/doca:2.9.3-devel

# 컨테이너 내부
cd /doca/projects/dpu
meson /tmp/build
ninja -C /tmp/build

# DOCA 프로그램 실행
./dpu_transfer -l 0-3 -n 2 \
  -a auxiliary:mlx5_core.sf.6,dv_flow_en=2 -- -l 50

```

> 코드 상 TCP 목적지는 10.38.36.32:8000로 하드코딩되어 있음
> 
> 
> **노드 서버(터미널 3)의 IP:PORT와 일치하도록 수정**
> (예: `tcp_connect_once("127.0.0.1", 8000)`)
> 

---

### 5) Minio로 실제 전송

```bash
# 샘플 객체 DPU가 설치된 노드에 업로드
mc cp ./payload_sample.json myminio/blockchain
mc cp ./298643_small.mp4   myminio/blockchain#
```

---

### 6) 온체인 조회 (선택)

**터미널 4** — 데이터 조회

```bash
npx hardhat run scripts/query.js --network localhost
```

---

## 프로젝트의 의미

- **불변성 보장**: 요청 로그의 핵심 메타데이터를 블록체인에 기록해 **사후 조작 불가능**한 감사 트레일 확보
- **최소한의 공개**: 전체 페이로드 대신 메서드/버킷/키/AKID만 저장 → **프라이버시와 비용 절감**
- **DPU 오프로딩**: 네트워크 레벨에서 **DPU가 모든 재조립/청크/전송을 처리**, **호스트 노드 CPU는 거의 부하 없음**
- **실시간 앵커링**: MinIO API 요청이 발생하는 즉시 **블록체인에 앵커**되어 무결성과 신뢰성 확보
