# 실행

### 컨테이너
```bash
sudo docker run   -v /mnt/src:/doca   -v /dev/hugepages:/dev/hugepages   --privileged --net=host -it nvcr.io/nvidia/doca/doca:2.9.3-devel
```

### DOCA Program (Container)
```bash
./dpu_transfer -l 0-3 -n 2     -a auxiliary:mlx5_core.sf.6,dv_flow_en=2 -- -l 51