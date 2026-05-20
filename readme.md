测试

哥伦比亚  1219879811313
哥#####  2BDC197182190981

DCC_DEBUG=1 \
DCC_CSV_PATH=/Users/lee/codes/dcc_cpp/table_data.csv \
DCC_OUTPUT_DIR=/tmp/dcc_test/ \
DCC_CALLBACK_URL=skip \
DCC_HW_INFO=1 \
DCC_CSV_STATS=1 \
DCC_PORT=8081 \
./build/dcc_encrypt

# 自有服务器
DCC_DEBUG=1 \
DCC_CSV_PATH=/root/dcc_cpp/data/test_input.csv \
DCC_OUTPUT_DIR=/tmp/dcc_test/ \
DCC_CALLBACK_URL=skip \
DCC_HW_INFO=1 \
DCC_CSV_STATS=1 \
DCC_PORT=8081 \
./build/dcc_encrypt

chmod 777 /root/dcc_cpp/build/dcc_encrypt ; nohup env DCC_TEAM_CODE=team077 DCC_OUTPUT_DIR='/root/dcc_cpp/output/' DCC_CSV_PATH='/root/dcc_cpp/data/test_input.csv' DCC_DEBUG=1 DCC_WORKERS=4 DCC_PORT=8081 /root/dcc_cpp/build/dcc_encrypt > /root/dcc_cpp/dcc.log 2>&1 &

x86 静态编译
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_RUNTIME=ON && cmake --build build -j4








# 资源
当前是在 mac 上编译调试
实际会在 x86_64 4C8G的机器上静态编译执行

# sm4 算法正确性验证
curl -s -X POST http://localhost:8081/encrypt \
        -H "Content-Type: application/json" \
        -d '{"requestId":"REQ_001","sm4Key":"8656ae6acdb820f3","ip":"127.0.0.1","fieldsToEncrypt":["trans_id","secret_code"]}'
使用 /private/tmp/test_data2.csv 的数据 得到的结果与 /private/tmp/dcc_out_key/REQ_001.csv 一致

data

要观察内存使用情况，不能超过上限


目标 
100个并发请求的整体加密时间尽可能短，要超越极限！


```bash
cd /root/dcc_cpp
git pull
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_RUNTIME=ON && cmake --build build -j4
./verify_sm4.sh
```


编译器 flags

列式存储替换 vector<vector<string>>（最大的结构性收益）
SSSE3 向量化 hex 编码
列式 CSV 存储
单 buffer 输出
DCC_WORKERS 可调 + 实测
AVX-512 对 gather 的进一步优化
AES-NI 实现 SM4 S-box
callback 线程解耦
hex 查表转换 
手写大 buffer 批量写文件 
string_view/offset 保存 

用 ccswitch  然后 结合 chatgpt  gemini 再优化

AES-NI VAES 加速 SM4（最高潜力，最高复杂度）

  Xeon Gold 5218 有 AES-NI (aes=1) 和 AVX-512 VAES。可用 _mm512_aesenclast_epi128 实现 SM4 S-box（利用 GF(2^8) 域同构），消除 4 个
  gather/轮的依赖链瓶颈：

  当前: 4× vgatherdps(zmm) → 约 16–24 cycles/gather，串行依赖
  VAES: 1× vaesenc + 少量 XOR → 约 4–8 cycles，吞吐量大幅提升

  预期 SM4 计算加速 2–3×，综合 enc 减少 30–50%。
  需要完整实现并通过 verify_sm4.sh 验证正确性。

字段级的batch  分块作为环境变量