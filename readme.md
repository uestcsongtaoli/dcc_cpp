测试

哥伦比亚  1219879811313
哥#####  2BDC197182190981

DCC_DEBUG=1 \
DCC_CSV_PATH=/Users/lee/codes/dcc_cpp/table_data.csv \
DCC_OUTPUT_DIR=/tmp/dcc_test/ \
DCC_CALLBACK_URL=skip \
./build/dcc_encrypt

x86 静态编译
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_RUNTIME=ON && cmake --build build -j4








# 资源
当前是在 mac 上编译调试
实际会在 x86_64 4C8G的机器上静态编译执行

# sm4 算法正确性验证
curl -s -X POST http://localhost:8080/encrypt \
        -H "Content-Type: application/json" \
        -d '{"requestId":"REQ_001","sm4Key":"8656ae6acdb820f3","ip":"127.0.0.1","fieldsToEncrypt":["trans_id","secret_code"]}'
使用 /private/tmp/test_data2.csv 的数据 得到的结果与 /private/tmp/dcc_out_key/REQ_001.csv 一致

data

要观察内存使用情况，不能超过上限


目标 
100个并发请求的整体加密时间尽可能短，要超越极限！


