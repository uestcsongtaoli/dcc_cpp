#!/usr/bin/env bash
# 在目标机器上运行，快速诊断 dcc_encrypt 启动问题
# 用法: bash diag.sh [binary路径]   默认 /opt/app/dcc/team077/dcc_encrypt

BINARY="${1:-/opt/app/dcc/team077/dcc_encrypt}"
LOG="/opt/app/dcc/team077/dcc.log"
PORT=8080

sep() { echo "────────────────────────────────────────"; }

sep
echo "1. 操作系统 / 内核"
uname -a
sep

echo "2. 二进制文件"
if [[ -f "$BINARY" ]]; then
    ls -lh "$BINARY"
    file "$BINARY"
else
    echo "  [MISSING] $BINARY"
fi
sep

echo "3. 动态库依赖 (静态编译应只剩 linux-vdso / libc / libm / libpthread)"
ldd "$BINARY" 2>&1 || echo "  ldd 失败（可能是静态二进制或路径不对）"
sep

echo "4. 端口 $PORT 占用情况"
ss -tlnp 2>/dev/null | grep ":$PORT" || \
    netstat -tlnp 2>/dev/null | grep ":$PORT" || \
    echo "  端口 $PORT 当前未监听"
sep

echo "5. dcc_encrypt 进程"
pgrep -a dcc_encrypt 2>/dev/null || echo "  进程不存在"
sep

echo "6. 日志文件 ($LOG)"
if [[ -f "$LOG" ]]; then
    echo "  大小: $(wc -c < "$LOG") bytes"
    echo "  最后20行:"
    tail -20 "$LOG"
else
    echo "  [NOT FOUND] 日志文件不存在"
fi
sep

echo "7. 直接运行（前台，5秒后 Ctrl-C）"
echo "  手动执行以下命令观察启动输出:"
echo ""
echo "  DCC_TEAM_CODE=team077 \\"
echo "  DCC_OUTPUT_DIR=/opt/app/dcc/team077/output/ \\"
echo "  DCC_CSV_PATH=/dcc/root/table_data.csv \\"
echo "  DCC_CALLBACK_URL=skip \\"
echo "  DCC_DEBUG=1 \\"
echo "  $BINARY"
echo ""
sep

echo "8. 目录 / 权限"
for dir in "$(dirname "$BINARY")" "/opt/app/dcc/team077/output" "/dcc/root"; do
    if [[ -d "$dir" ]]; then
        echo "  OK  $dir"
        ls -la "$dir" 2>/dev/null | head -5
    else
        echo "  MISSING  $dir"
    fi
done
sep

echo "9. CSV 文件"
CSV=/dcc/root/table_data.csv
if [[ -f "$CSV" ]]; then
    echo "  OK  $(ls -lh "$CSV")"
    echo "  行数: $(wc -l < "$CSV")"
else
    echo "  [MISSING] $CSV"
fi
sep
