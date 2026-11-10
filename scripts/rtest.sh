#!/usr/bin/env bash
# 在远程 Linux 上跑测试；本机不执行任何 go test。
# 用法: scripts/rtest.sh [package...]   默认 ./...
set -uo pipefail
REMOTE="${PACKOUT_REMOTE:-yk.song@120.77.59.18}"
KEY="${PACKOUT_KEY:-$HOME/.ssh/packout_ci}"
DEST="${PACKOUT_DEST:-~/packout-ci}"
SSH=(ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o ServerAliveInterval=15 -o ServerAliveCountMax=4 "$REMOTE")
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_ENV="cd $DEST && export PATH=\$HOME/tools/go/bin:\$PATH GOCACHE=\$HOME/.cache/go-build GOFLAGS=-mod=mod GOPROXY=https://goproxy.cn,direct"

# 并发下链路会偶发断；源码也可能正被并发编辑（忽略 "file changed as we read it"）
sync() {
  tar czf - -C "$ROOT" --warning=no-file-changed \
    --exclude=.git --exclude=build --exclude='*.exe' . 2>/dev/null \
    | "${SSH[@]}" "rm -rf $DEST && mkdir -p $DEST && tar xzf - -C $DEST"
  return "${PIPESTATUS[1]}"
}

echo "[rtest] syncing -> $REMOTE:$DEST"
ok=0
for i in 1 2 3; do
  if sync; then ok=1; break; fi
  echo "[rtest] sync attempt $i failed" >&2
done
[ "$ok" -eq 1 ] || { echo "[rtest] sync failed"; exit 90; }

PKGS=("$@"); [ ${#PKGS[@]} -eq 0 ] && PKGS=(./...)
echo "[rtest] go ${PKGS[*]}"
# 输出先进远端日志再整段取回：链路抖动时不至于丢掉全部结果
"${SSH[@]}" "$REMOTE_ENV && { go vet ${PKGS[*]}; go test -count=1 ${PKGS[*]}; } > /tmp/rtest.$$ 2>&1; echo \$? > /tmp/rtest.$$.code; cat /tmp/rtest.$$; exit $(cat /tmp/rtest.$$.code)"
status=$?
echo "[rtest] exit=$status"

# 本脚本只覆盖 Linux。Windows 运行时见 D-035：本机便携 Go 另跑一遍，
# 这里仍做 Windows 交叉编译，防止 Windows 构建断掉。
echo "[rtest] GOOS=windows go build ./... + vet ./internal/fsx"
"${SSH[@]}" "$REMOTE_ENV && GOOS=windows go build ./... && GOOS=windows go vet ./internal/fsx"
wstatus=$?
echo "[rtest] windows-build exit=$wstatus"
if [ $status -eq 0 ]; then status=$wstatus; fi
exit $status
