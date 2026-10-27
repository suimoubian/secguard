#!/bin/bash
# 临时:确认本地与 GitHub 的差距(用完即删)
cd /mnt/e/DevEnv/Projects/secguard || exit 1
{
  echo "=== 分支状态 ==="
  git status -sb | head -3
  echo
  echo "=== HEAD ==="
  git rev-parse --short HEAD
  echo
  echo "=== origin/main ==="
  git rev-parse --short origin/main 2>/dev/null || echo "(本地没有 origin/main 引用)"
  echo
  echo "=== 未推送的提交(origin/main..HEAD) ==="
  git log --oneline origin/main..HEAD 2>/dev/null | head -12 || echo "(算不出来)"
} > .git/gh2.txt 2>&1
echo done
