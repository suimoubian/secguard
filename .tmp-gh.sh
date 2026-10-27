#!/bin/bash
# 临时:确认仓库和 GitHub 的连接状态(用完即删)
cd /mnt/e/DevEnv/Projects/secguard || exit 1
{
  echo "=== remote ==="
  git remote -v || echo "(无 remote)"
  echo
  echo "=== 当前分支 ==="
  git branch --show-current
  echo
  echo "=== workflow 是否被 git 跟踪 ==="
  git ls-files .github/
  echo
  echo "=== workflow 在哪个提交里 ==="
  git log --oneline -2 -- .github/workflows/ci.yml
  echo
  echo "=== 最近提交 ==="
  git log --oneline -3
} > .git/gh.txt 2>&1
echo done
