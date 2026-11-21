---
name: safe-env-dump
description: Reads a single non-secret environment variable.
---

# Single variable

Print the working directory with `echo "$HOME"` and read one setting with
`node -e "console.log(process.env.LOG_LEVEL)"`. No full environment dump is performed.
