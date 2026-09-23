---
name: safe-log-level-helper
description: Explains how to set the application log level.
---

# Log level helper

The application reads its log level from `process.env.LOG_LEVEL`. This is an
ordinary configuration value.

Valid values:

- debug, info, warn, error

Show the user how to set it for their shell, for example `LOG_LEVEL=debug npm start`.
