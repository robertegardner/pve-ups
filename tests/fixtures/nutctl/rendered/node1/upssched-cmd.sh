#!/bin/bash
# NUT upssched CMDSCRIPT — tier-0 (GPU VM shed) / tier-1 (node shed) / power-back.
# Runs as user 'nut'; privileged actions go through the sudoers drop-in
# (/etc/sudoers.d/nut-upssched, written by install-client.sh).
# Test-hook envs (FLAG_FILE/ENV_FILE) default to the real paths in production.
ENV_FILE="${ENV_FILE:-/etc/nut/upssched.env}"
FLAG_FILE="${FLAG_FILE:-/var/lib/nut/gpu-shed.flag}"
TIER0_VMID=""
[ -r "$ENV_FILE" ] && . "$ENV_FILE"
case "$1" in
  gpu-shed)
    if [ -n "$TIER0_VMID" ]; then
      logger -t upssched "T0: on battery 90s — stopping GPU VM $TIER0_VMID"
      sudo /usr/sbin/qm shutdown "$TIER0_VMID" --timeout 120 && touch "$FLAG_FILE"
    fi ;;
  node-shed)
    logger -t upssched "T1: on battery 240s — shutting down node"
    sudo /sbin/shutdown -h now ;;
  power-back)
    if [ -n "$TIER0_VMID" ] && [ -f "$FLAG_FILE" ]; then
      logger -t upssched "power restored — restarting GPU VM $TIER0_VMID"
      sudo /usr/sbin/qm start "$TIER0_VMID" && rm -f "$FLAG_FILE"
    fi ;;
  *) logger -t upssched "unknown event: $*" ;;
esac
