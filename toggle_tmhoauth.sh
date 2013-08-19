#!/usr/bin/env bash
set -e

LOCAL_TMH="`pwd`/../tmhOAuth"
VENDOR_PATH="`pwd`/vendor/themattharris"
VENDOR_TMH="tmhoauth_vendor"
lib='tmhoauth'

if [[ -e "${VENDOR_PATH}/${VENDOR_TMH}" ]]; then
  echo 'Found vendored tmhoauth moved out the way, restoring it'
  rm -rf "${VENDOR_PATH}/${lib}"
  if [[ $? != 0 ]]; then
    echo 'FATAL: could not erase symlink. this is probably a directory'
    exit 1
  fi
  mv "${VENDOR_PATH}/${VENDOR_TMH}" "${VENDOR_PATH}/${lib}"
else
  echo 'tmhoauth is vendored. moving it out the way and creating symlink to local version'
  mv "${VENDOR_PATH}/${lib}" "${VENDOR_PATH}/${VENDOR_TMH}"
  ln -s "${LOCAL_TMH}" "${VENDOR_PATH}/${lib}"
fi
