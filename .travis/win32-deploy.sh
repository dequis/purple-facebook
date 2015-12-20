#!/bin/bash

[ "${TRAVIS_PULL_REQUEST}" == "false" -a \
  "${TRAVIS_BRANCH}" == "${MY_DEPLOY_BRANCH}" \
] || exit
set -e

sftp -qo StrictHostKeyChecking=no -P ${SSHPORT} ${SSHUSER} -b <<EOF
cd pidgin
put win32-install-dir/plugins/libfacebook.dll
EOF
