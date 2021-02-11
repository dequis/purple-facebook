#!/bin/bash

set -e

FULLVERS="$(date +%Y%m%d)~$(git rev-parse --short=7 HEAD)~${GITHUB_RUN_NUMBER}"
FULLDATE=$(date -R)
REPONAME=$(basename "${GITHUB_REPOSITORY}")
BUILD_DIR=$(pwd)

git reset -q --hard
git clean -dfqx

cat <<EOF > debian/changelog
${REPONAME} (${FULLVERS}) UNRELEASED; urgency=medium

  * Updated to ${FULLVERS}.

 -- Travis CI <travis@travis-ci.org>  ${FULLDATE}
EOF

mkdir -p ~/.config/osc/
cat <<EOF > ~/.config/osc/oscrc
[general]
apiurl = https://api.opensuse.org
[https://api.opensuse.org]
user = ${OBSUSER}
pass = ${OBSPASS}
credentials_mgr_class=osc.credentials.PlaintextConfigFileCredentialsManager
EOF

mkdir -p m4
osc checkout "home:${OBSUSER}" "${REPONAME}" -o /tmp/obs

(
    cd /tmp/obs
    rm -f *.{dsc,tar.gz}
    dpkg-source -b "${BUILD_DIR}"

    osc addremove -r
    osc commit -m "Updated to ${FULLVERS}"
)
