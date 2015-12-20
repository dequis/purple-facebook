#!/bin/bash

[ "${TRAVIS_PULL_REQUEST}" == "false" -a \
  "${TRAVIS_BRANCH}" == "${MY_DEPLOY_BRANCH}" \
] || exit
set -e

FULLVERS="$(date +%Y%m%d)~$(git rev-parse --short=7 HEAD)~${TRAVIS_BUILD_NUMBER}"
FULLDATE=$(date -R)
REPONAME=$(basename "${TRAVIS_REPO_SLUG}")

git reset -q --hard
git clean -dfqx
./update.sh

sed -ri \
    -e "20 s/^(\s+).*(,)\$/\1\[${FULLVERS}\]\2/" \
    configure.ac
sed -ri \
    -e "s/(^Build-Depends:.*)/\1, libzephyr4/" \
    debian/control

cat <<EOF > debian/changelog
${REPONAME} (${FULLVERS}) UNRELEASED; urgency=medium

  * Updated to ${FULLVERS}.

 -- Travis CI <travis@travis-ci.org>  ${FULLDATE}
EOF

cat <<EOF > ~/.oscrc
[general]
apiurl = https://api.opensuse.org
[https://api.opensuse.org]
user = ${OBSUSER}
pass = ${OBSPASS}
EOF

mkdir -p m4
osc checkout "home:${OBSUSER}" "${REPONAME}" -o /tmp/obs

(
    cd /tmp/obs
    rm -f *.{dsc,tar.gz}
    dpkg-source -I -b "${TRAVIS_BUILD_DIR}"

    osc addremove -r
    osc commit -m "Updated to ${FULLVERS}"
)
