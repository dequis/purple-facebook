#!/bin/bash

#[ "${TRAVIS_PULL_REQUEST}" == "false" -a \
#  "${TRAVIS_BRANCH}" == "${MY_DEPLOY_BRANCH}" \
#] || exit
set -e

#GITREV=$(git rev-parse --short=7 HEAD)
#FULLVERS="$(date +%Y%m%d)-$(cat RELEASE_VERSION)-${GITREV}-${GITHUB_RUN_NUMBER}"
FULLVERS="$(date +%Y%m%d)~$(git rev-parse --short=7 HEAD)~${GITHUB_RUN_NUMBER}"
FULLVERS_RPM="$(echo ${FULLVERS} | sed 's/-/~/g')"
FULLDATE=$(date -R)
BUILD_DIR=$(pwd)
#REPONAME=$(basename "${TRAVIS_REPO_SLUG}")
REPONAME=$(basename "${BUILD_DIR}")

git reset -q --hard
git clean -dfqx
./update.sh

sed -ri \
    -e "20 s/^(\s+).*(,)\$/\1\[${FULLVERS}\]\2/" \
    configure.ac
sed -ri \
    -e "s/(^Build-Depends:.*)/\1, libzephyr4/" \
    debian/control
sed -ri \
    -e "s/(^%setup -q.*)/\1 -n %\{name\}/" \
    -e "s/(^Source0:.*)\-(.*)/\1_\2/" \
    -e "s/(^Version:).*/\1 ${FULLVERS_RPM}/" \
    dist/*.spec

cat <<EOF > debian/changelog
${REPONAME} (${FULLVERS}) UNRELEASED; urgency=medium

  * Updated to ${FULLVERS}.

 -- Travis CI <travis@travis-ci.org>  ${FULLDATE}
EOF

echo asd
cat debian/changelog
echo dsa

cat <<EOF > ~/.oscrc
[general]
apiurl = https://api.opensuse.org
[https://api.opensuse.org]
user = ${OBSUSER}
pass = ${OBSPASS}
EOF

mkdir -p m4
osc checkout "home:jgeboski" "${REPONAME}" -o /tmp/obs

(
    cd /tmp/obs
    rm -f *.{dsc,tar.gz}
    dpkg-source -I -b "${BUILD_DIR}"
    cp "${BUILD_DIR}/dist/_service" .

    osc addremove -r
    osc commit -m "Updated to ${FULLVERS}"
)
