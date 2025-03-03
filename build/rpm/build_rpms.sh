#!/usr/bin/env bash
export RPMARCH=noarch
export RPMBUILD_HOME=$PWD/rpmbuild

# Remove previous rpmbuild folder
if [ -d $RPMBUILD_HOME ]; then
    echo "Removing previous rpmbuild folder"
    rm -rf $RPMBUILD_HOME
fi


# Setup rpmbuild folders
mkdir -p ${RPMBUILD_HOME}/SPECS
mkdir -p ${RPMBUILD_HOME}/SOURCES
mkdir -p ${RPMBUILD_HOME}/BUILD
mkdir -p ${RPMBUILD_HOME}/SRPMS
mkdir -p ${RPMBUILD_HOME}/RPMS

# Define some variables
# Ensure that date runs with English locale that rpmbuild requires
export RPM_BUILDDATE=$(LC_TIME=en_US.UTF-8 date +'%a %b %d %Y')
export OPENFIRE_REPOVERSION=$(git rev-parse --short HEAD)
export OPENFIRE_FULLVERSION=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
export OPENFIRE_VERSION=$(echo "${OPENFIRE_FULLVERSION}" | cut -d'-' -f1)

# Setup the RPM versioning correctly, so one can update from 
# a snapshot,alpha,beta,rc build to GA
# For General Releases we get x.y.z-1
# For Snapshot builds we get     x.y.z-0.1.{YYYYMMDD}snapshot
# For alpha builds we get   x.y.z-0.2.alpha
# For beta builds we get   x.y.z-0.2.beta
# For rc builds we get   x.y.z-0.2.rc
if [[ $OPENFIRE_FULLVERSION = *"SNAPSHOT"* ]]; then
    export OPENFIRE_RELEASE="0.1.$(date +'%Y%m%d')snapshot"
elif [[ $OPENFIRE_FULLVERSION = *"alpha"* ]]; then
    export OPENFIRE_RELEASE="0.2.alpha"
elif [[ $OPENFIRE_FULLVERSION = *"beta"* ]]; then
    export OPENFIRE_RELEASE="0.2.beta"
elif [[ $OPENFIRE_FULLVERSION = *"rc"* ]]; then
    export OPENFIRE_RELEASE="0.2.rc"
else
    export OPENFIRE_RELEASE="1"
fi

# generate our psuedo source tree, which is actually dist tree from maven
cd distribution/target
cp -r distribution-base openfire
mkdir -p openfire/logs
tar -czf openfire.tar.gz openfire
rm -rf openfire
mv openfire.tar.gz ${RPMBUILD_HOME}/SOURCES/
cd ../..

# Finally build the RPM
rpmbuild -bb \
  --target ${RPMARCH} \
  --define "_topdir ${RPMBUILD_HOME}" \
  --define "OPENFIRE_BUILDDATE ${RPM_BUILDDATE}" \
  --define "OPENFIRE_VERSION ${OPENFIRE_VERSION}" \
  --define "OPENFIRE_RELEASE ${OPENFIRE_RELEASE}" \
  --define "OPENFIRE_SOURCE openfire.tar.gz" \
  --define "OPENFIRE_REPOVERSION ${OPENFIRE_REPOVERSION}" \
  build/rpm/openfire.spec

# Move generated artifacts back into a rpms folder, so bamboo can grab it
mkdir -p distribution/target/rpms
mv ${RPMBUILD_HOME}/RPMS/${RPMARCH}/openfire*rpm distribution/target/rpms/
