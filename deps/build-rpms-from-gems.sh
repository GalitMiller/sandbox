#!/bin/bash

# Build .src.rpm packages from .gem packages.
# gem2rpm gem is required. Install it using command "sudo yum -y install rubygem-gem2rpm".

mkdir -p ok bad built

for I in "$@"
do
  echo "Building $I..."
  gem2rpm -s -t "spec.template" "$I"

  P="ruby193-rubygem-${I%.gem}-1.fc21.src.rpm"

  if mock "$P" >"$P.log" 2>&1
  then
    mv "$I" "$P" "$P.log" ./ok
    mv /var/lib/mock/epel-7-x86_64/result/*.rpm  ./built
  else
    echo "FAIL to build $I."
    tail "$P.log"
    mv "$I" "$P" "$P.log" ./bad
    mv /var/lib/mock/epel-7-x86_64/result/build.log ./bad/"$P-build.log"
    mv /var/lib/mock/epel-7-x86_64/result/root.log ./bad/"$P-root.log"
  fi

done
