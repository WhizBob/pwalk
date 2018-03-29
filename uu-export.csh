#!/bin/csh

set tag = `date +%Y%m%d@%H%M%S`
set uufile = ../pwalk-master_${tag}_uu.allow

# Get rid of OSX .DS_Store
rm -f .DS_Store >& /dev/null

# Make symlinks for scripts that are OneFS-only ...
rm bin/*/{pwalk_python.py,astat,wstat}
foreach p (bin/onefs*)
   pushd $p >& /dev/null
   foreach s (pwalk_python.py astat wstat)
      ln -s ../../src/$s
   end
   popd >& /dev/null
end

# Prepare uuencoded tgz file with dummy line 1 ...
cd ..
echo '# Remove this line!' > $uufile
tar cf - pwalk-master | uuencode pwalk_master.tgz >> $uufile
