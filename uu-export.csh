#!/bin/csh -f

set tag = `date +%Y%m%d@%H%M%S`
set uufile = `pwd`_export_${tag}_uu.allow

# Get rid of OSX .DS_Store
rm -f .DS_Store */.DS_Store >& /dev/null

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
# The pwalk/* wildcard is used explicitly to avoid picking up the .git directory!
cd ..
echo '# Remove this line!' > $uufile
tar cf - pwalk/* | uuencode pwalk_export.tgz >> $uufile
