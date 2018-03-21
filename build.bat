perl Configure VC-WIN32 no-hw no-shared no-zlib --prefix=..\master --openssldir=..\master
nmake
nmake test
nmake install
