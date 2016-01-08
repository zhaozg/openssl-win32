E:\portableDev\portable.cmd
perl Configure -DOPENSSL_CCSTC VC-WIN32 --prefix=..\win32
ms\do_nasm
nmake -f ms\nt.mak clean
nmake -f ms\nt.mak
nmake -f ms\nt.mak install
