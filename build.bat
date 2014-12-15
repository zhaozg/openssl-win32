E:\portableDev\portable.cmd
perl Configure -DOPENSSL_CCSTC VC-WIN32 --prefix=..\master
ms\do_nasm
nmake -f ms\nt.mak
nmake -f ms\nt.mak install
nmake -f ms\nt.mak clean
