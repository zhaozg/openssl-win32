SET PATH=E:\Totalcmd\Tools\Portable\PortableApps\CommonFiles\Perl\perl\bin;%PATH%
perl Configure -DOPENSSL_CCSTC VC-WIN32 --prefix=..\master
ms\do_nasm
nmake -f ms\nt.mak
nmake -f ms\nt.mak install
nmake -f ms\nt.mak clean
