#pragma once

static char* banner = ""
"[34mPPPPPPPPPPPPPPPPP                   kkkkkkkk\n"
"P[93m::::::::::::::::[34mP                  k[93m::::::[34mk\n"
"P[93m::::::[34mPPPPPP[93m:::::[34mP                 k[93m::::::[34mk\n"
"PP[93m:::::[34mP     P[93m:::::[34mP                k[93m::::::[34mk\n"
"  P[93m::::[34mP     P[93m:::::[34mP  ooooooooooo    k[93m:::::[34mk    kkkkkkk eeeeeeeeeeee       mmmmmmm    mmmmmmm      ooooooooooo   nnnn  nnnnnnnn\n"
"  P[93m::::[34mP     P[93m:::::[34mPoo[93m:::::::::::[34moo  k[93m:::::[34mk   k[93m:::::[34mkee[93m::::::::::::[34mee   mm[93m:::::::[34mm  m[93m:::::::[34mmm  oo[93m:::::::::::[34moo n[93m:::[34mnn[93m::::::::[34mnn\n"
"  P[93m::::[34mPPPPPP[93m:::::[34mPo[93m:::::::::::::::[34mo k[93m:::::[34mk  k[93m:::::[34mke[93m::::::[34meeeee[93m:::::[34meem[93m::::::::::[34mmm[93m::::::::::[34mmo[93m:::::::::::::::[34mon[93m::::::::::::::[34mnn\n"
"  P[93m:::::::::::::[34mPP o[93m:::::[34mooooo[93m:::::[34mo k[93m:::::[34mk k[93m:::::[34mke[93m::::::[34me     e[93m:::::[34mem[93m::::::::::::::::::::::[34mmo[93m:::::[34mooooo[93m:::::[34monn[93m:::::::::::::::[34mn\n"
"  P[93m::::[34mPPPPPPPPP   o[93m::::[34mo     o[93m::::[34mo k[93m::::::[34mk[93m:::::[34mk e[93m:::::::[34meeeee[93m::::::[34mem[93m:::::[34mmmm[93m::::::[34mmmm[93m:::::[34mmo[93m::::[34mo     o[93m::::[34mo  n[93m:::::[34mnnnn[93m:::::[34mn\n"
"  P[93m::::[34mP           o[93m::::[34mo     o[93m::::[34mo k[93m:::::::::::[34mk  e[93m:::::::::::::::::[34me m[93m::::[34mm   m[93m::::[34mm   m[93m::::[34mmo[93m::::[34mo     o[93m::::[34mo  n[93m::::[34mn    n[93m::::[34mn\n"
"  P[93m::::[34mP           o[93m::::[34mo     o[93m::::[34mo k[93m:::::::::::[34mk  e[93m::::::[34meeeeeeeeeee  m[93m::::[34mm   m[93m::::[34mm   m[93m::::[34mmo[93m::::[34mo     o[93m::::[34mo  n[93m::::[34mn    n[93m::::[34mn\n"
"  P[93m::::[34mP           o[93m::::[34mo     o[93m::::[34mo k[93m::::::[34mk[93m:::::[34mk e[93m:::::::[34me           m[93m::::[34mm   m[93m::::[34mm   m[93m::::[34mmo[93m::::[34mo     o[93m::::[34mo  n[93m::::[34mn    n[93m::::[34mn\n"
"PP[93m::::::[34mPP         o[93m:::::[34mooooo[93m:::::[34mok[93m::::::[34mk k[93m:::::[34mke[93m::::::::[34me          m[93m::::[34mm   m[93m::::[34mm   m[93m::::[34mmo[93m:::::[34mooooo[93m:::::[34mo  n[93m::::[34mn    n[93m::::[34mn\n"
"P[93m::::::::[34mP         o[93m:::::::::::::::[34mok[93m::::::[34mk  k[93m:::::[34mke[93m::::::::[34meeeeeeee  m[93m::::[34mm   m[93m::::[34mm   m[93m::::[34mmo[93m:::::::::::::::[34mo  n[93m::::[34mn    n[93m::::[34mn\n"
"P[93m::::::::[34mP          oo[93m:::::::::::[34moo k[93m::::::[34mk   k[93m:::::[34mkee[93m:::::::::::::[34me  m[93m::::[34mm   m[93m::::[34mm   m[93m::::[34mm oo[93m:::::::::::[34moo   n[93m::::[34mn    n[93m::::[34mn\n"
"PPPPPPPPPP            ooooooooooo   kkkkkkkk    kkkkkkk eeeeeeeeeeeeee  mmmmmm   mmmmmm   mmmmmm   ooooooooooo     nnnnnn    nnnnnn\n"
"\n"
"\n"
"                                                   [90mGGGGGGGGGGGGG     OOOOOOOOO\n"
"                                                GGG[34m::::::::::::[90mG   OO[34m:::::::::[90mOO\n"
"                                              GG[34m:::::::::::::::[90mG OO[34m:::::::::::::[90mOO\n"
"                                             G[34m:::::[90mGGGGGGGG[34m::::[90mGO[34m:::::::[90mOOO[34m:::::::[90mO\n"
"                                            G[34m:::::[90mG[34m*******[90mGGGGGGO[34m::::::[90mO[41m   [49mO[34m::::::[90mO\n"
"                                           G[34m:::::[90mG[34m**************[90mO[34m:::::[90mO[41m     [49mO[34m:::::[90mO\n"
"                                           G[34m:::::[90mG[34m**************[90mO[34m:::::[90mO[41m     [49mO[34m:::::[90mO\n"
"                                           G[36m:::::[90mG[36m****[90mGGGGGGGGGGO[36m:::::[90mO[100m  [107m [100m  [49mO[36m:::::[90mO\n"
"                                           G[36m:::::[90mG[36m****[90mG[36m::::::::[90mGO[36m:::::[90mO[107m     [49mO[36m:::::[90mO\n"
"                                           G[36m:::::[90mG[36m****[90mGGGGG[36m::::[90mGO[36m:::::[90mO[107m     [49mO[36m:::::[90mO\n"
"                                           G[36m:::::[90mG[36m********[90mG[36m::::[90mGO[36m:::::[90mO[107m     [49mO[36m:::::[90mO\n"
"                                            G[36m:::::[90mG[36m*******[90mG[36m::::[90mGO[36m::::::[90mO[107m   [49mO[36m::::::[90mO\n"
"                                             G[36m:::::[90mGGGGGGGG[36m::::[90mGO[36m:::::::[90mOOO[36m:::::::[90mO\n"
"                                              GG[36m:::::::::::::::[90mG OO[36m:::::::::::::[90mOO\n"
"                                                GGG[36m::::::[90mGGG[36m:::[90mG   OO[36m:::::::::[90mOO\n"
"                                                   GGGGGG   GGGG     OOOOOOOOO[39m\n"
"\n";

const static char *iconBulbasaur = ""
"                         \n"
"                NdmN     \n"
"          dsoooo::/-d    \n"
"    N+/+o/////////o:h    \n"
"   N/:::++/:::++++oo:h   \n"
"   o-///+::///+osoooo:   \n"
"   -//::/:-/++++ssoo++   \n"
"   do:++++o+++//++++-N   \n"
"     //o++/oo+//+oo+-    \n"
"     N:///s-/::/://:y    \n"
"      NNN  Ndmm NNNN     \n"
"                         \n"
"";

const static char *iconIvysaur = ""
"                         \n"
"        Ns/+oyNNmdN      \n"
"       N:-+:/::/:/:/N    \n"
"  m+o+o/::+/+oooo+o-s    \n"
"  -/++++oosooy++//o+:oN  \n"
"  /:++oossooso/:/o++//+  \n"
"   do-:+ssys+:///++++/:N \n"
"   m-++o+oy+://oooo+-sN  \n"
"    ys////+o:oososss-m   \n"
"      ++oo:+/+++.:o+:y   \n"
"      msooyNyo+++myssm   \n"
"                         \n"
"";

const static char *iconVenusaur = ""
"                         \n"
"    NNds++++oo++oyNN     \n"
"   y/::/://+++////-/+d   \n"
"   /:/++:/:hdh//:/++:/   \n"
" my+/-/ossssyysooo/::sdN \n"
"+:/+osssossssssooyssso///\n"
"++:+sss+//+o+o+++oyyyo-+o\n"
"  :ssoo++///+//+oossys-  \n"
"  h-oossso+//++ssssss:s  \n"
"   dhs:++:+ss:/sss/+hd   \n"
"      NddN   yo/o/y      \n"
"                         \n"
"";

const static char *iconCharmander = ""
"       NmmN              \n"
"     s:.---/m            \n"
"    y----::o:            \n"
"    ++:---+s-d     hd    \n"
"    +:////++.d   N/-.m   \n"
"   hs--/::/:-:/ooo-/--   \n"
"   :---:```-:::/:-.-:.   \n"
"   Nmd:.````:-.sNh.::d   \n"
"    N:.:.`..---////-d    \n"
"    s-///-:-::/+:/om     \n"
"   N::/osdNNh:::.y       \n"
"              NmN        \n"
"";

const static char *iconCharmeleon = ""
"          msoh           \n"
"      No+/:+-y           \n"
"      .////o:s           \n"
"     h.//o+o/+  mhm      \n"
"     m+::/oo-dN d`:/hN   \n"
"    d++/:--//:/+s`/:-/N  \n"
"  N+:::`.`.:++-/:`:.:.h  \n"
"  h--:/....:++/:/.`--s   \n"
"   md:://:-://++/:/:s    \n"
"    N.+oo:+::/++/+od     \n"
"   N.-:/+s +-/+:+        \n"
"    NmN    mhossN        \n"
"";

const static char *iconCharizard = ""
"                         \n"
"         yyhdN           \n"
"   Nhhyd ho++sm    dN    \n"
" dyoooyh   N/+    NhhydN \n"
"dsyhyssshdmN//hNNmhsysosm\n"
"hN   dhdyyo/::/oyyhsdmsyh\n"
"N     msym/-...+Ndoy m:dh\n"
"    Ndmdo/-.`..-yNN  s-sN\n"
"   y+++/:/:----::/hmmdmN \n"
"   hss+/+sssyyyyo/+dN    \n"
"      hhd        NmN     \n"
"                         \n"
"";

const static char *iconSquirtle = ""
"        NmdmN            \n"
"      y/.----:s          \n"
"     d::::/so/:o         \n"
"     //:///++++:         \n"
"    ms./++++++/:d        \n"
"  o+:-:--::/:/++-d       \n"
"  :+/::..-:////+:+NmmN   \n"
"  NNm/:--:-://:o/.:///y  \n"
"    y--:-:-::::o//++++-  \n"
"   N-//+:///:::+//++/:s  \n"
"    s+osh Nd.:/:-hhhdN   \n"
"            NNmN         \n"
"";

const static char *iconWartortle = ""
"     NdN                 \n"
"    N-`-N   Ns:..        \n"
"    y..-////:..-:        \n"
"    s.-------..-hmysyd   \n"
"    N:::--/://.oo.`-..h  \n"
"  ho/-:+::/+++:--:-:-`d  \n"
" N:/::/:.:/-.:////-:..:N \n"
"  Nmdhs.``.```-:+/.....N \n"
"     N/--`...-/++/-..-h  \n"
"     y:/++::-::::+-/hN   \n"
"     h++++mNNN-::/:/     \n"
"               Nmm       \n"
"";

const static char *iconBlastoise = ""
"                         \n"
"           yo+///oy      \n"
"     mmNNNm+://///.      \n"
"    h`.:+:-::/+/-`.+N    \n"
"    m.++//+o++s+:.-.d    \n"
"    /+o+oossssy-:+/::d   \n"
"    :ossssssss+-//++:+   \n"
"   s:sssssso/--:::mmmN   \n"
"   :+//+++/-./+++-d      \n"
"   -:/+o/---/ssso.d      \n"
"   //++oymNy-:oo+/h      \n"
"                         \n"
"";

const static char *iconMeowth = ""
"         s:m h/m         \n"
"       +o+-:+..ossN      \n"
"    d/o-ho:---ssy+:/y    \n"
"    m/.`:.`..`.-y---.y   \n"
"    mo:-.-.``.-.-...s    \n"
"      my-.::-:--::ooh    \n"
"   ms:.`-``..-:hmN       \n"
"   +.``-/....`y  s+++d   \n"
"   Ny/--..+`-.-+o.+o//   \n"
"    +:/:/d:-.oyo//++sm   \n"
"     dhm s:/-d           \n"
"         h++/N           \n"
"";

const static char *iconMewtwo = ""
"             yN m        \n"
"            d.::/        \n"
"        Ny  s-:-/        \n"
"       md/oo+///m        \n"
"   mhhhhddddd/-:ymN      \n"
"   hN msm    d-:ymhyN    \n"
"   mhN doymm+..++odood   \n"
"    msymdoo/--:+++hNNN   \n"
"     NyodNd/oyhy+d       \n"
"       N N+s   s+N       \n"
"        m/-y   mdssy     \n"
"        ddmm             \n"
"";

const static char *congBanner = ""
"Congrate!!! You are actually a Pokémon Master !!!\n"
"So I decide to give you a badge. Keep working hard!!\n\n\n"
"             WWWXXXNNXXXWWW                   \n"
"           WXKK0OOOOOOOO0KKXW                 \n"
"        WNXKOOOkkkkkkkkkkOOOKXNW              \n"
"       WN0OOkkkOO000000OOkkkOO0NW              ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ \n"
"      WX0OOkkO000000000000OkkOO0XW            ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌\n"
"      NKOOkk0000000000000000kkOO0N            ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀█░▌\n"
"     WX0OkkO0000000000000000OkkO0XW           ▐░▌       ▐░▌     ▐░▌     ▐░▌                    ▐░▌\n"
"     WX0OkkO0000000000000000OkkO0XW           ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄█░▌\n"
"      NKOOkk0000000000000000kkOOKW            ▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌\n"
"      WX0OOkkO000000000000OkkOO0XW            ▐░█▀▀▀▀▀▀▀█░▌     ▐░▌      ▀▀▀▀▀▀▀▀▀█░▌ ▀▀▀▀▀▀▀▀▀█░▌\n"
"       WX0OOkkOO00000000OkkkOO0NW             ▐░▌       ▐░▌     ▐░▌               ▐░▌          ▐░▌\n"
"        WNK0OOkkkkkkkOkkkkOO0KNW              ▐░▌       ▐░▌ ▄▄▄▄█░█▄▄▄▄  ▄▄▄▄▄▄▄▄▄█░▌ ▄▄▄▄▄▄▄▄▄█░▌\n"
"          W0xxxkOOOOOOOOkxxONW                ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌\n"
"          WOllloddoolodoc::dN                  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀\n"
"          WOlcccccc:;;;;;;;dX                 \n"
"          WOlcccclddoc;;;;;dX                 \n"
"          WOlcclxKNWNKxc:;;dX                  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ \n"
"          WOloxKW     WXkl:dX                 \n"
"          W0kKW         WXkkX                 \n"
"           WW             WWW                 \n"
"";