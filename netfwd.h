// NetMailForward: copy of netmail to own addresses sent to another address

extern short fwdcopy, netstored;

void fwdparse (short level, short exact);
void fwdskipparse (short level);
void fwdcheck (void);
void fwdfree (void);
void fwdprepare (void);
void fwdsend (void);
