void moreHandles (void);
void disableHandles (void);
void enableHandles (void);
short closeHandles (void);
unsigned rread (short handle, void *buf, unsigned len, char *file, short line);
unsigned rreadz (short handle, void *buf, unsigned len, char *file, short line);
unsigned wwrite (short handle, void *buf, unsigned len, char *file, short line);
void cclose (short *handle, char *file, unsigned short line);
short mysopen (char *fname, short type, char *file, short line);
