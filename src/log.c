#include "log.h"
#include <stdio.h>
#include <stdarg.h>
static int verbose=0; static FILE*lf=NULL; void log_set_verbose(int v){verbose=v;} void log_set_file(const char*p){if(p)lf=fopen(p,"a");} void log_close(void){if(lf)fclose(lf);} static void out(const char*fmt,va_list ap){vfprintf(lf?lf:stdout,fmt,ap);fprintf(lf?lf:stdout,"\n");fflush(lf?lf:stdout);} void log_info(const char*fmt,...){va_list ap;va_start(ap,fmt);out(fmt,ap);va_end(ap);} void log_error(const char*fmt,...){va_list ap;va_start(ap,fmt);out(fmt,ap);va_end(ap);} void log_hex(const char*l,const uint8_t*b,size_t n){if(!verbose)return; FILE*f=lf?lf:stdout; fprintf(f,"%s: ",l); for(size_t i=0;i<n;i++)fprintf(f,"%02x",b[i]); fprintf(f,"\n"); fflush(f);} 
