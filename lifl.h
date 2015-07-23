/*******************************************************************************
 *
 * LIFL version 0.1 beta.
 * Written by Frode Ulsund 2015.                              
 * Based on work from Rémi Flament and Victor Itkin.
 *
 * Please submit bug reports, feature requests and feedback to fr@68k.no
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 *
 *******************************************************************************/

#define FUSE_USE_VERSION 30

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <mysql.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <utmp.h>
#include <pwd.h>
#include <grp.h>
#include <utmpx.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <my_global.h> // note: my_global.h has #define _GNU_SOURCE

struct {

    char hostname[256];
    char tagname[64];
    char mountpoint[1024];

    int  allow_other;
    int  default_permissions;
    int  nonempty;

    char db_host[256];
    int  db_port;
    char db_database[64];
    char db_username[64];
    char db_password[64];

    char db_table[64];
    char db_dump_table[64];
    char db_error_table[64];

    int  enable_error_messages;
    int  enable_write_dump;

    int  dump_uid;
    int  dump_size;
    char dump_cmd[1024];
    
    int  syscall_getattr;
    int  syscall_access;
    int  syscall_readlink;
    int  syscall_readdir;
    int  syscall_mknod;
    int  syscall_mkdir;
    int  syscall_unlink;
    int  syscall_rmdir;
    int  syscall_symlink;
    int  syscall_rename;
    int  syscall_link;
    int  syscall_chmod;
    int  syscall_chown;
    int  syscall_truncate;
    int  syscall_utimens;
    int  syscall_open;
    int  syscall_read;
    int  syscall_write;
    int  syscall_statfs;
    int  syscall_fallocate;
    int  syscall_setxattr;
    int  syscall_getxattr;
    int  syscall_listxattr;
    int  syscall_removexattr;
    
    int  log_username;   
    int  log_groupname;
    int  log_tty;
    int  log_login_time;
    int  log_remote_host;
    
    int  log_cmd;
    int  log_args;
    int  log_ppid;
    int  log_ppid_cmd;

} conf;

struct {

    long logg_id;
    char time[20];
    char host[256];
    char tag[64];
    char operation[32];

    int  uid;
    int  gid;
    char username[256];
    char groupname[256];

    char tty[16];
    char login_time[20];
    char remote_host[256];

    char cmd[1024];
    char args[1024];

    int  pid;
    
    int  ppid;
    char p_cmd[1024];
    
    char file[1024];
    int  protection;
    char owner[256];
    char group[256];

 } logg;

struct {

    long logg_id;
    char error_message[512];

} errors;

 struct {

    long logg_id;
    int  size;
    int  offset;
    char *write_data;

 } data_dump;

void  read_cfg(const char* file);
void  test_cfg(void);
void  sql_write(const char* path,const char* op);
void  sql_write_err(void);
void  sql_dump_write(void);
void  sql_get_last_id(void);
void  sql_err(MYSQL* conn,char* query);
int   is_str(const char* str);
int   is_full_path(const char* path);
void  get_timestamp(time_t t,char *ptr);
char* get_rel_path(const char* path);
char* get_abs_path(const char* path);
void  get_cfg_str(char* in,char* out,const char* opt,const int out_size);
void  get_cfg_val(char* in,int* out,const char* opt);
void  exit_gracefull(void);
