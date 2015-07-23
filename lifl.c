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

#include "lifl.h"
#include "const.h"

long  id;
int   fd0;
MYSQL *conn;

void  read_cfg(const char* file)
{
    memset(&conf,0,sizeof(conf));
    FILE *fp;
    fp=fopen(file,"r");
    if(!fp)
    {
        fprintf(stderr,"Can not read config file : %s\n",file);
        exit(EXIT_FAILURE);
    }

    char *line=NULL;
    size_t len=0;

    char port[6];
    char uid[10];
    char size[10];

    memset(port,0,6);
    memset(uid,0,10);
    memset(size,0,10);
    
    while(getline(&line,&len,fp)!=-1)
    {
        get_cfg_str(line,conf.hostname,                 "hostname=",256);
        get_cfg_str(line,conf.tagname,                  "tagname=",64);
        get_cfg_str(line,conf.mountpoint,               "mountpoint=",1024);

        get_cfg_val(line,&conf.allow_other,             "allow_other=on");
        get_cfg_val(line,&conf.default_permissions,     "default_permissions=on");
        get_cfg_val(line,&conf.nonempty,                "nonempty=on");

        get_cfg_str(line,conf.db_host,                  "db_host=",256);
        get_cfg_str(line,port,                          "db_port=",6);
        get_cfg_str(line,conf.db_database,              "db_database=",64);
        get_cfg_str(line,conf.db_username,              "db_username=",64);
        get_cfg_str(line,conf.db_password,              "db_password=",64);

        get_cfg_str(line,conf.db_table,                 "db_table=",64);
        get_cfg_str(line,conf.db_dump_table,            "db_dump_table=",64);
        get_cfg_str(line,conf.db_error_table,           "db_error_table=",64);

        get_cfg_val(line,&conf.enable_error_messages,   "enable_error_messages=on");
        get_cfg_val(line,&conf.enable_write_dump,       "enable_write_dump=on");

        get_cfg_str(line,uid,                           "write_dump_effective_uid=",10);
        get_cfg_str(line,size,                          "write_dump_size_less_than=",10);
        get_cfg_str(line,conf.dump_cmd,                 "write_dump_cmd=",1024);

        get_cfg_val(line,&conf.syscall_getattr,         "syscall_getattr=on");
        get_cfg_val(line,&conf.syscall_access,          "syscall_access=on");
        get_cfg_val(line,&conf.syscall_readlink,        "syscall_readlink=on");
        get_cfg_val(line,&conf.syscall_readdir,         "syscall_readdir=on");
        get_cfg_val(line,&conf.syscall_mknod,           "syscall_mknod=on");
        get_cfg_val(line,&conf.syscall_mkdir,           "syscall_mkdir=on");
        get_cfg_val(line,&conf.syscall_unlink,          "syscall_unlink=on");
        get_cfg_val(line,&conf.syscall_rmdir,           "syscall_rmdir=on");
        get_cfg_val(line,&conf.syscall_symlink,         "syscall_symlink=on");
        get_cfg_val(line,&conf.syscall_rename,          "syscall_rename=on");
        get_cfg_val(line,&conf.syscall_link,            "syscall_link=on");
        get_cfg_val(line,&conf.syscall_chmod,           "syscall_chmod=on");
        get_cfg_val(line,&conf.syscall_chown,           "syscall_chown=on");
        get_cfg_val(line,&conf.syscall_truncate,        "syscall_truncate=on");
        
        #ifdef HAVE_UTIMENSAT
        get_cfg_val(line,&conf.syscall_utimens,         "syscall_utimens=on");
        #endif
        
        get_cfg_val(line,&conf.syscall_open,            "syscall_open=on");
        get_cfg_val(line,&conf.syscall_read,            "syscall_read=on");
        get_cfg_val(line,&conf.syscall_write,           "syscall_write=on");
        get_cfg_val(line,&conf.syscall_statfs,          "syscall_statfs=on");
        
        #ifdef HAVE_POSIX_FALLOCATE
        get_cfg_val(line,&conf.syscall_fallocate,       "syscall_fallocate=on");
        #endif
        
        #ifdef HAVE_SETXATTR
        get_cfg_val(line,&conf.syscall_setxattr,        "syscall_setxattr=on");
        get_cfg_val(line,&conf.syscall_getxattr,        "syscall_getxattr=on");
        get_cfg_val(line,&conf.syscall_listxattr,       "syscall_listxattr=on");
        get_cfg_val(line,&conf.syscall_removexattr,     "syscall_removexattr=on");
        #endif
        
        get_cfg_val(line,&conf.log_username,            "log_username=on");
        get_cfg_val(line,&conf.log_groupname,           "log_groupname=on");
        get_cfg_val(line,&conf.log_tty,                 "log_tty=on");
        get_cfg_val(line,&conf.log_login_time,          "log_login_time=on");
        get_cfg_val(line,&conf.log_remote_host,         "log_remote_host=on");

        get_cfg_val(line,&conf.log_cmd,                 "log_cmd=on");
        get_cfg_val(line,&conf.log_args,                "log_args=on");
        get_cfg_val(line,&conf.log_ppid,                "log_ppid=on");
        get_cfg_val(line,&conf.log_ppid_cmd,            "log_ppid_cmd=on");
    }
    
    fclose(fp);
    free(line);

    if(!is_str(conf.hostname))
    {
        if(gethostname(conf.hostname,256)==-1) memset(conf.hostname,0,256);   
    }
    if(sscanf(port,"%i",&conf.db_port)==0)
    {
        fprintf(stderr,"You must provide a port number.\n");
        exit(EXIT_FAILURE);
    }
    if(conf.enable_write_dump)
    {
        if(is_str(uid))
        {
            if(sscanf(uid,"%i",&conf.dump_uid)==0)
            {
                fprintf(stderr,"User id must be an integer value.\n");
                exit(EXIT_FAILURE);
            }
        }
        if(is_str(size))
        {
            if(sscanf(size,"%i",&conf.dump_size)==0)
            {
                fprintf(stderr,"Size limit must be an integer value.\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    if(!is_full_path(conf.mountpoint))
    {
        fprintf(stderr,"Use full path for mountpoint.\n");
        fprintf(stderr,"Mountpoint '%s' is not valid.\n",conf.mountpoint);
        exit(EXIT_FAILURE);
    }
}
void  test_cfg(void)
{
    fprintf(stdout,"\nConfiguration\n");
    fprintf(stdout,"----------------------------------------------------\n");  
    fprintf(stdout,"hostname :\t\t%s\n",conf.hostname);
    fprintf(stdout,"tagname :\t\t%s\n",conf.tagname);
    fprintf(stdout,"mountpoint :\t\t%s\n",conf.mountpoint);
    fprintf(stdout,"----------------------------------------------------\n");
    fprintf(stdout,"allow_other :\t\t"); if(conf.allow_other) fprintf(stdout,"yes\n"); else fprintf(stdout,"no\n");
    fprintf(stdout,"default_permissions:\t"); if(conf.default_permissions) fprintf(stdout,"yes\n"); else fprintf(stdout,"no\n");
    fprintf(stdout,"nonempty:\t\t"); if(conf.nonempty)  fprintf(stdout,"yes\n"); else fprintf(stdout,"no\n");
    fprintf(stdout,"----------------------------------------------------\n");
    fprintf(stdout,"db_host :\t\t%s\n",conf.db_host);
    fprintf(stdout,"db_port :\t\t%i\n",conf.db_port);
    fprintf(stdout,"db_database :\t\t%s\n",conf.db_database);
    fprintf(stdout,"db_username :\t\t%s\n",conf.db_username);
    fprintf(stdout,"db_password :\t\t******\n");
    fprintf(stdout,"db_table :\t\t%s\n",conf.db_table);
    fprintf(stdout,"----------------------------------------------------\n");
    if(conf.enable_error_messages)
    {
        fprintf(stdout,"Error messages enabled.\n");
        fprintf(stdout,"db_error_table:\t\t%s\n",conf.db_error_table);
    }
    if(conf.enable_write_dump)
    {
        fprintf(stdout,"Write dumps enabled.\n");
        fprintf(stdout,"db_dump_table:\t\t%s\n",conf.db_dump_table);
        if(conf.dump_uid) fprintf(stdout,"-- Effective user-id '%i'.\n",conf.dump_uid);
        if(conf.dump_size) fprintf(stdout,"-- Limit writes to '%i' kilobytes.\n",conf.dump_size);
        if(is_str(conf.dump_cmd)) fprintf(stdout,"-- Only monitoring the '%s' command.\n",conf.dump_cmd);
    }
    fprintf(stdout,"----------------------------------------------------\n");
    fprintf(stdout,"Following system calls are monitored :\n");
    if(conf.syscall_getattr)     fprintf(stdout,"getattr\n");     
    if(conf.syscall_access)      fprintf(stdout,"access\n");      
    if(conf.syscall_readlink)    fprintf(stdout,"readlink\n");    
    if(conf.syscall_readdir)     fprintf(stdout,"readdir\n");     
    if(conf.syscall_mknod)       fprintf(stdout,"mknod\n");
    if(conf.syscall_mkdir)       fprintf(stdout,"mkdir\n");     
    if(conf.syscall_unlink)      fprintf(stdout,"unlink\n");      
    if(conf.syscall_rmdir)       fprintf(stdout,"rmdir\n");     
    if(conf.syscall_symlink)     fprintf(stdout,"symlink\n");     
    if(conf.syscall_rename)      fprintf(stdout,"rename\n");
    if(conf.syscall_link)        fprintf(stdout,"link\n");      
    if(conf.syscall_chmod)       fprintf(stdout,"chmod\n");     
    if(conf.syscall_chown)       fprintf(stdout,"chown\n");     
    if(conf.syscall_truncate)    fprintf(stdout,"truncate\n");    
    if(conf.syscall_utimens)     fprintf(stdout,"utimens\n");     
    if(conf.syscall_open)        fprintf(stdout,"open\n");      
    if(conf.syscall_read)        fprintf(stdout,"read\n");
    if(conf.syscall_write)       fprintf(stdout,"write\n");     
    if(conf.syscall_statfs)      fprintf(stdout,"statfs\n");      
    if(conf.syscall_fallocate)   fprintf(stdout,"fallocate\n");   
    if(conf.syscall_setxattr)    fprintf(stdout,"setxattr\n");    
    if(conf.syscall_getxattr)    fprintf(stdout,"getxattr\n");
    if(conf.syscall_listxattr)   fprintf(stdout,"listxattr\n");   
    if(conf.syscall_removexattr) fprintf(stdout,"removexattr\n"); 
    fprintf(stdout,"----------------------------------------------------\n");
    fprintf(stdout,"Additional logging enabled:\n");
    if(conf.log_username)    fprintf(stdout,"username\n");
    if(conf.log_groupname)   fprintf(stdout,"groupname\n");
    if(conf.log_tty)         fprintf(stdout,"tty\n");
    if(conf.log_login_time)  fprintf(stdout,"logintime\n");
    if(conf.log_remote_host) fprintf(stdout,"remotehost\n");
    if(conf.log_cmd)         fprintf(stdout,"cmd\n"); 
    if(conf.log_args)        fprintf(stdout,"args\n");
    if(conf.log_ppid)        fprintf(stdout,"ppid\n");
    if(conf.log_ppid_cmd)    fprintf(stdout,"ppidcmd\n");
    fprintf(stdout,"----------------------------------------------------\n");

    conn=mysql_init(NULL);
    if(!conn) sql_err(conn,NULL);
    if(!mysql_real_connect(conn,conf.db_host,conf.db_username,conf.db_password,conf.db_database,conf.db_port,NULL,0)) sql_err(conn,NULL);
    fprintf(stdout,"connectivity \t\t\t[ok]\n");

    id=1;

    logg.logg_id=id;
    get_timestamp(0,logg.time);
    strncpy(logg.host,conf.hostname,256);
    strncpy(logg.tag,"test",64); 
    strncpy(logg.operation,"sql insert",32);
    logg.uid=800;
    logg.gid=800;
    strncpy(logg.username,"test",256);
    strncpy(logg.groupname,"test",256);
    strncpy(logg.tty,"pts/0",16);
    get_timestamp(0,logg.login_time);
    strncpy(logg.remote_host,"localhost",256);
    strncpy(logg.cmd,"lifl",1024);
    strncpy(logg.args,"--test",1024);
    logg.pid=200;
    logg.ppid=100;
    strncpy(logg.p_cmd,"system",1024);
    strncpy(logg.file,"/path/to/folder",1024);
    logg.protection=330;
    strncpy(logg.owner,"admin",256);
    strncpy(logg.group,"admin",256);

    size_t size;
    size=strlen(INS)
    +strlen(conf.db_database)
    +strlen(conf.db_table)
    +20
    +strlen(logg.time)
    +strlen(logg.host)
    +strlen(logg.tag)
    +strlen(logg.operation)
    +10
    +10
    +strlen(logg.username)
    +strlen(logg.groupname)
    +strlen(logg.tty)
    +strlen(logg.login_time)
    +strlen(logg.remote_host)
    +strlen(logg.cmd)
    +strlen(logg.args)
    +10
    +10
    +strlen(logg.p_cmd)
    +strlen(logg.file)
    +10
    +strlen(logg.owner)
    +strlen(logg.group);

    char *buf;
    buf=malloc(size);
    if(!buf) exit(EXIT_FAILURE);

    if((size=snprintf(buf,size,
        INS,
        conf.db_database,
        conf.db_table,
        logg.logg_id,
        logg.time,
        logg.host,
        logg.tag,
        logg.operation,
        logg.uid,
        logg.gid,
        logg.username,
        logg.groupname,
        logg.tty,
        logg.login_time,
        logg.remote_host,
        logg.cmd,
        logg.args,
        logg.pid,
        logg.ppid,
        logg.p_cmd,
        logg.file,
        logg.protection,
        logg.owner,
        logg.group))) {

         if(mysql_real_query(conn,buf,size)) sql_err(conn,buf);    
    } ;

    free(buf);
    fprintf(stdout,"%s \t\t\t[ok]\n",conf.db_table);

    if(conf.enable_write_dump)
    {
        FILE *fp;
        fp=fopen("/bin/bash","r");
        if(fp)
        {
            buf=malloc(1024);
            if(!buf) exit(EXIT_FAILURE);
            size=fread(buf,1,1024,fp);
            fclose(fp);
        }
        else
        {
            buf=NULL;
            size=0;
        }
        data_dump.size=size;
        data_dump.offset=0;
        data_dump.write_data=buf;
        sql_dump_write();
        free(buf);
        fprintf(stdout,"%s \t\t\t[ok]\n",conf.db_dump_table);
    }
    if(conf.enable_error_messages)
    {
        sql_write_err();
        fprintf(stdout,"%s \t\t\t\t[ok]\n",conf.db_error_table);
    }
    mysql_close(conn);
}
void  sql_write(const char* path,const char* op)
{
    memset(&logg,0,sizeof(logg));

    ++id;
    logg.logg_id=id;

    get_timestamp(0,logg.time);
    strncpy(logg.operation,op,32);
    
    // REMEMBER: path my be non existing //

    char *absolute_path;
    char *relative_path;
    absolute_path=get_abs_path(path);
    relative_path=get_rel_path(path);
    strncpy(logg.file,absolute_path,1024);
    
    struct stat stbuf;
    if(lstat(relative_path,&stbuf)==0)
    {
        logg.protection=(unsigned int)stbuf.st_mode;

        uid_t uid;
        uid=stbuf.st_uid;
        size_t buflen;
        buflen=sysconf(_SC_GETPW_R_SIZE_MAX);
        if(buflen==-1) exit(EXIT_FAILURE);
        char *buf;
        buf=malloc(buflen);
        if(!buf) exit(EXIT_FAILURE);
        struct passwd pwd;
        struct passwd *pwd_result;
        if(getpwuid_r(uid,&pwd,buf,buflen,&pwd_result)==0)
        {
            if(pwd_result) strncpy(logg.owner,pwd.pw_name,256);
        }
        free(buf);
        gid_t gid;
        gid=stbuf.st_gid;
        buflen=sysconf(_SC_GETGR_R_SIZE_MAX);
        if(buflen==-1) exit(EXIT_FAILURE);
        buf=malloc(buflen);
        if(!buf) exit(EXIT_FAILURE);
        struct group grp;
        struct group *grp_result;
        if(getgrgid_r(gid,&grp,buf,buflen,&grp_result)==0)
        {
            if(grp_result) strncpy(logg.group,grp.gr_name,256);
        }
        free(buf);
    }
    free(absolute_path);
    free(relative_path);

    strncpy(logg.host,conf.hostname,256);
    strncpy(logg.tag,conf.tagname,64); 
    
    logg.uid=(unsigned int)fuse_get_context()->uid;
    logg.gid=(unsigned int)fuse_get_context()->gid; 
    logg.pid=(unsigned int)fuse_get_context()->pid;

    if(conf.log_username)
    {
        uid_t uid;
        uid=fuse_get_context()->uid;
        size_t buflen;
        buflen=sysconf(_SC_GETPW_R_SIZE_MAX);
        if(buflen==-1) exit(EXIT_FAILURE);
        char *buf;
        buf=malloc(buflen);
        if(!buf) exit(EXIT_FAILURE);
        struct passwd pwd;
        struct passwd *result;
        if(getpwuid_r(uid,&pwd,buf,buflen,&result)==0)
        {
            if(result) strncpy(logg.username,pwd.pw_name,256);
        }
        free(buf);
        
        if(is_str(logg.username))
        {
            if(conf.log_tty||conf.log_remote_host||conf.log_login_time)
            {
                setutxent();
                struct utmpx *utx;
                while((utx=getutxent()))
                {
                    if(!strcmp(logg.username,utx->ut_user))
                    {
                       if(conf.log_tty) strncpy(logg.tty,utx->ut_line,16);
                       if(conf.log_remote_host) strncpy(logg.remote_host,utx->ut_host,256);
                       if(conf.log_login_time) get_timestamp(utx->ut_tv.tv_sec,logg.login_time);
                   }
                }
                endutxent();
            }
        }
    }
    if(conf.log_groupname)
    {
        gid_t gid;
        gid=fuse_get_context()->gid;
        size_t buflen;
        buflen=sysconf(_SC_GETGR_R_SIZE_MAX);
        if(buflen==-1) exit(EXIT_FAILURE);
        char *buf;
        buf=malloc(buflen);
        if(!buf) exit(EXIT_FAILURE);
        struct group grp;
        struct group *result;
        if(getgrgid_r(gid,&grp,buf,buflen,&result)==0)
        {
            if(result) strncpy(logg.groupname,grp.gr_name,256);
        }
        free(buf);
    }

    if(conf.log_cmd)
    {
        size_t size;
        size=strlen("/proc//cmdline")+10+1;
        char *buf;
        buf=malloc(size);
        if(!buf) exit(EXIT_FAILURE);

        if(snprintf(buf,size,"/proc/%i/cmdline",logg.pid))
        {
            FILE *fp;
            fp=fopen(buf,"r");
            free(buf);
            if(!fp) return;
            buf=malloc(1024);
            if(!buf) exit(EXIT_FAILURE);
            size_t bytes_r;
            bytes_r=fread(buf,1,1024,fp);
            fclose(fp);
            if(bytes_r==0)
            {
                free(buf);
                return;
            }
            strncpy(logg.cmd,buf,1024);    
            if(conf.log_args)
            {
                int i=0;
                while(++i<bytes_r-1) if(buf[i]==0x00) buf[i]=0x20; 
                int str_off=strlen(logg.cmd);
                strncpy(logg.args,&buf[str_off],1024);
                free(buf);
            } 
        }
    }
    if(conf.log_ppid)
    {
        size_t size;
        size=strlen("/proc//status")+10+1;
        char *buf;
        buf=malloc(size);
        if(!buf) exit(EXIT_FAILURE);
        if(snprintf(buf,size,"/proc/%i/status",logg.pid))
        {
            FILE *fp;
            fp=fopen(buf,"r");
            free(buf);
            if(!fp) return;
            char *line=NULL;
            size_t len=0;
            while(getline(&line,&len,fp)!=-1)
            {
                if(!strncmp(line,"PPid:",5))
                {
                    if((strlen(line)-6)<20) sscanf(line,"PPid:\t%i",&logg.ppid);
                    break;
                }
            }
            fclose(fp);
            free(line);
        }
        if(conf.log_ppid_cmd)
        {
            size_t size;
            size=strlen("/proc//cmdline")+10+1;
            char *buf;
            buf=malloc(size);
            if(!buf) exit(EXIT_FAILURE);

            if(snprintf(buf,size,"/proc/%i/cmdline",logg.ppid))
            {
                FILE *fp;
                fp=fopen(buf,"r");
                free(buf);
                if(!fp) return;
                buf=malloc(1024);
                if(!buf) exit(EXIT_FAILURE);
                size_t bytes_r;
                bytes_r=fread(buf,1,1024,fp);
                fclose(fp);
                if(bytes_r==0)
                {
                    free(buf);
                    return;
                }
                strncpy(logg.p_cmd,buf,1024);
                free(buf);
            }
        }
    } 
    
    size_t size;
    size=strlen(INS)
    +strlen(conf.db_database)
    +strlen(conf.db_table)
    +20
    +strlen(logg.time)
    +strlen(logg.host)
    +strlen(logg.tag)
    +strlen(logg.operation)
    +10
    +10
    +strlen(logg.username)
    +strlen(logg.groupname)
    +strlen(logg.tty)
    +strlen(logg.login_time)
    +strlen(logg.remote_host)
    +strlen(logg.cmd)
    +strlen(logg.args)
    +10
    +10
    +strlen(logg.p_cmd)
    +strlen(logg.file)
    +10
    +strlen(logg.owner)
    +strlen(logg.group);

    char *buf;
    buf=malloc(size);
    if(!buf) exit(EXIT_FAILURE);

    if((size=snprintf(buf,size,
        INS,
        conf.db_database,
        conf.db_table,
        logg.logg_id,
        logg.time,
        logg.host,
        logg.tag,
        logg.operation,
        logg.uid,
        logg.gid,
        logg.username,
        logg.groupname,
        logg.tty,
        logg.login_time,
        logg.remote_host,
        logg.cmd,
        logg.args,
        logg.pid,
        logg.ppid,
        logg.p_cmd,
        logg.file,
        logg.protection,
        logg.owner,
        logg.group))) {

            if(mysql_real_query(conn,buf,size)) sql_err(conn,buf);    
    }
    free(buf); 
}
void  sql_write_err(void)
{  
    errors.logg_id=id;
    char str[512];
    memset(str,0,512);
    int ret;
    ret=strerror_r(errno,str,512);
    if(ret!=0) snprintf(str,512,"Unknown error");  
    snprintf(errors.error_message,512,"ERROR (%s)",str);    
    size_t size;
    size=strlen(ERR)
    +strlen(conf.db_database)
    +strlen(conf.db_error_table)
    +20
    +strlen(errors.error_message)
    +1;
    char *buf;
    buf=malloc(size);
    if(!buf) exit(EXIT_FAILURE);
    if((size=snprintf(buf,size,
        ERR,
        conf.db_database,
        conf.db_error_table,
        errors.logg_id,
        errors.error_message))) {
            if(mysql_real_query(conn,buf,size)) sql_err(conn,buf);
    }
    free(buf);
}
void  sql_dump_write(void)
{
    data_dump.logg_id=id;
    char *to;
    to=malloc(data_dump.size*2+1);
    if(!to) exit(EXIT_FAILURE);
    unsigned long length;
    length=mysql_real_escape_string(conn,to,data_dump.write_data,data_dump.size);
    size_t size;
    size=strlen(BWD)
    +strlen(conf.db_database)
    +strlen(conf.db_dump_table)
    +20
    +10
    +10
    +length
    +1;
    char *buf;
    buf=malloc(size);
    if(!buf) exit(EXIT_FAILURE);
    if((size=snprintf(buf,size,
        BWD,
        conf.db_database,
        conf.db_dump_table,
        data_dump.logg_id,
        data_dump.size,
        data_dump.offset,
        to))) {

            if(mysql_real_query(conn,buf,size)) sql_err(conn,buf);
    }
    free(to);
    free(buf);
}
void  sql_get_last_id(void)
{
    size_t size;
    size=strlen(GET)
    +strlen(conf.db_database)
    +strlen(conf.db_table)
    +1;
    char *buf;
    buf=malloc(size);
    if(!buf) exit(EXIT_FAILURE);
    if((size=snprintf(buf,size,
        GET,
        conf.db_database,
        conf.db_table))) {
            if(mysql_real_query(conn,buf,size)) sql_err(conn,buf);
            MYSQL_RES *res;
            res=mysql_store_result(conn);
            if(!res) sql_err(conn,buf);
            free(buf);
            MYSQL_ROW row;
            row=mysql_fetch_row(res);
            if(!row) id=0;
            else if(sscanf(row[0],"%li",&id)==0)
            {
                fprintf(stderr,"Failed to fetching row counter.\n");
                fprintf(stderr,"Starting at 0.\n");
                id=0;
            }
            mysql_free_result(res);
    }
}
void  sql_err(MYSQL* conn,char* query)
{
    fprintf(stderr,"Error %u: %s\n",mysql_errno(conn),mysql_error(conn));
    if(is_str(query)) fprintf(stderr,"\nQuery =\n\n%s\n\n",query);
    exit(EXIT_FAILURE);
}
int  is_str(const char* str)
{       
    if(!str) return(0);
    int len;
    len=strlen(str);
    if(len<1) return(0); // len>=1 is considered a string.
    while(--len>=0)
    {       
        if(!isprint(str[len])) return(0);
    }
    return(1);
}
int  is_full_path(const char* path)
{
    if(is_str(path))
    {
        if(path[0]=='/') return(1);
    }
    return(0);
}
void get_timestamp(time_t t,char *ptr)
{
    if(!ptr) exit(EXIT_FAILURE);

    if(t==0)
    {
        t=time(NULL);
        if(t==-1) exit(EXIT_FAILURE);
    }
    if(!strftime(ptr,20,"%Y-%m-%d %T",localtime(&t))) exit(EXIT_FAILURE);
}
char* get_rel_path(const char* path)
{
    size_t size;
    size=strlen(path)+2;
    char *relative_path;
    relative_path=malloc(size);
    if(!relative_path) exit(EXIT_FAILURE);
    strncpy(relative_path,".",size); // path should start with slash here.
    strcat(relative_path,path);
    return(relative_path);
}
char* get_abs_path(const char* path)
{
    size_t size;
    size=strlen(path)+strlen(conf.mountpoint)+1;
    char *realpath;
    realpath=malloc(size);
    if(!realpath) exit(EXIT_FAILURE);
    strcpy(realpath,conf.mountpoint);
    if(realpath[strlen(realpath)-1]=='/') realpath[strlen(realpath)-1]='\0';
    strcat(realpath,path);
    return(realpath);
}
void get_cfg_str(char* in,char* out,const char* opt,const int out_size)
{
    if(in)
    {
        int opt_len;
        opt_len=strlen(opt);

        if(!strncmp(in,opt,opt_len))
        {
            int in_len;
            in_len=strlen(in);

            if(in_len>opt_len)
            {
                if(out)
                {
                    in=(char*)&in[opt_len];
                    in_len=strlen(in);

                    if(out_size>=in_len)
                    {
                        while(--in_len>=0)
                        {
                            if(in[in_len]=='\n') in[in_len]='\0';
                        }
                        strncpy(out,in,out_size);
                    }
                }
            }
       }
    }
}
void get_cfg_val(char* in,int* out,const char* opt)
{
    if(in)
    {
        int opt_len;
        opt_len=strlen(opt);

        if(!strncmp(in,opt,opt_len))
        {
            *out=1;
        }
    }
}
void exit_gracefull(void)
{
    if(errno)
    {
        char str[512];
        memset(str,0,512);
        int ret;
        ret=strerror_r(errno,str,512);
        if(ret!=0) sprintf(str,"Unknown error");
        fprintf(stderr,"Sorry the program encountered a problem.\n");
        fprintf(stderr,"Error : %s\n",str);    
    }
    fprintf(stdout,"Exiting.\n");
}

/* The following code is copied directly from the fuse api example 'fusexmp.c'. */
/* Additional code is added. */

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    if(conf.syscall_getattr) sql_write(path,"status");
    
    int res;
    char *rpath;
    rpath=get_rel_path(path);
    res = lstat(rpath, stbuf);
    free(rpath);
        
    if (res == -1)
    {
        if(conf.syscall_getattr && conf.enable_error_messages) sql_write_err();
        return -errno;
    }
    
    return 0;
}
static int xmp_access(const char *path, int mask)
{
    if(conf.syscall_access) sql_write(path,"access");
    
    int res;
    char *rpath;
    rpath=get_rel_path(path);
    res = access(rpath, mask);
    free(rpath);
        
    if (res == -1)
    {
        if(conf.syscall_access && conf.enable_error_messages) sql_write_err();
        return -errno;
    }
        
    return 0;
}
static int xmp_readlink(const char *path, char *buf, size_t size)
{
    if(conf.syscall_readlink) sql_write(path,"readlink");

    int res;
    char *rpath;
    rpath=get_rel_path(path);
    res = readlink(rpath, buf, size - 1);
    free(rpath);        
        
    if (res == -1)
    {
        if(conf.syscall_readlink && conf.enable_error_messages) sql_write_err();
        return -errno;
    }
    buf[res] = '\0';    
    
    return 0;
}
static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    if(conf.syscall_readdir) sql_write(path,"readdir");

    DIR *dp;
    struct dirent *de;
    (void) offset;
    (void) fi;
    
    char *rpath;
    rpath=get_rel_path(path);
    dp = opendir(rpath);
    free(rpath);
        
    if (dp == NULL)
    {
        if(conf.syscall_readdir && conf.enable_error_messages) sql_write_err();
        return -errno;
    }
    while ((de = readdir(dp)) != NULL) {
            struct stat st;
            memset(&st, 0, sizeof(st));
            st.st_ino = de->d_ino;
            st.st_mode = de->d_type << 12;
            if (filler(buf, de->d_name, &st, 0))
                    break;
        }
        
        closedir(dp);
        return 0;
}
static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
        int res;
        /* On Linux this could just be 'mknod(path, mode, rdev)' but this
           is more portable */
        char *rpath;
        rpath=get_rel_path(path);

        if (S_ISREG(mode))
        {
            res = open(rpath, O_CREAT | O_EXCL | O_WRONLY, mode);
            
            if (res >= 0)
            {
                res = close(res); 
            }
        }
        else if (S_ISFIFO(mode))
        {
            res = mkfifo(rpath, mode);
        }
        else
        {
            res = mknod(rpath, mode, rdev);
        }

        if (res == -1)
        {
            if(conf.syscall_mknod && conf.enable_error_messages) sql_write(path,"mknod");
            if(conf.syscall_mknod && conf.enable_error_messages) sql_write_err();
            free(rpath);
            return -errno;
        }
        
        lchown(rpath,fuse_get_context()->uid,fuse_get_context()->gid);
        if(conf.syscall_mknod) sql_write(path,"mknod");
        free(rpath);

        return 0;
}
static int xmp_mkdir(const char *path, mode_t mode)
{
    if(conf.syscall_mkdir) sql_write(path,"mkdir");

    int res;
    char *rpath;
    rpath=get_rel_path(path);
    res = mkdir(rpath, mode);
         
    if (res == -1)
    {
        if(conf.syscall_mkdir && conf.enable_error_messages) sql_write_err();
        free(rpath);
        return -errno;
    }

    lchown(rpath,fuse_get_context()->uid,fuse_get_context()->gid);
    free(rpath);
    return 0;
}
static int xmp_unlink(const char *path)
{
    if(conf.syscall_unlink) sql_write(path,"unlink");

    int res;
    char *rpath;
    rpath=get_rel_path(path);
    res = unlink(rpath);
    free(rpath);
        
    if (res == -1)
    {
        if(conf.syscall_unlink && conf.enable_error_messages) sql_write_err();
        return -errno;
    }

    return 0;
}
static int xmp_rmdir(const char *path)
{
        if(conf.syscall_rmdir) sql_write(path,"rmdir");

        int res;
        char *rpath;
        rpath=get_rel_path(path);
        res = rmdir(rpath);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_rmdir && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
static int xmp_symlink(const char *from, const char *to)
{
        if(conf.syscall_symlink) sql_write(from,"symlink");

        int res;
        char *rto;
        rto=get_rel_path(to);
        res = symlink(from, rto);
        
        if (res == -1)
        {
            if(conf.syscall_symlink && conf.enable_error_messages) sql_write_err();
            free(rto);
            return -errno;
        }
        
        lchown(rto,fuse_get_context()->uid,fuse_get_context()->gid);
        free(rto);
        return 0;
}
static int xmp_rename(const char *from, const char *to)
{
        if(conf.syscall_rename) sql_write(from,"rename");

        int res;
        char *rfrom;
        rfrom=get_rel_path(from);
        char *rto;
        rto=get_rel_path(to);
        res = rename(rfrom, rto);
        free(rfrom);
        free(rto);

        if (res == -1)
        {
            if(conf.syscall_rename && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
static int xmp_link(const char *from, const char *to)
{
        if(conf.syscall_link) sql_write(from,"link");   

        int res;
        char *rfrom;
        rfrom=get_rel_path(from);
        char *rto;
        rto=get_rel_path(to);
        res = link(rfrom, rto);
        free(rfrom);

        if (res == -1)
        {
            if(conf.syscall_link && conf.enable_error_messages) sql_write_err();
            free(rto);
            return -errno;
        }
        
        lchown(rto,fuse_get_context()->uid,fuse_get_context()->gid);
        free(rto);
        return 0;
}
static int xmp_chmod(const char *path, mode_t mode)
{
        if(conf.syscall_chmod) sql_write(path,"chmod");

        int res;
        char *rpath;
        rpath=get_rel_path(path);
        res = chmod(rpath, mode);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_chmod && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
        if(conf.syscall_chown) sql_write(path,"chown");

        int res;
        char *rpath;
        rpath=get_rel_path(path);
        res = lchown(rpath, uid, gid);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_chown && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
static int xmp_truncate(const char *path, off_t size)
{
        if(conf.syscall_truncate) sql_write(path,"truncate");

        int res;
        char *rpath;
        rpath=get_rel_path(path);
        res = truncate(rpath, size);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_truncate && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2])
{
        if(conf.syscall_utimens) sql_write(path,"utimens");

        int res;
        /* don't use utime/utimes since they follow symlinks */
        char *rpath;
        rpath=get_rel_path(path);
        res = utimensat(0, rpath, ts, AT_SYMLINK_NOFOLLOW);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_utimens && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
#endif
static int xmp_open(const char *path, struct fuse_file_info *fi)
{
        if(conf.syscall_open) sql_write(path,"open");

        int res;
        char *rpath;
        rpath=get_rel_path(path);
        res = open(rpath, fi->flags);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_open && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        close(res);
        
        return 0;
}
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
        if(conf.syscall_read) sql_write(path,"read");

        int fd;
        int res;
        (void) fi;
        char *rpath;
        rpath=get_rel_path(path);
        fd = open(rpath, O_RDONLY);
        free(rpath);
        
        if (fd == -1)
        {
            if(conf.syscall_read && conf.enable_error_messages) sql_write_err();
            return -errno;
        }      
        res = pread(fd, buf, size, offset);
        if (res == -1)
        {
            if(conf.syscall_read && conf.enable_error_messages) sql_write_err();
            res = -errno;
        }
        close(fd);
        
        return res;
}
static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
        if(conf.syscall_write) sql_write(path,"write");

        int fd;
        int res;
        (void) fi;
        char *rpath;
        rpath=get_rel_path(path);
        fd = open(rpath, O_WRONLY);
        free(rpath);
        
        if (fd == -1)
        {
            if(conf.syscall_write && conf.enable_error_messages) sql_write_err();
            return -errno;
        }

        res = pwrite(fd, buf, size, offset);
        if (res == -1)
        {
            if(conf.syscall_write && conf.enable_error_messages) sql_write_err();
            res = -errno;
        }
        close(fd);
        
        if(conf.enable_write_dump)
        {
            data_dump.size=res;
            data_dump.offset=(int)offset;
            
            if(conf.dump_uid && conf.dump_uid!=(unsigned int)fuse_get_context()->uid)
            {
                return res;
            }

            if(conf.dump_size && conf.dump_size<data_dump.size)
            {
                return res;
            }

            if(is_str(conf.dump_cmd) && strncmp(conf.dump_cmd,logg.cmd,1024)!=0)
            {
                return res;
            }
       
            char *ptr;
            ptr=malloc(res);
            if(!ptr) exit(EXIT_FAILURE);
            memset(ptr,0,res);
            memcpy(ptr,buf,res);
            if(!ptr) exit(EXIT_FAILURE);
            data_dump.write_data=ptr;
            sql_dump_write();
            free(ptr);
        }

        return res;
}
static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
        if(conf.syscall_statfs) sql_write(path,"statfs");

        int res;
        char *rpath;
        rpath=get_rel_path(path);
        res = statvfs(rpath, stbuf);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_statfs && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
static int xmp_release(const char *path, struct fuse_file_info *fi)
{
        /* Just a stub.  This method is optional and can safely be left
           unimplemented */
        (void) path;
        (void) fi;
        return 0;
}
static int xmp_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
        /* Just a stub.  This method is optional and can safely be left
           unimplemented */
        (void) path;
        (void) isdatasync;
        (void) fi;
        return 0;
}
#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
                        off_t offset, off_t length, struct fuse_file_info *fi)
{
        if(conf.syscall_fallocate) sql_write(path,"fallocate");

        int fd;
        int res;
        (void) fi;
        
        if (mode)
        {
            if(conf.syscall_fallocate && conf.enable_error_messages) sql_write_err();
            return -EOPNOTSUPP;
        }

        char *rpath;
        rpath=get_rel_path(path);
        fd = open(rpath, O_WRONLY);
        free(rpath);
        
        if (fd == -1)
        {
            if(conf.syscall_fallocate && conf.enable_error_messages) sql_write_err();
            return -errno;
        }

        res = -posix_fallocate(fd, offset, length);
        close(fd);
        
        return res;
}
#endif
#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
        if(conf.syscall_setxattr) sql_write(path,"setxattr");

        char *rpath;
        rpath=get_rel_path(path);
        int res = lsetxattr(rpath, name, value, size, flags);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_setxattr && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
static int xmp_getxattr(const char *path, const char *name, char *value,
                        size_t size)
{
        if(conf.syscall_getxattr) sql_write(path,"getxattr");

        char *rpath;
        rpath=get_rel_path(path);
        int res = lgetxattr(rpath, name, value, size);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_getxattr && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return res;
}
static int xmp_listxattr(const char *path, char *list, size_t size)
{
        if(conf.syscall_listxattr) sql_write(path,"listxattr");

        char *rpath;
        rpath=get_rel_path(path);
        int res = llistxattr(rpath, list, size);
        free(rpath);

        if (res == -1)
        {
            if(conf.syscall_listxattr && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return res;
}
static int xmp_removexattr(const char *path, const char *name)
{
        if(conf.syscall_removexattr) sql_write(path,"removexattr");

        char *rpath;
        rpath=get_rel_path(path);
        int res = lremovexattr(rpath, name);
        free(rpath);
        
        if (res == -1)
        {
            if(conf.syscall_removexattr && conf.enable_error_messages) sql_write_err();
            return -errno;
        }
        
        return 0;
}
#endif /* HAVE_SETXATTR */

static void* lifl_init(struct fuse_conn_info* info)
{
     fchdir(fd0);
     close(fd0);
     return(NULL);
}

int main(int argc,char *argv[])
{
    id=0;

    umask(0);

    if(atexit(exit_gracefull)!=0)
    {
        fprintf(stderr,"Sorry the program encountered a problem.\nExiting.\n");
        exit(EXIT_FAILURE);
    }

    static struct fuse_operations op;

    op.init           =lifl_init;

    op.getattr        =xmp_getattr;
    op.access         =xmp_access;
    op.readlink       =xmp_readlink;
    op.readdir        =xmp_readdir;
    op.mknod          =xmp_mknod;
    op.mkdir          =xmp_mkdir;
    op.symlink        =xmp_symlink;
    op.unlink         =xmp_unlink;
    op.rmdir          =xmp_rmdir;
    op.rename         =xmp_rename;
    op.link           =xmp_link;
    op.chmod          =xmp_chmod;
    op.chown          =xmp_chown;
    op.truncate       =xmp_truncate;

    #ifdef HAVE_UTIMENSAT
    op.utimens        =xmp_utimens,
    #endif

    op.open           =xmp_open;
    op.read           =xmp_read;
    op.write          =xmp_write;
    op.statfs         =xmp_statfs;
    op.release        =xmp_release;
    op.fsync          =xmp_fsync;

    #ifdef HAVE_POSIX_FALLOCATE
    op.fallocate      =xmp_fallocate;
    #endif

    #ifdef HAVE_SETXATTR
    op.setxattr       =xmp_setxattr;
    op.getxattr       =xmp_getxattr;
    op.listxattr      =xmp_listxattr;
    op.removexattr    =xmp_removexattr;
    #endif

    char config_file[255];
    strncpy(config_file,DEFAULT_CONF_NAME,255);
  
    static struct option long_options[]=
    {
            {"help",          no_argument,       0, 'h'},
            {"config",        required_argument, 0, 'c'},
            {"test",          no_argument,       0, 't'},
            {0,               0,                 0,  0 }
    };

    while(1)
    {
        int option_index=0;
        int ch=getopt_long(argc,argv,"hc:t",long_options,&option_index);
        
        if(ch==-1) break;
        switch (ch)
        {
        case 'h':
            fprintf(stdout,"-h --help\n");
            fprintf(stdout,"-c --config <filename>\n");
            fprintf(stdout,"-t --test\n");
            exit(EXIT_SUCCESS);    
        case 'c':
            strncpy(config_file,optarg,255);  
            break;
        case 't':
            read_cfg(config_file);
            test_cfg();
            errno=0;
            exit(EXIT_SUCCESS);
        }
    }

    if(optind<argc)
    {
        while(optind<argc) fprintf(stderr,"%s is not a valid argument\n",argv[optind++]);
    }

    read_cfg(config_file);
    
    conn=mysql_init(NULL);
    if(!conn) sql_err(conn,NULL);
    if(!mysql_real_connect(conn,conf.db_host,conf.db_username,conf.db_password,conf.db_database,conf.db_port,NULL,0)) sql_err(conn,NULL);

    sql_get_last_id();

    fprintf(stdout,"Starting up...\n");
    sleep(2);
    
    chdir(conf.mountpoint);
    fd0=open(".",0);

    char *fuse_argv[8];
    memset(fuse_argv,0,sizeof(fuse_argv));

    int fuse_argc;
    fuse_argc=0;

    fuse_argv[fuse_argc++]=argv[0];
    fuse_argv[fuse_argc++]=conf.mountpoint;

    if(conf.allow_other)
    {
        fuse_argv[fuse_argc++]="-o";
        fuse_argv[fuse_argc++]="allow_other";
    }

    if(conf.default_permissions)
    {
        fuse_argv[fuse_argc++]="-o";
        fuse_argv[fuse_argc++]="default_permissions";
    }
    
    if(conf.nonempty)
    {
        fuse_argv[fuse_argc++]="-o";
        fuse_argv[fuse_argc++]="nonempty";
    }

    fuse_argv[fuse_argc++]="-o";
    fuse_argv[fuse_argc++]="use_ino";
    fuse_argv[fuse_argc]=NULL;

    fuse_main(fuse_argc,fuse_argv,&op,NULL);
    mysql_close(conn);
    exit(EXIT_SUCCESS);
}
