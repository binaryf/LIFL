# LIFL

Description
=================================================
	
LIFL. Linux Filesystem Logger. Version 0.1 beta.
A filesystem activities to MySQL database logging daemon.
This software is similar to loggedfs, (work from Rémi Flament and Victor Itkin),
but rewritten in C mainly with the purpose of storing data directly to database.

THIS IS A BETA VERSION, AND NEED TESTING.


Usage
=================================================
	
The program remount a directory-path as a virtual filesystem.

Any filesystem operations inside this directory,
is logged in detail.
	
The data can easily be arranged and analyzed by
making spesific sql queries.

Program is configurable and features can be
enabled or disabled.

Additional to the previous version of the project,
known as loggedfs, this is added:

+ Remote logging. (SQL).
+ Log data analyzing becomes easier with SQL.
+ Logging of user's tty, login time and remote host address.
+ A seperated cmd and arguments list.
+ Parent process pid also with the parent cmd.
+ Error messages are now stored as human readable strings.
+ Simple 'on' and 'off' switches to increase performance.
+ An experimental write data dump feature is implented.
 Controlled with options to limit the output
 to the effective userid, write size or a
 specified command you might want to target.

Remember to disable functionality you dont need.

The database formatted output can be of interest for further development.
My intention is to use a sql client front-end, like MySQLWorkbench.

This project, need a project! :)

Please feel free to interact.


Project goal
=================================================

+ Transparency.
+ Usability.
+ Stability.


Compiling
=================================================

You will need:

+ libmysqlclient-dev
+ libfuse-dev

Depending on your linux you need to set the flags
<pre>
-D_FILE_OFFSET_BITS=64
-D_FILE_OFFSET_BITS=32
</pre>

And eventually you might want to add
<pre>
-DHAVE_UTIMENSAT
-DHAVE_POSIX_FALLOCATE
-DHAVE_SETXATTR
</pre>

If you want to start lifl as your user, add
read permission to /etc/fuse.conf, or add your
user to fuse group.

To allow non-root users to use the allow_other mount option,
you must add 'user_allow_other' in /etc/fuse.conf.


Database
=================================================

+ create database
+ create database user
+ create tables from sql scripts. 

<pre>
operations.sql
errors.sql
data_dump.sql
</pre>

When you have created the database, the database user and
the tables, you will need a SELECT and INSERT permission for the program.

(DO NOT GIVE THE PROGRAM DATABASE USER ANY MORE PRIVLIGES).
	

Configuration
=================================================
	
+ Defualt filename is 'lifl.conf' 
+ (See "MANUAL")	


Using
=================================================

You have two options available:

<pre>
-c --config
-t --test
</pre>

Whithout any arguments program will start, daemonize, 
and load the configuration from default file.

Example:
<pre>
./lifl
./lifl --config lifl.config
./lifl --config lifl.config --test
</pre>

Notices
===============================================

+ Remember to unmount the virtual directory after use.

+ The write data dump is ment to be an extra (experimental) feature.
  Many calls to pwrite are of block sizes (4096).
  You might log unwanted junk if you dont narrow it down with
  configuration options.


Needs
==================================================

+ Testing!
+ Minor bug fixes?


Future features?
=================================================

+ Manpage
+ Makefile
+ Make thread-safe
+ Bandwith optimalization
+ Filelist to target locations

