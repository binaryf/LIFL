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

#define DEFAULT_CONF_NAME "lifl.conf"

#define GET "SELECT `operation_id` FROM `%s`.`%s` ORDER BY `row` DESC LIMIT 1;"

#define INS "INSERT INTO `%s`.`%s` (`operation_id`,`time`,`host`,`tag`,`operation`,`uid`,`gid`,`username`,`groupname`,`tty`,`login_time`,`remote_host`,`cmd`,`args`,`pid`,`ppid`,`p_cmd`,`file`,`protection`,`owner`,`group`) VALUES ('%li','%s','%s','%s','%s','%i','%i','%s','%s','%s','%s','%s','%s','%s','%i','%i','%s','%s','%i','%s','%s');" 
#define BWD "INSERT INTO `%s`.`%s` (`operation_id`,`size`,`offset`,`write_data`) VALUES ('%li','%i','%i','%s');"
#define ERR "INSERT INTO `%s`.`%s` (`operation_id`,`error_message`) VALUES ('%li','%s');"
