smbcmp - diff, compare and debug SMB network traces 
====================================================


Synopsis
--------
**smbcmp** [-h] [-m {text,pdml}] [-c CONFIG] [-k KEYPAIR] CAPFILE1:NO [CAPFILE2:NO]


Description
-----------
**smbcmp** is small curses utility to diff, compare and debug SMB network traces.


Positional Arguments
---------------------

CAPFILE1:NO,
  first file/packet number

CAPFILE2:NO,
  second file/packet number (diff mode)


Options
------------
-h, --help
  Show this help message and exit

-m {text,pdml}, --mode {text,pdml}
  Diff method (default text)

-c CONFIG, --config CONFIG (default ~/.smbcmp)
  Read alternative config file 

-k KEYPAIR, --key KEYPAIR
  KEYPAIR can be either a path to a log file containing
  the keys (for the kernel client, enable
  CONFIG_CIFS_DEBUG_KEYS, for samba
  --option=debugencryption=yes) or literal session id &
  key pair given in hex (as SESSID,KEY). This option can
  be used multiple times to pass multiple keys.


See Also
-----------
smbcmp-gui(1)


Bugs
-------
No known bugs


Authors
--------
Aurelien Aptel <aurelien.aptel@gmail.com>
Mairo Paul Rufus <akoudanilo@gmail.com>

