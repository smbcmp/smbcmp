smbcmp
======

Small curses utility to diff, compare and debug SMB network traces.


[![demo](https://asciinema.org/a/235634.svg)](https://asciinema.org/a/235634)



Install
=======

### Requirements

- python3
- python3-curses
- python3-lxml (optionnal)
- tshark (wireshark)

If you are interested in the wxWidget-based version of the UI you will also need:

- python3-wxPython

### smbcmp

There are no packages for now so you will need to get the sources:

    $ git clone https://github.com/smbcmp/smbcmp.git
    $ cd smbcmp
    $ PYTHONPATH=$PWD scripts/smbcmp --help

To have it readily available from your shell you can setup the following:

Assuming you have `~/bin` in your `PATH` env var, you can run this to
add a simple launcher (replace `<DIR>` by the path to the git
directory).

    echo -e '#!/bin/sh\nset -e\ncd <DIR>\nPYTHONPATH=$(pwd) scripts/smbcmp "$@"' > ~/bin/smbcmp && chmod +x ~/bin/smbcmp

For the GUI

    echo -e '#!/bin/sh\nset -e\ncd <DIR>\nPYTHONPATH=$(pwd) scripts/smbcmp-gui "$@"' > ~/bin/smbcmp-gui && chmod +x ~/bin/smbcmp-gui

Usage
=====

You can view single capture, similar to a simple console version of wireshark

    $ smbcmp a.pcap

Or you can diff 2 capture side by side, with a diff on the bottom pane

    $ smbcmp a.pcap b.pcap


Features
========

- Based on wireshark (tshark): supports SMB1/2/3
- Decryption support
  - pass sesid/keys via command line option
  - can parse crypto keys
    - from linux kernel console (requires `CONFIG_CIFS_DEBUG_DUMP_KEYS` enabled)
    - from samba/smbclient (`--option=debugencryption=yes`)
- Highlights non-sucessful responses


Key bindings
============

Default keybindings (see Configuration to change them):

- d/f: next/prev line in left pane
- j/k: next/prev line in right pane
- down/up: next/prev line in both left and right panes at the same time
- b/n: next/prev line in bottom pane
- Use PgUp/PgDown to change the vertical position of the split
- While diffing 2 traces in pdml mode, you can use 'a' to ignore the
  field under the cursor. Press a again to stop ignoring it.


Configuration
=============

All keybindings are configurable through the ~/.smbcmp config file
which uses an INI style format.

Sample config file with the default values.


    [global]
    # default ratio for pane split
    vsplit_ratio = .5

    # alternative path to use for the tshark binary
    tshark_path = /home/aaptel/prog/wireshark-git/test.sh

    # key bindings
    # (use ncurses names for key values)
    key_lwin_next = d
    key_lwin_prev = f
    key_rwin_next = j
    key_rwin_prev = k
    key_top_next = KEY_DOWN
    key_top_prev = KEY_UP
    key_bwin_next = b
    key_bwin_prev = n
    key_vsplit_up = KEY_PPAGE
    key_vsplit_down = KEY_NPAGE
    key_toggle_ignore = a
