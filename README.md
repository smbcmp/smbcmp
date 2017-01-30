smbcmp
======

Small curses utility to diff, compare and debug SMB network traces.

Install
=======

Dependencies:
- python3
- tshark (wireshark)
- python3-curses

Usage
=====

    $ smbcmp a.pcap b.pcap

- Use d/f and j/k to move to the prev/next line in respectively the
  left and right side.
- Use up/down arrows to move in both sides at the same time
- Use b/v to move inside the diff buffer at the bottom

![smbcmp demo](https://framapic.org/h65lq3Goa4MR/RPpeIdHAZybS.gif)
