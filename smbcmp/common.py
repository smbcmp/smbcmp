#!/usr/bin/env python3
# Compare SMB packets from 2 network capture files
#
# Copyright (C) 2017 Aurelien Aptel <aurelien.aptel@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import binascii
import configparser
import subprocess
import re
import functools
import os
from subprocess import SubprocessError
import difflib
try:
    import lxml.etree.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from itertools import zip_longest

TSHARK_FILTER_FLAG = None
DEFAULT_CONFIG = os.path.expanduser("~/.smbcmp")
DEFAULT_MODE = 'text'
KEY = {}
CONF = configparser.ConfigParser()
CONF.add_section('global')
CRYPTO_KEY = {}


def load_config(fn):
    if fn and os.path.exists(fn):
        CONF.read(fn)

    def k(name, default):
        KEY[name] = CONF['global'].get('key_'+name, default)
    k('lwin_next', 'd')
    k('lwin_prev', 'f')
    k('rwin_next', 'j')
    k('rwin_prev', 'k')
    k('top_next', 'KEY_DOWN')
    k('top_prev', 'KEY_UP')
    k('bwin_next', 'b')
    k('bwin_prev', 'n')
    k('vsplit_up', 'KEY_PPAGE')
    k('vsplit_down', 'KEY_NPAGE')
    k('toggle_ignore', 'a')


def wireshark_checks(args):
    try:
        out = subprocess.check_output(tshark('-h')).decode('utf-8')
    except SubprocessError:
        print("Can't run tshark, check if installed properly")
        raise

    if 'wireshark' not in out:
        raise Exception("Unexpected tshark out, check if installed properly")

    global TSHARK_FILTER_FLAG
    if '-Y' in out:
        TSHARK_FILTER_FLAG = '-Y'
    else:
        TSHARK_FILTER_FLAG = '-R'

    if args.key:
        try:
            out = subprocess.check_output(tshark(
                '-ouat:smb2_seskey_list:ffffffffffffffff' +
                ',ffffffffffffffffffffffffffffffff',
                '-v')).decode('utf-8')
        except SubprocessError:
            print("your version of tshark doesn't support decryption")
            raise


def strip_packet_no(arg):
    try:
        i = arg.rindex(":")
        return arg[:i]
    except Exception:
        return arg


def split_packet_arg(arg):
    try:
        m = re.match(r'^(.+?)(?::(\d+))?$', arg)
        fn = m.group(1)
        no = None
        if m.group(2):
            no = int(m.group(2))
        return (fn, no)
    except Exception:
        raise Exception("invalid packet:no specified")

def extract_kernel_keys(log):
    r = {}
    byte = r'(?: [A-Fa-f0-9]{2})'
    kernel_rx = re.compile(r'(?:Session Id\s+(' +byte+ r'+))|(?:Session Key\s+(' +byte+ r'+))')
    samba_rx = re.compile(r'(?:Session Id\s+\[0000\]('+byte+r'{8}))'
                          +'|(?:Session Key\s+\[0000\]('+byte+r'{8}  '+byte+r'{8}))')

    for rx in (kernel_rx, samba_rx):
        last_id = None
        last_key = None

        for m in rx.finditer(log):
            if m.group(1):
                last_id = hex_to_bytes(m.group(1))
            elif m.group(2):
                last_key = hex_to_bytes(m.group(2))
                r[last_id] = last_key
                last_key = last_id = None
    return r


def load_crypto_keys(args):
    # try dmesg
    try:
        dmesg = subprocess.check_output(["dmesg"]).decode("utf-8")
        CRYPTO_KEY.update(extract_kernel_keys(dmesg))
    except:
        pass

    for kp in args.key:
        m = re.match(r'''^([a-f0-9]+),([a-f0-9]+)$''', kp)
        if m:
            sid = hex_to_bytes(m.group(1))
            skey = hex_to_bytes(m.group(2))
            CRYPTO_KEY[sid] = skey
        elif os.path.exists(kp):
            CRYPTO_KEY.update(extract_kernel_keys(open(kp).read()))
        else:
            raise Exception("<%s> is neither a file nor a hex SID,KEY string"
                            % kp)


def tshark(*args):
    binpath = CONF['global'].get('tshark_path', 'tshark')
    return [binpath] + list(args)


def bytes_to_hex(b):
    return binascii.hexlify(b).decode('ascii')


def hex_to_bytes(h):
    return binascii.unhexlify(h.replace(' ', ''))


def tshark_keys_opts():
    r = []
    for (sid, skey) in CRYPTO_KEY.items():
        opt = "-ouat:smb2_seskey_list:%s,%s" % (bytes_to_hex(sid),
                                                bytes_to_hex(skey))
        r.append(opt)
    return r


def wrap(prefix, s):
    """Prefix every line in s with prefix"""
    return ''.join([prefix+x+"\n" for x in s.splitlines()])


def is_multiline(s):
    return s.count('\n') > 0


def multiline_mod(a, b, ignored=False):
    """Helper to generate a colorized diff of multi-line values"""
    out = []
    max_len = max([len(x) for x in a.splitlines()])

    # pick colors
    add = STYLE[OUT_ADD][1]
    rem = STYLE[OUT_REM][1]
    if ignored:
        add = rem = COL_IGNORED

    i = 0
    for aa, bb in zip_longest(a.splitlines(), b.splitlines(), fillvalue=''):
        aa = aa.ljust(max_len + 2)
        mid = "   "
        if i == 0:
            mid = " → "
        out.append(rem+aa+COL_END+mid+add+bb+COL_END+"\n")
        i += 1
    return ''.join(out)


def smb_diff(a, b, gui=False):
    lines = difflib.unified_diff(smb_packet(a[0], a[1]).split("\n"),
                                 smb_packet(b[0], b[1]).split("\n"),
                                 "%s #%d"%(a[0], a[1]),
                                 "%s #%d"%(b[0], b[1]),
                                 lineterm="")
    if gui:
        return list(lines)
    return "\n".join(lines)


@functools.lru_cache(maxsize=128)
def smb_summaries(pcap):
    cmd = tshark(*tshark_keys_opts())
    cmd += ['-r', pcap, TSHARK_FILTER_FLAG, '!browser && (smb||smb2)']
    out = subprocess.check_output(cmd).decode('utf-8')
    pkts = {}
    for line in out.split('\n'):
        m = re.match(r'''\s*(\d+).+?SMB2?\s*\d+\s*(.+)''', line)
        if m:
            pkts[int(m.group(1))] = m.group(2)
    return pkts


@functools.lru_cache(maxsize=128)
def smb_packet(pcap, no, pdml=False):
    """Show the content of a packet

    Keyword arguments
    pcap -- name of the capture file
    no -- number of the packet
    """
    cmd = tshark(*tshark_keys_opts())
    cmd += ['-r', pcap, TSHARK_FILTER_FLAG, 'frame.number == %d' % no, '-V']
    if pdml:
        cmd += ['-Tpdml']
        return subprocess.check_output(cmd).decode('utf-8')
    else:
        out = subprocess.check_output(cmd).decode('utf-8')
        out = re.sub(r'^[\s\S]+?\nSMB', 'SMB', out, re.S)
        return out


class Node:
    def __init__(self, name, val, *children):
        self.name = name
        self.val = val
        self.children = children
        self._cached_hash = None

    def display_name_val(self):
        """Return a tuple (name, val) used for showing humans"""
        if '....' in self.val:
            # bitfields are left alone
            return ('', self.val)
        if ':' in self.val:
            return self.val.split(":", 1)

        return ('', self.val)

    def __str__(self):
        return "<%s: %s ...>" % (self.name, self.val)

    def __repr__(self):
        return "<%s: %s ...>" % (self.name, self.val)

    def __hash__(self):
        if not self._cached_hash:
            if self.children:
                ch = tuple(x.__hash__() for x in self.children)
            else:
                ch = hash(None)
            # don't hash the value, check for val mods in 'equal'
            self._cached_hash = hash((self.name, ch))
        return self._cached_hash

    def __eq__(self, o):
        if self.name != o.name or self.val != o.val:
            return False
        if not self.children and not o.children:
            return True
        if self.children and o.children:
            if len(self.children) != len(o.children):
                return False
            for a, b in zip_longest(self.children, o.children):
                if not a.__eq__(b):
                    return False
            return True
        return False


class DiffOutputItem:
    def __init__(self, name, text, node_a=None, node_b=None):
        self.name = name
        self.text = text
        self.node_a = node_a
        self.node_b = node_b
        self.nb_lines = text.count('\n')

# output types
OUT_SAME = 0  # normal node
OUT_ADD = 1  # added node
OUT_REM = 2  # removed node
OUT_MOD = 3  # node modified

# equality types
SAME = 0  # node are identical
MOD = 1  # nodes are same type but value differs
DIFF = 2  # nodes are completely different

# prefix and colors
STYLE = {
    OUT_SAME: (' ', '',        ''),
    OUT_ADD: ('+', '\x1b[32m', '\x1b[0m'),  # green
    OUT_REM: ('-', '\x1b[31m', '\x1b[0m'),  # red
}
COL_END = "\x1b[0m"  # reset
COL_IGNORED = "\x1b[30;1m"  # bold

class DiffOutput:
    def __init__(self):
        self.items = []

    def get_item_at_line(self, line):
        prev = 0

        if len(self.items) == 0:
            return None

        for it in self.items:
            if prev <= line < prev + it.nb_lines:
                return it
            prev += it.nb_lines

        return self.items[-1]

    def get_text(self, sep=''):
        return sep.join([x.text for x in self.items])

    def dump(self, mode, node, ignored=False, indent=0):
        """Recursively dump a node.
        mode must be one of the OUT_??? type."""
        if not node.children:
            self.print_field(mode, node, ignored, indent)
        else:
            self.print_field(mode, node, ignored, indent)
            for child in node.children:
                self.dump(mode, child, ignored, indent+1)

    def print_mod_field(self, a, b, ignored=False, indent=0):
        """Print a diff of 2 same-type nodes"""

        # pick colors
        add = STYLE[OUT_ADD][1]
        rem = STYLE[OUT_REM][1]
        if ignored:
            add = rem = COL_IGNORED

        a_name, a_val = a.display_name_val()
        b_name, b_val = b.display_name_val()

        if is_multiline(a_val) or is_multiline(b_val):
            diff = wrap(' '*(len(a_name)+2), multiline_mod(a_val, b_val,
                                                           ignored))
            text = '{name}:\n{diff}\n'.format(name=a_name, diff=diff)
        else:
            fmt = '{name}: {rem}{a}{end} → {add}{b}{end}\n'
            text = fmt.format(name=a_name, a=a_val, b=b_val,
                              rem=rem,
                              add=add,
                              end=COL_END)
        self.items.append(DiffOutputItem(a.name, wrap(' '*(4*indent+1), text), a, b))

    def print_field(self, mode, node, ignored=False, indent=0):
        """Print a node"""

        name, val = node.display_name_val()

        # wrap and indent multiline values
        if is_multiline(val):
            val_indent = ' '*(len(name)+4)
            text = '%s:\n%s\n' % (name, wrap(val_indent, val))
        else:
            text = '%s: %s\n' % (name, val)

        # pick colors
        prefix, beg, end = STYLE[mode]
        if ignored:
            beg = COL_IGNORED

        prefix = ('    '*indent)+prefix
        text = wrap(prefix, text)

        self.items.append(DiffOutputItem(node.name, (beg + text + end), node))


class PDMLDiff:
    """Compute diffs between two captures using PDML output

    Keyword arguments:
    pkt_a -- a tuple ('foo_a.cap', frame_nb)
    pkt_b -- a tuple ('foo_b.cap', frame_nb)
    ignored_fields -- a set() of wireshark field names (e.g. "smb2.session_id")
    """
    def __init__(self, pkt_a, pkt_b, ignored_fields=None):
        if ignored_fields is None:
            ignored_fields = set()
        self.ignored_fields = ignored_fields
        self.set_packets(pkt_a, pkt_b)

    def set_packets(self, pkt_a, pkt_b):
        self.pkt_a = self.pdml_to_node(smb_packet(pkt_a[0], pkt_a[1], pdml=True))
        self.pkt_b = self.pdml_to_node(smb_packet(pkt_b[0], pkt_b[1], pdml=True))

    def ignore_field(self, field):
        self.ignored_fields.add(field)

    def toggle_ignore_field(self, field):
        if field in self.ignored_fields:
            self.ignored_fields.remove(field)
        else:
            self.ignored_fields.add(field)

    def pdml_to_node(self, xml):

        def _pdml_to_node(field):
            children = list(field)

            name = field.get('name')
            show = field.get('show')
            showname = field.get('showname')

            if not showname and show:
                showname = show

            if not children:
                return Node(name, showname)
            else:
                return Node(name, showname,
                            *tuple(_pdml_to_node(c) for c in children))

        xml = ET.fromstring(xml)
        smb2 = xml.findall("./packet/proto[@name='smb2']")
        return Node('Root', 'Root',
                    *tuple(_pdml_to_node(x) for x in smb2))

    def ignored_with_rules(self, node):
        """Return True if the presence/absence of node can be ignored"""
        # use node name and content to decide whether it should be
        # considered different if completely added or removed
        # note that node can be flat or tree
        if node.name in self.ignored_fields:
            return True
        return False

    def diff_field_with_rules(self, a, b):
        """Return a tuple (eq_type, ignored) between 2 leaf nodes"""
        # use field names and values to decide equality type
        # a and b are always flat
        if a.name == b.name:
            if a.val == b.val:
                eq = SAME
            else:
                eq = MOD
        else:
            eq = DIFF
        ign = False
        if eq == MOD and a.name in self.ignored_fields:
            ign = True
        return (eq, ign)

    def diff_attr_with_rules(self, a, b):
        """Return a tuple (eq_type, ignored) between 2 folder nodes"""
        # use field names and values to decide equality type
        if a.name == b.name:
            if a.val == b.val:
                eq = SAME
            else:
                eq = MOD
        else:
            eq = DIFF
        ign = False
        if eq == MOD and a.name in self.ignored_fields:
            ign = True
        return (eq, ign)

    def smb_diff(self):
        """Compute PDML diff and return DiffOutput instance"""
        output = DiffOutput()

        def rec_diff(a, b, n=0):
            final_eq = SAME

            #
            # Diff a folder attributes
            #

            eq, ign = self.diff_attr_with_rules(a, b)
            if eq == SAME:
                # doesnt matter which
                output.print_field(OUT_SAME, a, indent=n)
            elif eq == MOD:
                output.print_mod_field(a, b, indent=n)
                if not ign:
                    final_eq = max(final_eq, eq)
            elif eq == DIFF:
                output.dump(OUT_REM, a, ignored=ign, indent=n)
                output.dump(OUT_ADD, b, ignored=ign, indent=n)
                if not ign:
                    final_eq = max(final_eq, eq)
                return final_eq

            #
            # Diff the children of the folder
            #

            sm = difflib.SequenceMatcher(None, a.children, b.children)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == 'delete':
                    for child_a in a.children[i1:i2]:
                        ign = self.ignored_with_rules(child_a)
                        output.dump(OUT_REM, child_a, ignored=ign, indent=n+1)
                        if not ign:
                            final_eq = max(final_eq, eq)
                    continue
                elif tag == 'insert':
                    for child_b in b.children[j1:j2]:
                        ign = self.ignored_with_rules(child_b)
                        output.dump(OUT_ADD, child_b, ignored=ign, indent=n+1)
                        if not ign:
                            final_eq = max(final_eq, eq)
                    continue
                elif tag == 'equal':
                    for child_a, child_b in zip_longest(a.children[i1:i2],
                                                        b.children[j1:j2]):
                        eq, ign = self.diff_field_with_rules(child_a, child_b)
                        if eq == SAME:
                            # doesnt matter which
                            output.dump(OUT_SAME, child_a, indent=n+1)
                        elif eq == MOD:
                            output.print_mod_field(child_a, child_b,
                                                   ignored=ign, indent=n+1)
                            if not ign:
                                final_eq = max(final_eq, eq)
                        else:
                            raise Exception("nodes should not be diff here")
                    continue
                elif tag == 'replace':
                    for child_a, child_b in zip_longest(a.children[i1:i2],
                                                        b.children[j1:j2]):

                        #
                        # Cases where A and B have different numbers
                        # of children

                        if child_a is None:
                            # B has more children
                            ign = self.ignored_with_rules(child_b)
                            output.dump(OUT_ADD, child_b, ignored=ign, indent=n+1)
                            if not ign:
                                final_eq = max(final_eq, eq)
                            continue

                        if child_b is None:
                            # A has more children
                            ign = self.ignored_with_rules(child_a)
                            output.dump(OUT_REM, child_a, ignored=ign, indent=n+1)
                            if not ign:
                                final_eq = max(final_eq, eq)
                            continue

                        #
                        # Terminal cases: 2 leaf nodes
                        #

                        if not child_a.children and not child_b.children:
                            eq, ign = self.diff_field_with_rules(child_a,
                                                                 child_b)
                            if eq == SAME:
                                # doesnt matter which
                                output.dump(OUT_SAME, child_a, indent=n+1)
                            elif eq == MOD:
                                output.print_mod_field(child_a, child_b,
                                                       ignored=ign, indent=n+1)
                                if not ign:
                                    final_eq = max(final_eq, eq)
                            else:
                                output.dump(OUT_REM, child_a, ignored=ign,
                                            indent=n+1)
                                output.dump(OUT_ADD, child_b, ignored=ign,
                                            indent=n+1)
                                if not ign:
                                    final_eq = max(final_eq, eq)
                            continue


                        #
                        # 1 Leaf node vs 1 Folder node
                        #

                        if not child_a.children or not child_b.children:
                            # doesn't make sense to diff deeper,
                            # consider one has been removed
                            # and the other added

                            ign = self.ignored_with_rules(child_a) and \
                                self.ignored_with_rules(child_b)
                            output.dump(OUT_REM, child_a, ignored=ign,
                                        indent=n+1)
                            output.dump(OUT_ADD, child_b, ignored=ign,
                                        indent=n+1)
                            if not ign:
                                final_eq = max(final_eq, DIFF)
                            continue

                        #
                        # Recursive case: 2 Tree nodes
                        #

                        eq = rec_diff(child_a, child_b, n=n+1)
                        final_eq = max(final_eq, eq)

            return final_eq

        rec_diff(self.pkt_a, self.pkt_b)
        return output


def parse_args(gui=False):
    ap = argparse.ArgumentParser(description='compare smb packets')
    ap.add_argument('-m', '--mode',
                    help='diff method (default %s)'%DEFAULT_MODE, default=DEFAULT_MODE, choices=['text', 'pdml'])
    ap.add_argument('-c', '--config',
                    help='read alternative config file (default %s)'%DEFAULT_CONFIG)
    ap.add_argument('-k', '--key', metavar='KEYPAIR',
                    default=[], action='append',
                    help='''KEYPAIR can be either a path to a log file containing the keys (for
                    the kernel client, enable CONFIG_CIFS_DEBUG_KEYS,
                    for samba --option=debugencryption=yes) or literal
                    session id & key pair given in hex (as
                    SESSID,KEY). This option can be used multiple
                    times to pass multiple keys.''')

    if gui:
        # GUI can take 0 or 2 files, no single view
        ap.add_argument('filea', nargs='?', metavar='CAPFILE1:NO', help='first file/packet number')
        ap.add_argument('fileb', nargs='?', metavar='CAPFILE2:NO', help='second file/packet number')
    else:
        ap.add_argument('filea', metavar='CAPFILE1:NO', help='first file/packet number')
        ap.add_argument('fileb', nargs='?', metavar='CAPFILE2:NO', help='second file/packet number (diff mode)')

    args = ap.parse_args()

    if args.config:
        load_config(args.config)
    elif os.path.exists(DEFAULT_CONFIG):
        load_config(DEFAULT_CONFIG)
    else:
        load_config(None)

    wireshark_checks(args)
    load_crypto_keys(args)

    return args

