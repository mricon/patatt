# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 by The Linux Foundation
# SPDX-License-Identifier: MIT-0
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import sys
import os
import re

import hashlib
import base64
import subprocess
import logging
import tempfile
import time
import datetime

import urllib.parse
import email.utils
import email.header

from pathlib import Path
from typing import Optional, Tuple
from io import BytesIO

logger = logging.getLogger(__name__)

# Overridable via [patatt] parameters
GPGBIN = 'gpg'

# Hardcoded defaults
DEVSIG_HDR = b'X-Developer-Signature'
REQ_HDRS = [b'from', b'subject']
DEFAULT_CONFIG = {
    'publickeypath': ['ref::.keys', 'ref::.local-keys'],
    'gpgusedefaultkeyring': 'yes',
}

# My version
__VERSION__ = '0.1.0'


class SigningError(Exception):
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message)
        self.errors = errors


class ValidationError(Exception):
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message)
        self.errors = errors


class ConfigurationError(Exception):
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message)
        self.errors = errors


def get_data_dir():
    if 'XDG_DATA_HOME' in os.environ:
        datahome = os.environ['XDG_DATA_HOME']
    else:
        datahome = os.path.join(str(Path.home()), '.local', 'share')
    datadir = os.path.join(datahome, 'patatt')
    Path(datadir).mkdir(parents=True, exist_ok=True)
    return datadir


def _run_command(cmdargs: list, stdin: bytes = None, env: Optional[dict] = None) -> Tuple[int, bytes, bytes]:
    sp = subprocess.Popen(cmdargs, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    logger.debug('Running %s', ' '.join(cmdargs))
    (output, error) = sp.communicate(input=stdin)
    return sp.returncode, output, error


def git_run_command(gitdir: Optional[str], args: list, stdin: Optional[bytes] = None,
                    env: Optional[dict] = None) -> Tuple[int, bytes, bytes]:
    if gitdir:
        env = {'GIT_DIR': gitdir}

    args = ['git', '--no-pager'] + args
    return _run_command(args, stdin=stdin, env=env)


def get_config_from_git(regexp: str, section: Optional[str] = None, defaults: Optional[dict] = None):
    args = ['config', '-z', '--get-regexp', regexp]
    ecode, out, err = git_run_command(None, args)
    if defaults is None:
        defaults = dict()

    if not len(out):
        return defaults

    gitconfig = defaults
    out = out.decode()

    for line in out.split('\x00'):
        if not line:
            continue
        key, value = line.split('\n', 1)
        try:
            chunks = key.split('.')
            # Drop the starting part
            chunks.pop(0)
            cfgkey = chunks.pop(-1).lower()
            if len(chunks):
                if not section:
                    # Ignore it
                    continue
                # We're in a subsection
                sname = '.'.join(chunks)
                if sname != section:
                    # Not our section
                    continue
            elif section:
                # We want config from a subsection specifically
                continue

            if cfgkey in gitconfig:
                # Multiple entries become lists
                if isinstance(gitconfig[cfgkey], str):
                    gitconfig[cfgkey] = [gitconfig[cfgkey]]
                if value not in gitconfig[cfgkey]:
                    gitconfig[cfgkey].append(value)
            else:
                gitconfig[cfgkey] = value
        except ValueError:
            logger.debug('Ignoring git config entry %s', line)

    return gitconfig


def gpg_run_command(cmdargs: list, stdin: bytes = None) -> Tuple[int, bytes, bytes]:
    cmdargs = [GPGBIN, '--batch', '--no-auto-key-retrieve', '--no-auto-check-trustdb'] + cmdargs
    return _run_command(cmdargs, stdin)


def check_gpg_status(status: bytes) -> Tuple[bool, bool, bool, str]:
    good = False
    valid = False
    trusted = False
    signtime = ''

    gs_matches = re.search(rb'^\[GNUPG:] GOODSIG ([0-9A-F]+)\s+(.*)$', status, flags=re.M)
    if gs_matches:
        good = True
    vs_matches = re.search(rb'^\[GNUPG:] VALIDSIG ([0-9A-F]+) (\d{4}-\d{2}-\d{2}) (\d+)', status, flags=re.M)
    if vs_matches:
        valid = True
        signtime = vs_matches.groups()[2].decode()
    ts_matches = re.search(rb'^\[GNUPG:] TRUST_(FULLY|ULTIMATE)', status, flags=re.M)
    if ts_matches:
        trusted = True

    return good, valid, trusted, signtime


def get_git_mailinfo(payload: bytes) -> Tuple[bytes, bytes, bytes]:
    with tempfile.TemporaryDirectory(suffix='.git-mailinfo') as td:
        mf = os.path.join(td, 'm')
        pf = os.path.join(td, 'p')
        cmdargs = ['git', 'mailinfo', '--encoding=utf-8', mf, pf]
        ecode, out, err = _run_command(cmdargs, stdin=payload)
        if ecode > 0:
            logger.debug('FAILED  : Failed running git-mailinfo:')
            logger.debug(err.decode())
            raise RuntimeError('Failed to run git-mailinfo: %s' % err.decode())

        with open(mf, 'rb') as mfh:
            m = mfh.read()
        with open(pf, 'rb') as pfh:
            p = pfh.read()
        return m, p, out


def is_signed(headers: list):
    for header in headers:
        try:
            left, right = header.split(b':', 1)
            if left.strip().lower() == DEVSIG_HDR.lower():
                return True
        except ValueError:
            continue

    return False


def parse_message(msgdata: bytes) -> Tuple[list, bytes]:
    # We use simplest parsing -- using Python's email module would be overkill
    headers = list()
    with BytesIO(msgdata) as fh:
        while True:
            line = fh.readline()
            if not len(line):
                break

            if not len(line.strip()):
                # Keep extra LF in headers so we don't have to track LF/CRLF endings
                headers.append(line)
                payload = fh.read()
                break

            # is it a wrapped header?
            if line[0] in ("\x09", "\x20", 0x09, 0x20):
                if not len(headers):
                    raise RuntimeError('Not a valid RFC2822 message')
                # attach it to the previous header
                headers[-1] += line
                continue
            headers.append(line)

    return headers, payload


def get_mailinfo_message(oheaders: list, opayload: bytes, want_hdrs: list,
                         maxlen: Optional[int]) -> Tuple[list, bytes, str]:
    # We pre-canonicalize using git mailinfo
    # use whatever lf is used in the headers
    origmsg = b''.join(oheaders) + opayload
    m, p, i = get_git_mailinfo(origmsg)
    # Generate a new payload using m and p and canonicalize with \r\n endings,
    # trimming any excess blank lines ("simple" DKIM canonicalization).
    cpayload = b''
    for line in re.sub(rb'[\r\n]*$', b'', m + p).split(b'\n'):
        cpayload += re.sub(rb'[\r\n]*$', b'', line) + b'\r\n'

    if maxlen:
        logger.debug('Limiting payload length to %d bytes', maxlen)
        cpayload = cpayload[:maxlen]

    idata = dict()
    for line in re.sub(rb'[\r\n]*$', b'', i).split(b'\n'):
        left, right = line.split(b':', 1)
        idata[left.lower()] = right.strip()

    # Theoretically, we should always see an "Email" line
    identity = idata.get(b'email', b'').decode()

    # Now substituting headers returned by mailinfo
    cheaders = list()
    for oheader in oheaders:
        try:
            left, right = oheader.split(b':', 1)
            lleft = left.lower()
            if lleft not in want_hdrs:
                continue
            if lleft == b'from':
                right = b' ' + idata.get(b'author', b'') + b' <' + idata.get(b'email', b'') + b'>'
            elif lleft == b'subject':
                right = b' ' + idata.get(b'subject', b'')
            cheaders.append(left + b':' + right)
        except ValueError:
            cheaders.append(oheader)

    return cheaders, cpayload, identity


def splitter(longstr: bytes, limit: int = 78) -> bytes:
    splitstr = list()
    first = True
    while len(longstr) > limit:
        at = limit
        if first:
            first = False
            at -= 2
        splitstr.append(longstr[:at])
        longstr = longstr[at:]
    splitstr.append(longstr)
    return b' '.join(splitstr)


def get_git_toplevel(gitdir: str = None) -> str:
    cmdargs = ['git']
    if gitdir:
        cmdargs += ['--git-dir', gitdir]
    cmdargs += ['rev-parse', '--show-toplevel']
    ecode, out, err = _run_command(cmdargs)
    if ecode == 0:
        return out.decode().strip()
    return ''


def get_parts_from_header(hval: bytes) -> dict:
    hval = re.sub(rb'\s*', b'', hval)
    hdata = dict()
    for chunk in hval.split(b';'):
        parts = chunk.split(b'=', 1)
        if len(parts) < 2:
            continue
        hdata[parts[0].decode()] = parts[1]
    return hdata


def dkim_canonicalize_header(hval: bytes) -> bytes:
    # We only do relaxed for headers
    #    o  Unfold all header field continuation lines as described in
    #       [RFC5322]; in particular, lines with terminators embedded in
    #       continued header field values (that is, CRLF sequences followed by
    #       WSP) MUST be interpreted without the CRLF.  Implementations MUST
    #       NOT remove the CRLF at the end of the header field value.
    hval = re.sub(rb'[\r\n]', b'', hval)
    #    o  Convert all sequences of one or more WSP characters to a single SP
    #       character.  WSP characters here include those before and after a
    #       line folding boundary.
    hval = re.sub(rb'\s+', b' ', hval)
    #    o  Delete all WSP characters at the end of each unfolded header field
    #       value.
    #    o  Delete any WSP characters remaining before and after the colon
    #       separating the header field name from the header field value.  The
    #       colon separator MUST be retained.
    hval = hval.strip() + b'\r\n'
    return hval


def make_pkey_path(keytype: str, identity: str, selector: str) -> str:
    chunks = identity.split('@', 1)
    if len(chunks) != 2:
        raise ValidationError('identity must include both local and domain parts')
    local = chunks[0].lower()
    domain = chunks[1].lower()
    selector = selector.lower()
    # urlencode all potentially untrusted bits to make sure nobody tries path-based badness
    keypath = os.path.join(urllib.parse.quote_plus(keytype), urllib.parse.quote_plus(domain),
                           urllib.parse.quote_plus(local), urllib.parse.quote_plus(selector))

    return keypath


def get_public_key(source: str, keytype: str, identity: str, selector: str) -> Tuple[bytes, str]:
    keypath = make_pkey_path(keytype, identity, selector)

    if source.find('ref:') == 0:
        gittop = get_git_toplevel()
        if not gittop:
            raise RuntimeError('Not in a git tree, so cannot use a ref: source')
        # format is: ref:refspec:path
        # or it could omit the refspec, meaning "whatever the current ref"
        # but it should always have at least two ":"
        chunks = source.split(':', 2)
        if len(chunks) < 3:
            logger.debug('ref: sources must have refspec and path, e.g.: ref:refs/heads/master:.keys')
            raise ConfigurationError('Invalid ref: source: %s' % source)
        # grab the key from a fully ref'ed path
        ref = chunks[1]
        pathtop = chunks[2]
        subpath = os.path.join(pathtop, keypath)

        if not ref:
            # What is our current ref?
            cmdargs = ['git', 'symbolic-ref', 'HEAD']
            ecode, out, err = _run_command(cmdargs)
            if ecode == 0:
                ref = out.decode().strip()

        cmdargs = ['git']
        keysrc = f'{ref}:{subpath}'
        cmdargs += ['show', keysrc]
        ecode, out, err = _run_command(cmdargs)
        if ecode == 0:
            logger.debug('KEYSRC  : %s', keysrc)
            return out, keysrc

        # Does it exist on disk in gittop?
        fullpath = os.path.join(gittop, subpath)
        if os.path.exists(fullpath):
            with open(fullpath, 'rb') as fh:
                logger.debug('KEYSRC  : %s', fullpath)
                return fh.read(), fullpath

        raise KeyError('Could not find %s in %s' % (subpath, ref))

    # It's a direct path, then
    fullpath = os.path.join(source, keypath)
    if os.path.exists(fullpath):
        with open(fullpath, 'rb') as fh:
            logger.debug('Loaded key from %s', fullpath)
            return fh.read(), fullpath

    raise KeyError('Could not find %s' % fullpath)


def make_devsig_header(headers: list, payload: bytes, algo: str, signtime: Optional[str] = None,
                       identity: Optional[str] = None, selector: Optional[str] = None, maxlen: Optional[int] = None,
                       want_hdrs: Optional[list] = None, strict: bool = False) -> Tuple[bytes, bytes]:
    if not want_hdrs:
        want_hdrs = REQ_HDRS
    cheaders, cpayload, cidentity = get_mailinfo_message(headers, payload, want_hdrs, maxlen)
    hashed = hashlib.sha256()
    hashed.update(cpayload)
    bh = base64.b64encode(hashed.digest())

    hparts = [
        b'v=1',
        b'a=%s-sha256' % algo.encode(),
        ]
    if (identity and strict) or (not strict and identity != cidentity):
        hparts.append(b'i=%s' % identity.encode())

    if selector:
        hparts.append(b's=%s' % selector.encode())
    if signtime:
        hparts.append(b't=%s' % signtime.encode())

    hparts.append(b'h=%s' % b':'.join(want_hdrs))
    hparts.append(b'l=%d' % len(cpayload))
    hparts.append(b'bh=%s' % bh)
    hparts.append(b'b=')
    dshval = b'; '.join(hparts)

    hashed = hashlib.sha256()
    for cheader in cheaders:
        try:
            left, right = cheader.split(b':', 1)
            hname = left.strip().lower()
            if hname not in want_hdrs:
                continue
        except ValueError:
            continue

        hashed.update(hname + b':' + dkim_canonicalize_header(right))
    hashed.update(DEVSIG_HDR.lower() + b':' + dshval)
    dshdr = DEVSIG_HDR + b': ' + dshval

    return dshdr, hashed.digest()


def get_devsig_header_info(headers) -> Tuple[Optional[str], str, str, str, list, dict]:
    from_hdr = None
    hdata = None
    need_hdrs = [b'from', DEVSIG_HDR.lower()]
    for header in headers:
        try:
            left, right = header.split(b':', 1)
            hname = left.strip().lower()
            # We want a "from" header and a DEVSIG_HDR
            if hname not in need_hdrs:
                continue
            if hname == b'from':
                from_hdr = right
                continue
            hval = dkim_canonicalize_header(right)
            hdata = get_parts_from_header(hval)
        except ValueError:
            continue

    if hdata is None:
        raise ValidationError('No "%s:" header in message' % DEVSIG_HDR.decode())

    # make sure the required headers are in the sig
    if 'h' not in hdata:
        raise ValidationError('h= is required but is not present in %s' % DEVSIG_HDR.decode())

    signed_hdrs = [x.strip() for x in hdata['h'].split(b':')]
    for rhdr in REQ_HDRS:
        if rhdr not in signed_hdrs:
            raise ValidationError('%s is a required header' % rhdr.decode())

    if 'i' not in hdata:
        # Use the identity from the from header
        if not from_hdr:
            raise ValidationError('No i= in %s, and no From: header!' % DEVSIG_HDR.decode())
        parts = email.utils.parseaddr(from_hdr.decode())
        identity = parts[1]
    else:
        identity = hdata['i'].decode()

    if 'a' in hdata:
        apart = hdata['a'].decode()
        if apart.startswith('ed25519'):
            algo = 'ed25519'
        elif apart.startswith('openpgp'):
            algo = 'openpgp'
        else:
            raise ValidationError('Unsupported a= in %s: %s' % (DEVSIG_HDR.decode(), apart))
    else:
        # Default is ed25519-sha256
        algo = 'ed25519'

    if 's' in hdata:
        selector = hdata['s'].decode()
    else:
        selector = 'default'

    if 't' in hdata:
        signtime = hdata['t'].decode()
    else:
        signtime = None

    return signtime, identity, selector, algo, signed_hdrs, hdata


def sign_ed25519(headers: list, payload: bytes, keydata: str,
                 identity: Optional[str] = None, selector: Optional[str] = None) -> email.header.Header:
    from nacl.signing import SigningKey
    from nacl.encoding import Base64Encoder

    logger.debug('SIGNING : ED25519')
    signtime = str(int(time.time()))
    dshdr, digest = make_devsig_header(headers, payload, algo='ed25519', signtime=signtime,
                                       identity=identity, selector=selector)
    sk = SigningKey(keydata, encoder=Base64Encoder)
    bdata = sk.sign(digest, encoder=Base64Encoder)
    hhdr = email.header.make_header([(dshdr + splitter(bdata), 'us-ascii')], maxlinelen=78)
    return hhdr


def validate_ed25519(sigdata: bytes, pubkey: bytes) -> bytes:
    from nacl.signing import VerifyKey
    from nacl.encoding import Base64Encoder
    from nacl.exceptions import BadSignatureError

    vk = VerifyKey(pubkey, encoder=Base64Encoder)
    try:
        return vk.verify(sigdata, encoder=Base64Encoder)
    except BadSignatureError:
        raise ValidationError('Failed to validate signature')


def sign_openpgp(headers: list, payload: bytes, keyid: Optional[str],
                 identity: Optional[str] = None, selector: Optional[str] = None) -> email.header.Header:
    logger.debug('SIGNING : OpenPGP')
    # OpenPGP header includes signing time, so we don't need to include t=
    dshdr, digest = make_devsig_header(headers, payload, algo='openpgp', identity=identity, selector=selector)
    gpgargs = ['-s']
    if keyid:
        gpgargs += ['-u', keyid]
    ecode, out, err = gpg_run_command(gpgargs, digest)
    if ecode > 0:
        raise SigningError('Running gpg failed', errors=err.decode().split('\n'))

    bdata = base64.b64encode(out)
    hhdr = email.header.make_header([(dshdr + splitter(bdata), 'us-ascii')], maxlinelen=78)
    return hhdr


def validate_openpgp(sigdata: bytes, pubkey: Optional[bytes]) -> Tuple[bytes, tuple]:
    bsigdata = base64.b64decode(sigdata)
    vrfyargs = ['--verify', '--output', '-', '--status-fd=2']
    if pubkey:
        with tempfile.TemporaryFile(suffix='.patch-attest-poc') as temp_keyring:
            keyringargs = ['--no-default-keyring', f'--keyring={temp_keyring}']
            gpgargs = keyringargs + ['--status-fd=1', '--import']
            ecode, out, err = gpg_run_command(gpgargs, stdin=pubkey)
            # look for IMPORT_OK
            if out.find(b'[GNUPG:] IMPORT_OK') < 0:
                raise ValidationError('Could not import GnuPG public key')
            gpgargs = keyringargs + vrfyargs
            ecode, out, err = gpg_run_command(gpgargs, stdin=bsigdata)

    else:
        logger.debug('Verifying using default keyring')
        ecode, out, err = gpg_run_command(vrfyargs, stdin=bsigdata)

    if ecode > 0:
        raise ValidationError('Failed to validate PGP signature')

    good, valid, trusted, signtime = check_gpg_status(err)
    if good and valid:
        return out, (good, valid, trusted, signtime)

    raise ValidationError('Failed to validate PGP signature')


def _load_messages(cmdargs) -> dict:
    import sys
    if not sys.stdin.isatty():
        messages = {'-': sys.stdin.buffer.read()}
    elif len(cmdargs.msgfile):
        # Load all message from the files passed to make sure they all parse correctly
        messages = dict()
        for msgfile in cmdargs.msgfile:
            with open(msgfile, 'rb') as fh:
                messages[msgfile] = fh.read()
    else:
        logger.critical('ERROR: Pipe a message to sign or pass filenames with individual messages')
        raise RuntimeError('Nothing to do')

    return messages


def cmd_sign(cmdargs, config: dict) -> None:
    # Do we have the signingkey defined?
    usercfg = get_config_from_git(r'user\..*')
    if not config.get('identity') and usercfg.get('email'):
        # Use user.email
        config['identity'] = usercfg.get('email')
    if not config.get('signingkey'):
        if usercfg.get('signingkey'):
            logger.warning('NOTICE: Using pgp key %s defined by user.signingkey', usercfg.get('signingkey'))
            logger.warning('        Override by setting patatt.signingkey')
            config['signingkey'] = 'openpgp:%s' % usercfg.get('signingkey')
        else:
            logger.critical('ERROR: patatt.signingkey is not set')
            logger.critical('       Perhaps you need to run genkey first?')
            sys.exit(1)

    messages = _load_messages(cmdargs)

    sk = config.get('signingkey')
    if sk.startswith('ed25519:'):
        _sign_func = sign_ed25519
        identifier = sk[8:]
        keysrc = None
        if identifier.startswith('/') and os.path.exists(identifier):
            keysrc = identifier
        else:
            # datadir/private/%s.key
            ddir = get_data_dir()
            skey = os.path.join(ddir, 'private', '%s.key' % identifier)
            if os.path.exists(skey):
                keysrc = skey
            else:
                # finally, try .git/%s.key
                gtdir = get_git_toplevel()
                if gtdir:
                    skey = os.path.join(gtdir, '.git', '%s.key' % identifier)
                    if os.path.exists(skey):
                        keysrc = skey

        if not keysrc:
            logger.critical('ERROR: Could not find the key matching %s', identifier)
            sys.exit(1)

        logger.info('Using ed25519 key: %s', keysrc)
        with open(keysrc, 'r') as fh:
            keydata = fh.read()

    elif sk.startswith('openpgp:'):
        _sign_func = sign_openpgp
        keydata = sk[8:]
    else:
        logger.critical('Unknown key type: %s', sk)
        sys.exit(1)

    for filename, msgdata in messages.items():
        headers, payload = parse_message(msgdata)
        if is_signed(headers):
            logger.critical('Already signed: %s', filename)
            continue

        try:
            hhdr = _sign_func(headers, payload, keydata, identity=config.get('identity', ''),
                              selector=config.get('selector', ''))
        except SigningError as ex:
            logger.critical('ERROR: %s', ex)
            sys.exit(1)

        dshdr = hhdr.encode().encode()
        # insert it before the blank line
        lf = headers.pop(-1)
        headers.append(dshdr + lf)
        headers.append(lf)
        payload = b''.join(headers) + payload
        logger.debug('--- SIGNED MESSAGE STARTS ---')
        logger.debug(payload)
        if filename == '-':
            sys.stdout.buffer.write(payload)
        else:
            with open(filename, 'wb') as fh:
                fh.write(payload)

            logger.info('Signed: %s', filename)


def validate_message(msgdata: bytes, sources: list):
    headers, payload = parse_message(msgdata)

    if not is_signed(headers):
        raise ValidationError('message is not signed')

    signtime, identity, selector, algo, signed_hdrs, hdata = get_devsig_header_info(headers)

    pkey = None
    keysrc = None
    for source in sources:
        try:
            pkey, keysrc = get_public_key(source, algo, identity, selector)
            break
        except KeyError:
            pass

    if not pkey and algo == 'ed25519':
        raise ValidationError('no %s public key for %s/%s' % (algo, identity, selector))

    sdigest = None
    if algo == 'ed25519':
        sdigest = validate_ed25519(hdata['b'], pkey)
        # signtime is required for ed25519 signatures
        signtime = hdata.get('t', b'').decode()
        if not signtime:
            raise ValidationError('signature does not include t= signing time')
    elif algo == 'openpgp':
        sdigest, signtime = validate_openpgp(hdata['b'], pkey)

    if not sdigest:
        raise ValidationError('faled to verify %s signature for %s/%s' % (algo, identity, selector))

    # Now calculate our own digest and compare
    dshdr, digest = make_devsig_header(headers, payload, algo, signtime=hdata.get('t', b'').decode(),
                                       identity=hdata.get('i', b'').decode(),
                                       selector=hdata.get('s', b'').decode(), want_hdrs=signed_hdrs,
                                       strict=True)
    if sdigest == digest:
        return signtime, identity, selector, algo, keysrc

    raise ValidationError('failed to verify message content')


def cmd_validate(cmdargs, config: dict):
    messages = _load_messages(cmdargs)
    ddir = get_data_dir()
    pdir = os.path.join(ddir, 'public')
    sources = config.get('publickeypath', list())
    if pdir not in sources:
        sources.append(pdir)

    for filename, msgdata in messages.items():
        try:
            signtime, identity, selector, algo, pkey = validate_message(msgdata, sources)
            logger.critical('PASS: %s', os.path.basename(filename))
            logger.info('      by : %s (%s)', identity, algo)
            if pkey:
                logger.info('      key: %s', pkey)
            else:
                logger.info('      key: in default GnuPG keyring')
        except ValidationError as ex:
            logger.critical('FAIL: %s', os.path.basename(filename))
            logger.critical('      err: %s', ex)


def cmd_gen(cmdargs, config: dict) -> None:
    try:
        from nacl.signing import SigningKey
    except ModuleNotFoundError:
        raise RuntimeError('This operation requires PyNaCl libraries')

    # Do we have the signingkey defined?
    usercfg = get_config_from_git(r'user\..*')
    if not config.get('identity') and usercfg.get('email'):
        # Use user.email
        config['identity'] = usercfg.get('email')

    identifier = cmdargs.keyname
    if not identifier:
        identifier = datetime.datetime.today().strftime('%Y%m%d')

    ddir = get_data_dir()
    sdir = os.path.join(ddir, 'private')
    pdir = os.path.join(ddir, 'public')
    if not os.path.exists(sdir):
        os.mkdir(sdir, mode=0o0700)
    if not os.path.exists(pdir):
        os.mkdir(pdir, mode=0o0755)
    skey = os.path.join(sdir, '%s.key' % identifier)
    pkey = os.path.join(pdir, '%s.pub' % identifier)
    # Do we have a key with this identifier already present?
    if os.path.exists(skey) and not cmdargs.force:
        logger.critical('Key already exists: %s', skey)
        logger.critical('Use a different -n or pass -f to overwrite it')
        raise RuntimeError('Key already exists')

    logger.info('Generating a new ed25519 keypair')
    newkey = SigningKey.generate()

    # Make sure we write it as 0600
    def priv_opener(path, flags):
        return os.open(path, flags, 0o0600)

    with open(skey, 'wb', opener=priv_opener) as fh:
        fh.write(base64.b64encode(bytes(newkey)))
        logger.info('Wrote: %s', skey)

    with open(pkey, 'wb') as fh:
        fh.write(base64.b64encode(bytes(newkey.verify_key)))
        logger.info('Wrote: %s', pkey)

    # Also copy it into our local keyring
    dpkey = os.path.join(pdir, make_pkey_path('ed25519', config.get('identity'), 'default'))
    Path(os.path.dirname(dpkey)).mkdir(parents=True, exist_ok=True)
    if not os.path.exists(dpkey):
        with open(dpkey, 'wb') as fh:
            fh.write(base64.b64encode(bytes(newkey.verify_key)))
            logger.info('Wrote: %s', dpkey)
    else:
        spkey = os.path.join(pdir, make_pkey_path('ed25519', config.get('identity'), identifier))
        with open(spkey, 'wb') as fh:
            fh.write(base64.b64encode(bytes(newkey.verify_key)))
            logger.info('Wrote: %s', spkey)

    logger.info('Add the following to your .git/config (or global ~/.gitconfig):')
    logger.info('---')
    if cmdargs.section:
        logger.info('[patatt "%s"]', cmdargs.section)
    else:
        logger.info('[patatt]')
    logger.info('    signingkey = ed25519:%s', identifier)
    logger.info('---')
    logger.info('Next, communicate the contents of the following file to the')
    logger.info('repository keyring maintainers for inclusion into the project:')
    logger.info(pkey)


def command() -> None:
    import argparse
    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(
        prog='patatt',
        description='Cryptographically attest patches before sending out',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-q', '--quiet', action='store_true', default=False,
                        help='Only output errors to the stdout')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Show debugging output')
    parser.add_argument('-s', '--section', dest='section', default=None,
                        help='Use config section [patatt "sectionname"]')

    subparsers = parser.add_subparsers(help='sub-command help', dest='subcmd')

    sp_sign = subparsers.add_parser('sign', help='Cryptographically attest an RFC2822 message')
    sp_sign.add_argument('msgfile', nargs='*', help='RFC2822 message files to sign')
    sp_sign.set_defaults(func=cmd_sign)

    sp_val = subparsers.add_parser('validate', help='Validate a devsig-signed message')
    sp_val.add_argument('msgfile', nargs='*', help='Signed RFC2822 message files to validate')
    sp_val.set_defaults(func=cmd_validate)

    sp_gen = subparsers.add_parser('genkey', help='Generate a new ed25519 keypair')
    sp_gen.add_argument('-n', '--keyname', default=None,
                        help='Name to use for the key, e.g. "workstation", or "default"')
    sp_gen.add_argument('-f', '--force', action='store_true', default=False,
                        help='Overwrite any existing keys, if found')
    sp_gen.set_defaults(func=cmd_gen)

    _args = parser.parse_args()

    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)

    if _args.quiet:
        ch.setLevel(logging.CRITICAL)
    elif _args.debug:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)

    logger.addHandler(ch)
    config = get_config_from_git(r'patatt\..*', section=_args.section, defaults=DEFAULT_CONFIG)

    if 'func' not in _args:
        parser.print_help()
        sys.exit(1)

    try:
        _args.func(_args, config)
    except RuntimeError:
        sys.exit(1)


if __name__ == '__main__':
    command()
