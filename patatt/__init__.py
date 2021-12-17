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
from typing import Optional, Tuple, Union
from io import BytesIO

logger = logging.getLogger(__name__)

# Overridable via [patatt] parameters
GPGBIN = None
SSHKBIN = None

# Hardcoded defaults
DEVSIG_HDR = b'X-Developer-Signature'
DEVKEY_HDR = b'X-Developer-Key'

# Result and severity levels
RES_VALID = 0
RES_NOSIG = 4
RES_NOKEY = 8
RES_ERROR = 16
RES_BADSIG = 32

REQ_HDRS = [b'from', b'subject']
OPT_HDRS = [b'message-id']

# Quick cache for key info
KEYCACHE = dict()

# My version
__VERSION__ = '0.5-dev'
MAX_SUPPORTED_FORMAT_VERSION = 1


class SigningError(Exception):
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message)
        self.errors = errors


class ConfigurationError(Exception):
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message)
        self.errors = errors


class ValidationError(Exception):
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message)
        self.errors = errors


class NoKeyError(ValidationError):
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message)
        self.errors = errors


class BodyValidationError(ValidationError):
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message, errors)


class DevsigHeader:
    def __init__(self, hval: Optional[bytes] = None):
        self._headervals = list()
        self._body_hash = None
        # it doesn't need to be in any particular order,
        # but that's just anarchy, anarchy, I say!
        self._order = ['v', 'a', 't', 'l', 'i', 's', 'h', 'bh']
        self.hval = None
        self.hdata = dict()

        if hval:
            self.from_bytes(hval)
        else:
            self.hdata['v'] = b'1'

    def from_bytes(self, hval: bytes) -> None:
        self.hval = DevsigHeader._dkim_canonicalize_header(hval)
        hval = re.sub(rb'\s*', b'', self.hval)
        for chunk in hval.split(b';'):
            parts = chunk.split(b'=', 1)
            if len(parts) < 2:
                continue
            self.set_field(parts[0].decode(), parts[1])

    def get_field(self, field: str, decode: bool = False) -> Union[None, str, bytes]:
        value = self.hdata.get(field)
        if isinstance(value, bytes) and decode:
            return value.decode()
        return value

    def set_field(self, field: str, value: Union[None, str, bytes]) -> None:
        if value is None:
            del self.hdata[field]
            return
        if isinstance(value, str):
            value = value.encode()
        self.hdata[field] = value

    # do any git-mailinfo normalization prior to calling this
    def set_body(self, body: bytes, maxlen: Optional[int] = None) -> None:
        if maxlen:
            if maxlen > len(body):
                raise ValidationError('maxlen is larger than payload')
            if maxlen < len(body):
                body = body[:maxlen]

            self.hdata['l'] = bytes(len(body))

        hashed = hashlib.sha256()
        hashed.update(body)
        self._body_hash = base64.b64encode(hashed.digest())

    # do any git-mailinfo normalization prior to calling this
    def set_headers(self, headers: list, mode: str) -> None:
        parsed = list()
        allhdrs = set()
        # DKIM operates on headers in reverse order
        for header in reversed(headers):
            try:
                left, right = header.split(b':', 1)
                hname = left.strip().lower()
                parsed.append((hname, right))
                allhdrs.add(hname)
            except ValueError:
                continue

        reqset = set(REQ_HDRS)
        optset = set(OPT_HDRS)
        self._headervals = list()
        if mode == 'sign':
            # Make sure REQ_HDRS is a subset of allhdrs
            if not reqset.issubset(allhdrs):
                raise SigningError('The following required headers not present: %s'
                                   % (b', '.join(reqset.difference(allhdrs)).decode()))
            # Add optional headers that are actually present
            optpresent = list(allhdrs.intersection(optset))
            signlist = REQ_HDRS + sorted(optpresent)
            self.hdata['h'] = b':'.join(signlist)

        elif mode == 'validate':
            hfield = self.get_field('h')
            signlist = [x.strip() for x in hfield.split(b':')]
            # Make sure REQ_HEADERS are in this set
            if not reqset.issubset(set(signlist)):
                raise ValidationError('The following required headers not signed: %s'
                                      % (b', '.join(reqset.difference(set(signlist))).decode()))
        else:
            raise RuntimeError('Unknown set_header mode: %s' % mode)

        for shname in signlist:
            if shname not in allhdrs:
                # Per RFC:
                # Nonexistent header fields do not contribute to the signature computation (that is, they are
                # treated as the null input, including the header field name, the separating colon, the header field
                # value, and any CRLF terminator).
                continue
            at = 0
            for hname, rawval in list(parsed):
                if hname == shname:
                    self._headervals.append(hname + b':' + DevsigHeader._dkim_canonicalize_header(rawval))
                    parsed.pop(at)
                    break
                at += 1

    def sanity_check(self) -> None:
        if 'a' not in self.hdata:
            raise RuntimeError('Must set "a" field first')
        if not self._body_hash:
            raise RuntimeError('Must use set_body first')
        if not self._headervals:
            raise RuntimeError('Must use set_headers first')

    def validate(self, keyinfo: Union[str, bytes, None]) -> Tuple[str, str]:
        self.sanity_check()
        # Start by validating the body hash. If it fails to match, we can
        # bail early, before needing to do any signature validation.
        if self.get_field('bh') != self._body_hash:
            raise BodyValidationError('Body content validation failed')
        # Check that we have a b= field
        if not self.get_field('b'):
            raise RuntimeError('Missing "b=" value')
        pts = self.hval.rsplit(b'b=', 1)
        dshdr = pts[0] + b'b='
        bdata = re.sub(rb'\s*', b'', pts[1])
        # Calculate our own digest
        hashed = hashlib.sha256()
        # Add in our _headervals first (they aready have CRLF endings)
        hashed.update(b''.join(self._headervals))
        # and the devsig header now, without the trailing CRLF
        hashed.update(DEVSIG_HDR.lower() + b':' + dshdr)
        vdigest = hashed.digest()
        algo = self.get_field('a', decode=True)
        if algo.startswith('ed25519'):
            sdigest = DevsigHeader._validate_ed25519(bdata, keyinfo)
            signtime = self.get_field('t', decode=True)
            signkey = keyinfo
            if not signtime:
                raise ValidationError('t= field is required for ed25519 sigs')
            if sdigest != vdigest:
                raise ValidationError('Header validation failed')
        elif algo.startswith('openssh'):
            DevsigHeader._validate_openssh(bdata, vdigest, keyinfo)
            signtime = self.get_field('t', decode=True)
            signkey = keyinfo
            if not signtime:
                raise ValidationError('t= field is required for openssh sigs')
        elif algo.startswith('openpgp'):
            sdigest, (good, valid, trusted, signkey, signtime) = DevsigHeader._validate_openpgp(bdata, keyinfo)
            if sdigest != vdigest:
                raise ValidationError('Header validation failed')
        else:
            raise ValidationError('Unknown algorithm: %s', algo)

        return signkey, signtime

    def sign(self, keyinfo: Union[str, bytes], split: bool = True) -> Tuple[bytes, bytes]:
        self.sanity_check()
        self.set_field('bh', self._body_hash)
        algo = self.get_field('a', decode=True)
        hparts = list()
        for fn in self._order:
            fv = self.get_field(fn)
            if fv is not None:
                hparts.append(b'%s=%s' % (fn.encode(), fv))

        hparts.append(b'b=')
        dshval = b'; '.join(hparts)
        hashed = hashlib.sha256()
        # Add in our _headervals first (they aready have CRLF endings)
        hashed.update(b''.join(self._headervals))
        # and ourselves now, without the trailing CRLF
        hashed.update(DEVSIG_HDR.lower() + b':' + dshval)
        digest = hashed.digest()

        if algo.startswith('ed25519'):
            bval, pkinfo = DevsigHeader._sign_ed25519(digest, keyinfo)
        elif algo.startswith('openpgp'):
            bval, pkinfo = DevsigHeader._sign_openpgp(digest, keyinfo)
        elif algo.startswith('openssh'):
            bval, pkinfo = DevsigHeader._sign_openssh(digest, keyinfo)
        else:
            raise RuntimeError('Unknown a=%s' % algo)

        if split:
            return dshval + DevsigHeader.splitter(bval), pkinfo

        return dshval + bval, pkinfo

    @staticmethod
    def _sign_ed25519(payload: bytes, privkey: bytes) -> Tuple[bytes, bytes]:
        global KEYCACHE
        try:
            from nacl.signing import SigningKey
            from nacl.encoding import Base64Encoder
        except ModuleNotFoundError:
            raise RuntimeError('This operation requires PyNaCl libraries')

        if privkey not in KEYCACHE:
            sk = SigningKey(privkey, encoder=Base64Encoder)
            vk = base64.b64encode(sk.verify_key.encode())
            KEYCACHE[privkey] = (sk, vk)
        else:
            sk, vk = KEYCACHE[privkey]

        bdata = sk.sign(payload, encoder=Base64Encoder)

        return bdata, vk

    @staticmethod
    def _validate_ed25519(sigdata: bytes, pubkey: bytes) -> bytes:
        try:
            from nacl.signing import VerifyKey
            from nacl.encoding import Base64Encoder
            from nacl.exceptions import BadSignatureError
        except ModuleNotFoundError:
            raise RuntimeError('This operation requires PyNaCl libraries')

        vk = VerifyKey(pubkey, encoder=Base64Encoder)
        try:
            return vk.verify(sigdata, encoder=Base64Encoder)
        except BadSignatureError:
            raise ValidationError('Failed to validate signature')

    @staticmethod
    def _sign_openssh(payload: bytes, keyfile: str) -> Tuple[bytes, bytes]:
        global KEYCACHE
        keypath = os.path.expanduser(os.path.expandvars(keyfile))
        if not os.access(keypath, os.R_OK):
            raise SigningError('Unable to read openssh public key %s' % keypath)
        sshkargs = ['-Y', 'sign', '-n', 'patatt', '-f', keypath]
        ecode, out, err = sshk_run_command(sshkargs, payload)
        if ecode > 0:
            raise SigningError('Running ssh-keygen failed', errors=err.decode().split('\n'))
        # Remove the header/footer
        sigdata = b''
        for bline in out.split(b'\n'):
            if bline.startswith(b'----'):
                continue
            sigdata += bline
        if keypath not in KEYCACHE:
            # Now get the fingerprint of this keyid
            sshkargs = ['-l', '-f', keypath]
            ecode, out, err = sshk_run_command(sshkargs, payload)
            if ecode > 0:
                raise SigningError('Running ssh-keygen failed', errors=err.decode().split('\n'))
            chunks = out.split()
            keyfp = chunks[1]
            KEYCACHE[keypath] = keyfp
        else:
            keyfp = KEYCACHE[keypath]

        return sigdata, keyfp

    @staticmethod
    def _validate_openssh(sigdata: bytes, payload: bytes, keydata: bytes) -> None:
        with tempfile.TemporaryDirectory(suffix='.patch-attest-poc') as td:
            # Start by making a signers file
            fpath = os.path.join(td, 'signers')
            spath = os.path.join(td, 'sigdata')
            with open(fpath, 'wb') as fh:
                chunks = keydata.split()
                bcont = b'patatter@local namespaces="patatt" ' + chunks[0] + b' ' + chunks[1] + b'\n'
                logger.debug('allowed-signers: %s', bcont)
                fh.write(bcont)
            with open(spath, 'wb') as fh:
                bcont = b'-----BEGIN SSH SIGNATURE-----\n' + sigdata + b'\n-----END SSH SIGNATURE-----\n'
                logger.debug('sigdata: %s', bcont)
                fh.write(bcont)
            sshkargs = ['-Y', 'verify', '-n', 'patatt', '-I', 'patatter@local', '-f', fpath, '-s', spath]
            ecode, out, err = sshk_run_command(sshkargs, payload)
            if ecode > 0:
                raise ValidationError('Failed to validate openssh signature', errors=err.decode().split('\n'))

    @staticmethod
    def _sign_openpgp(payload: bytes, keyid: str) -> Tuple[bytes, bytes]:
        global KEYCACHE
        gpgargs = ['-s', '-u', keyid]
        ecode, out, err = gpg_run_command(gpgargs, payload)
        if ecode > 0:
            raise SigningError('Running gpg failed', errors=err.decode().split('\n'))
        bdata = base64.b64encode(out)
        # Now get the fingerprint of this keyid
        if keyid not in KEYCACHE:
            gpgargs = ['--with-colons', '--fingerprint', keyid]
            ecode, out, err = gpg_run_command(gpgargs)
            if ecode > 0:
                raise SigningError('Running gpg failed', errors=err.decode().split('\n'))
            pkid = None
            keyfp = None
            for line in out.split(b'\n'):
                if line.startswith(b'pub:'):
                    fields = line.split(b':')
                    pkid = fields[4]
                elif line.startswith(b'fpr:') and pkid:
                    fields = line.split(b':')
                    if fields[9].find(pkid) > 0:
                        keyfp = fields[9]
                        break
            KEYCACHE[keyid] = keyfp
        else:
            keyfp = KEYCACHE[keyid]

        return bdata, keyfp

    @staticmethod
    def _validate_openpgp(sigdata: bytes, pubkey: Optional[bytes]) -> Tuple[bytes, tuple]:
        global KEYCACHE
        bsigdata = base64.b64decode(sigdata)
        vrfyargs = ['--verify', '--output', '-', '--status-fd=2']
        if pubkey:
            with tempfile.TemporaryFile(suffix='.patch-attest-poc') as temp_keyring:
                keyringargs = ['--no-default-keyring', f'--keyring={temp_keyring.name}']
                if pubkey in KEYCACHE:
                    logger.debug('Reusing cached keyring')
                    temp_keyring.write(KEYCACHE[pubkey])
                else:
                    logger.debug('Importing into new keyring')
                    gpgargs = keyringargs + ['--status-fd=1', '--import']
                    ecode, out, err = gpg_run_command(gpgargs, stdin=pubkey)
                    # look for IMPORT_OK
                    if out.find(b'[GNUPG:] IMPORT_OK') < 0:
                        raise ValidationError('Could not import GnuPG public key')
                    KEYCACHE[pubkey] = temp_keyring.read()
                gpgargs = keyringargs + vrfyargs
                ecode, out, err = gpg_run_command(gpgargs, stdin=bsigdata)

        else:
            logger.debug('Verifying using default keyring')
            ecode, out, err = gpg_run_command(vrfyargs, stdin=bsigdata)

        if ecode > 0:
            if err.find(b'[GNUPG:] NO_PUBKEY '):
                raise NoKeyError('No matching key found')
            raise ValidationError('Failed to validate PGP signature')

        good, valid, trusted, signkey, signtime = DevsigHeader._check_gpg_status(err)
        if good and valid:
            return out, (good, valid, trusted, signkey, signtime)

        raise ValidationError('Failed to validate PGP signature')

    @staticmethod
    def _check_gpg_status(status: bytes) -> Tuple[bool, bool, bool, str, str]:
        good = False
        valid = False
        trusted = False
        signtime = ''
        signkey = ''

        logger.debug('GNUPG status:\n\t%s', status.decode().strip().replace('\n', '\n\t'))
        gs_matches = re.search(rb'^\[GNUPG:] GOODSIG ([0-9A-F]+)\s+(.*)$', status, flags=re.M)
        if gs_matches:
            good = True
        vs_matches = re.search(rb'^\[GNUPG:] VALIDSIG ([0-9A-F]+) (\d{4}-\d{2}-\d{2}) (\d+)', status, flags=re.M)
        if vs_matches:
            valid = True
            signkey = vs_matches.groups()[0].decode()
            signtime = vs_matches.groups()[2].decode()
        ts_matches = re.search(rb'^\[GNUPG:] TRUST_(FULLY|ULTIMATE)', status, flags=re.M)
        if ts_matches:
            trusted = True

        return good, valid, trusted, signkey, signtime

    @staticmethod
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

    @staticmethod
    def _dkim_canonicalize_header(hval: bytes) -> bytes:
        # Handle MIME encoded-word syntax or other types of header encoding if
        # present. The decode_header() function requires a str argument (not
        # bytes) so we must decode our bytes first, this is easy as RFC2822 (sec
        # 2.2) says header fields must be composed of US-ASCII characters. The
        # resulting string is re-encoded to allow further processing.
        if b'?q?' in hval:
            hval = hval.decode('ascii', errors='ignore')
            hval = str(email.header.make_header(email.header.decode_header(hval)))
            hval = hval.encode('utf-8')
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


class PatattMessage:
    def __init__(self, msgdata: bytes):
        self.headers = list()
        self.body = b''
        self.lf = b'\n'
        self.signed = False

        self.canon_headers = None
        self.canon_body = None
        self.canon_identity = None

        self.sigs = None

        self.load_from_bytes(msgdata)

    def git_canonicalize(self):
        if self.canon_body is not None:
            return

        # Generate a new payload using m and p and canonicalize with \r\n endings,
        # trimming any excess blank lines ("simple" DKIM canonicalization).
        m, p, i = PatattMessage._get_git_mailinfo(b''.join(self.headers) + self.lf + self.body)
        self.canon_body = b''
        for line in re.sub(rb'[\r\n]*$', b'', m + p).split(b'\n'):
            self.canon_body += re.sub(rb'[\r\n]*$', b'', line) + b'\r\n'

        idata = dict()
        for line in re.sub(rb'[\r\n]*$', b'', i).split(b'\n'):
            left, right = line.split(b':', 1)
            idata[left.lower()] = right.strip()

        # Theoretically, we should always see an "Email" line
        self.canon_identity = idata.get(b'email', b'').decode()

        # Now substituting headers returned by mailinfo
        self.canon_headers = list()
        for header in self.headers:
            try:
                left, right = header.split(b':', 1)
                lleft = left.lower()
                if lleft == b'from':
                    right = b' ' + idata.get(b'author', b'') + b' <' + idata.get(b'email', b'') + b'>'
                elif lleft == b'subject':
                    right = b' ' + idata.get(b'subject', b'')
                self.canon_headers.append(left + b':' + right)
            except ValueError:
                self.canon_headers.append(header)

    def sign(self, algo: str, keyinfo: Union[str, bytes], identity: Optional[str], selector: Optional[str]) -> None:
        # Remove any devsig headers
        for header in list(self.headers):
            if header.startswith(DEVSIG_HDR) or header.startswith(DEVKEY_HDR):
                self.headers.remove(header)
        self.git_canonicalize()
        ds = DevsigHeader()
        ds.set_headers(self.canon_headers, mode='sign')
        ds.set_body(self.canon_body)
        ds.set_field('l', str(len(self.canon_body)))
        if not identity:
            identity = self.canon_identity
        ds.set_field('i', identity)
        if selector:
            ds.set_field('s', selector)

        if algo not in ('ed25519', 'openpgp', 'openssh'):
            raise SigningError('Unsupported algorithm: %s' % algo)

        ds.set_field('a', '%s-sha256' % algo)
        if algo in ('ed25519', 'openssh'):
            # Set signing time for non-pgp sigs
            ds.set_field('t', str(int(time.time())))
        hv, pkinfo = ds.sign(keyinfo)

        dshdr = email.header.make_header([(DEVSIG_HDR + b': ' + hv, 'us-ascii')], maxlinelen=78)
        self.headers.append(dshdr.encode().encode() + self.lf)

        # Make informational header about the key used
        idata = [
            b'i=%s' % identity.encode(),
            b'a=%s' % algo.encode(),
        ]
        if algo == 'openpgp':
            idata.append(b'fpr=%s' % pkinfo)
        elif algo == 'openssh':
            idata.append(b'fpr=%s' % pkinfo)
        else:
            idata.append(b'pk=%s' % pkinfo)

        dkhdr = email.header.make_header([(DEVKEY_HDR + b': ' + b'; '.join(idata), 'us-ascii')], maxlinelen=78)
        self.headers.append(dkhdr.encode().encode() + self.lf)

    def validate(self, identity: str, pkey: Union[bytes, str, None], trim_body: bool = False) -> str:
        vds = None
        for ds in self.sigs:
            if ds.get_field('i', decode=True) == identity:
                vds = ds
                break
        if vds is None:
            raise ValidationError('No signatures matching identity %s' % identity)

        self.git_canonicalize()
        vds.set_headers(self.canon_headers, mode='validate')

        if trim_body:
            lfield = vds.get_field('l')
            if lfield:
                try:
                    maxlen = int(lfield)
                    vds.set_body(self.canon_body, maxlen=maxlen)
                except ValueError:
                    vds.set_body(self.canon_body)
        else:
            vds.set_body(self.canon_body)

        return vds.validate(pkey)

    def as_bytes(self):
        return b''.join(self.headers) + self.lf + self.body

    def as_string(self, encoding='utf-8'):
        return self.as_bytes().decode(encoding)

    def load_from_bytes(self, msgdata: bytes) -> None:
        # We use simplest parsing -- using Python's email module would be overkill
        ldshn = DEVSIG_HDR.lower()
        with BytesIO(msgdata) as fh:
            while True:
                line = fh.readline()
                if not len(line):
                    break

                if not len(line.strip()):
                    self.lf = line
                    self.body = fh.read()
                    break

                # is it a wrapped header?
                if line[0] in ("\x09", "\x20", 0x09, 0x20):
                    if not len(self.headers):
                        raise RuntimeError('Not a valid RFC2822 message')
                    # attach it to the previous header
                    self.headers[-1] += line
                    continue
                # Is it a signature header?
                if line.lower().startswith(ldshn):
                    self.signed = True
                self.headers.append(line)

        if not len(self.headers) or not len(self.body):
            raise RuntimeError('Not a valid RFC2822 message')

    def get_sigs(self) -> list:
        if self.sigs is not None:
            return self.sigs

        ldshn = DEVSIG_HDR.lower()
        self.sigs = list()
        from_id = None

        for header in self.headers:
            try:
                left, right = header.split(b':', 1)
                hn = left.strip().lower()
                hv = right
                if hn == ldshn:
                    self.sigs.append(DevsigHeader(hv))
                elif hn == b'from':
                    parts = email.utils.parseaddr(hv.decode().strip())
                    from_id = parts[1]
            except ValueError:
                raise RuntimeError('Error parsing headers')

        if from_id:
            for ds in self.sigs:
                if 'i' not in ds.hdata:
                    ds.set_field('i', from_id)

        return self.sigs

    @staticmethod
    def _get_git_mailinfo(payload: bytes) -> Tuple[bytes, bytes, bytes]:
        with tempfile.TemporaryDirectory(suffix='.git-mailinfo') as td:
            mf = os.path.join(td, 'm')
            pf = os.path.join(td, 'p')
            cmdargs = ['git', 'mailinfo', '--encoding=utf-8', '--no-scissors', mf, pf]
            ecode, i, err = _run_command(cmdargs, stdin=payload)
            if ecode > 0:
                logger.debug('FAILED  : Failed running git-mailinfo:')
                logger.debug(err.decode())
                raise RuntimeError('Failed to run git-mailinfo: %s' % err.decode())

            with open(mf, 'rb') as mfh:
                m = mfh.read()
            with open(pf, 'rb') as pfh:
                p = pfh.read()
            return m, p, i


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
        args = ['git', '--git-dir', gitdir, '--no-pager'] + args
    else:
        args = ['git', '--no-pager'] + args
    return _run_command(args, stdin=stdin, env=env)


def get_config_from_git(regexp: str, section: Optional[str] = None, defaults: Optional[dict] = None,
                        multivals: Optional[list] = None):
    if multivals is None:
        multivals = list()

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

            if cfgkey in multivals:
                if cfgkey not in gitconfig:
                    gitconfig[cfgkey] = list()
                gitconfig[cfgkey].append(value)
            else:
                gitconfig[cfgkey] = value
        except ValueError:
            logger.debug('Ignoring git config entry %s', line)

    return gitconfig


def gpg_run_command(cmdargs: list, stdin: bytes = None) -> Tuple[int, bytes, bytes]:
    set_bin_paths(None)
    cmdargs = [GPGBIN, '--batch', '--no-auto-key-retrieve', '--no-auto-check-trustdb'] + cmdargs
    return _run_command(cmdargs, stdin)


def sshk_run_command(cmdargs: list, stdin: bytes = None) -> Tuple[int, bytes, bytes]:
    set_bin_paths(None)
    cmdargs = [SSHKBIN] + cmdargs
    return _run_command(cmdargs, stdin)


def get_git_toplevel(gitdir: str = None) -> str:
    cmdargs = ['git']
    if gitdir:
        cmdargs += ['--git-dir', gitdir]
    cmdargs += ['rev-parse', '--show-toplevel']
    ecode, out, err = _run_command(cmdargs)
    if ecode == 0:
        return out.decode().strip()
    return ''


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
    logger.debug('Looking for %s in %s', keypath, source)

    # ref:refs/heads/someref:in-repo/path
    if source.startswith('ref:'):
        # split by :
        parts = source.split(':', 4)
        if len(parts) < 4:
            raise ConfigurationError('Invalid ref, must have at least 3 colons: %s' % source)
        gitrepo = parts[1]
        gitref = parts[2]
        gitsub = parts[3]
        if not gitrepo:
            gitrepo = get_git_toplevel()
        if not gitrepo:
            raise KeyError('Not in a git tree, so cannot use a ref:: source')

        gitrepo = os.path.expanduser(gitrepo)
        if gitrepo.find('$') >= 0:
            gitrepo = os.path.expandvars(gitrepo)
        if os.path.isdir(os.path.join(gitrepo, '.git')):
            gittop = os.path.join(gitrepo, '.git')
        else:
            gittop = gitrepo

        # it could omit the refspec, meaning "whatever the current ref"
        # grab the key from a fully ref'ed path
        subpath = os.path.join(gitsub, keypath)

        if not gitref:
            # What is our current ref?
            cmdargs = ['symbolic-ref', 'HEAD']
            ecode, out, err = git_run_command(gittop, cmdargs)
            if ecode == 0:
                gitref = out.decode().strip()
        if not gitref:
            raise KeyError('Could not figure out current ref in %s' % gittop)

        keysrc = f'{gitref}:{subpath}'
        cmdargs = ['show', keysrc]
        ecode, out, err = git_run_command(gittop, cmdargs)
        if ecode == 0:
            # Handle one level of symlinks
            if out.find(b'\n') < 0 < out.find(b'/'):
                # Check this path as well
                linktgt = os.path.normpath(os.path.join(os.path.dirname(subpath), out.decode()))
                keysrc = f'{gitref}:{linktgt}'
                cmdargs = ['show', keysrc]
                ecode, out, err = git_run_command(gittop, cmdargs)
                if ecode == 0:
                    logger.debug('KEYSRC  : %s (symlinked)', keysrc)
                    return out, 'ref:%s:%s' % (gittop, keysrc)
            logger.debug('KEYSRC  : %s', keysrc)
            return out, 'ref:%s:%s' % (gittop, keysrc)

        # Does it exist on disk but hasn't been committed yet?
        fullpath = os.path.join(gitrepo, subpath)
        if os.path.exists(fullpath):
            with open(fullpath, 'rb') as fh:
                logger.debug('KEYSRC  : %s', fullpath)
                return fh.read(), fullpath

        raise KeyError('Could not find %s in %s:%s' % (subpath, gittop, gitref))

    # It's a disk path, then
    # Expand ~ and env vars
    source = os.path.expanduser(source)
    if source.find('$') >= 0:
        source = os.path.expandvars(source)
    fullpath = os.path.join(source, keypath)
    if os.path.exists(fullpath):
        with open(fullpath, 'rb') as fh:
            logger.debug('Loaded key from %s', fullpath)
            return fh.read(), fullpath

    raise KeyError('Could not find %s' % fullpath)


def _load_messages(cmdargs) -> dict:
    import sys
    if len(cmdargs.msgfile):
        # Load all message from the files passed to make sure they all parse correctly
        messages = dict()
        for msgfile in cmdargs.msgfile:
            with open(msgfile, 'rb') as fh:
                messages[msgfile] = fh.read()
    elif not sys.stdin.isatty():
        messages = {'-': sys.stdin.buffer.read()}
    else:
        logger.critical('E: Pipe a message to sign or pass filenames with individual messages')
        raise RuntimeError('Nothing to do')

    return messages


def sign_message(msgdata: bytes, algo: str, keyinfo: Union[str, bytes],
                 identity: Optional[str], selector: Optional[str]) -> bytes:
    pm = PatattMessage(msgdata)
    pm.sign(algo, keyinfo, identity=identity, selector=selector)
    return pm.as_bytes()


def set_bin_paths(config: Optional[dict]) -> None:
    global GPGBIN, SSHKBIN
    if GPGBIN is None:
        gpgcfg = get_config_from_git(r'gpg\..*')
        if config and config.get('gpg-bin'):
            GPGBIN = config.get('gpg-bin')
        elif gpgcfg.get('program'):
            GPGBIN = gpgcfg.get('program')
        else:
            GPGBIN = 'gpg'
    if SSHKBIN is None:
        sshcfg = get_config_from_git(r'gpg\..*', section='ssh')
        if config and config.get('ssh-keygen-bin'):
            SSHKBIN = config.get('ssh-keygen-bin')
        elif sshcfg.get('program'):
            SSHKBIN = sshcfg.get('program')
        else:
            SSHKBIN = 'ssh-keygen'


def cmd_sign(cmdargs, config: dict) -> None:
    # Do we have the signingkey defined?
    usercfg = get_config_from_git(r'user\..*')
    if not config.get('identity') and usercfg.get('email'):
        # Use user.email
        config['identity'] = usercfg.get('email')
    if not config.get('signingkey'):
        if usercfg.get('signingkey'):
            logger.info('N: Using pgp key %s defined by user.signingkey', usercfg.get('signingkey'))
            logger.info('N: Override by setting patatt.signingkey')
            config['signingkey'] = 'openpgp:%s' % usercfg.get('signingkey')
        else:
            logger.critical('E: patatt.signingkey is not set')
            logger.critical('E: Perhaps you need to run genkey first?')
            sys.exit(1)

    try:
        messages = _load_messages(cmdargs)
    except IOError as ex:
        logger.critical('E: %s', ex)
        sys.exit(1)

    sk = config.get('signingkey')
    if sk.startswith('ed25519:'):
        algo = 'ed25519'
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
            logger.critical('E: Could not find the key matching %s', identifier)
            sys.exit(1)

        logger.info('N: Using ed25519 key: %s', keysrc)
        with open(keysrc, 'r') as fh:
            keydata = fh.read()

    elif sk.startswith('openpgp:'):
        algo = 'openpgp'
        keydata = sk[8:]
    elif sk.startswith('openssh:'):
        algo = 'openssh'
        keydata = sk[8:]
    else:
        logger.critical('E: Unknown key type: %s', sk)
        sys.exit(1)

    for fn, msgdata in messages.items():
        try:
            pm = PatattMessage(msgdata)
            pm.sign(algo, keydata, identity=config.get('identity'), selector=config.get('selector'))
            logger.debug('--- SIGNED MESSAGE STARTS ---')
            logger.debug(pm.as_string())
            if fn == '-':
                sys.stdout.buffer.write(pm.as_bytes())
            else:
                with open(fn, 'wb') as fh:
                    fh.write(pm.as_bytes())

                logger.critical('SIGN | %s', os.path.basename(fn))

        except SigningError as ex:
            logger.critical('E: %s', ex)
            sys.exit(1)

        except RuntimeError as ex:
            logger.critical('E: %s: %s' % (fn, ex))
            sys.exit(1)


def validate_message(msgdata: bytes, sources: list, trim_body: bool = False) -> list:
    attestations = list()
    pm = PatattMessage(msgdata)
    if not pm.signed:
        logger.debug('message is not signed')
        attestations.append((RES_NOSIG, None, None, None, None, ['no signatures found']))
        return attestations

    # Find all identities for which we have public keys
    for ds in pm.get_sigs():
        errors = list()
        a = ds.get_field('a', decode=True)
        i = ds.get_field('i', decode=True)
        s = ds.get_field('s', decode=True)
        t = ds.get_field('t', decode=True)
        if not s:
            s = 'default'
        if a.startswith('ed25519'):
            algo = 'ed25519'
        elif a.startswith('openpgp'):
            algo = 'openpgp'
        elif a.startswith('openssh'):
            algo = 'openssh'
        else:
            errors.append('%s/%s Unknown algorigthm: %s' % (i, s, a))
            attestations.append((RES_ERROR, i, t, None, a, errors))
            continue

        pkey = keysrc = None
        for source in sources:
            try:
                pkey, keysrc = get_public_key(source, algo, i, s)
                break
            except KeyError:
                pass

        if not pkey and algo in ('ed25519', 'openssh'):
            errors.append('%s/%s no matching %s key found' % (i, s, algo))
            attestations.append((RES_NOKEY, i, t, None, algo, errors))
            continue

        try:
            signkey, signtime = pm.validate(i, pkey, trim_body=trim_body)
            if keysrc is None:
                # Default keyring used
                keysrc = '(default keyring)/%s' % signkey
            attestations.append((RES_VALID, i, signtime, keysrc, algo, errors))
        except NoKeyError:
            # Not in default keyring
            errors.append('%s/%s no matching openpgp key found' % (i, s))
            attestations.append((RES_NOKEY, i, t, None, algo, errors))
        except ValidationError:
            if keysrc is None:
                errors.append('failed to validate using default keyring')
            else:
                errors.append('failed to validate using %s' % keysrc)
            attestations.append((RES_BADSIG, i, t, keysrc, algo, errors))

    return attestations


def cmd_validate(cmdargs, config: dict):
    import mailbox
    if len(cmdargs.msgfile) == 1:
        # Try to open as an mbox file
        try:
            mbox = mailbox.mbox(cmdargs.msgfile[0])
        except IOError as ex:
            logger.critical('E: %s', ex)
            sys.exit(1)

        messages = dict()
        for msg in mbox:
            subject = msg.get('Subject', 'No subject')
            messages[subject] = msg.as_bytes()
    else:
        try:
            messages = _load_messages(cmdargs)
        except IOError as ex:
            logger.critical('E: %s', ex)
            sys.exit(1)

    ddir = get_data_dir()
    pdir = os.path.join(ddir, 'public')
    sources = config.get('keyringsrc')

    if pdir not in sources:
        sources.append(pdir)

    if config.get('trimbody', 'no') == 'yes':
        trim_body = True
    else:
        trim_body = False

    highest_err = 0
    for fn, msgdata in messages.items():
        try:
            attestations = validate_message(msgdata, sources, trim_body=trim_body)
            for result, identity, signtime, keysrc, algo, errors in attestations:
                if result > highest_err:
                    highest_err = result

                if result == RES_VALID:
                    logger.critical('  PASS | %s, %s', identity, fn)
                    if keysrc:
                        logger.info('       | key: %s', keysrc)
                    else:
                        logger.info('       | key: default GnuPG keyring')
                elif result <= RES_NOSIG:
                    logger.critical(' NOSIG | %s', fn)
                    for error in errors:
                        logger.critical('       | %s', error)
                elif result <= RES_NOKEY:
                    logger.critical(' NOKEY | %s, %s', identity, fn)
                    for error in errors:
                        logger.critical('       | %s', error)
                elif result <= RES_ERROR:
                    logger.critical(' ERROR | %s, %s', identity, fn)
                    for error in errors:
                        logger.critical('       | %s', error)
                else:
                    logger.critical('BADSIG | %s, %s', identity, fn)
                    for error in errors:
                        logger.critical('       | %s', error)

        except RuntimeError as ex:
            highest_err = RES_ERROR
            logger.critical(' ERROR | err: %s | %s', ex, fn)

    sys.exit(highest_err)


def cmd_genkey(cmdargs, config: dict) -> None:
    try:
        from nacl.signing import SigningKey
    except ModuleNotFoundError:
        raise RuntimeError('This operation requires PyNaCl libraries')

    # Do we have the signingkey defined?
    usercfg = get_config_from_git(r'user\..*')
    if not config.get('identity'):
        if not usercfg.get('email'):
            logger.critical('This operation requires user.email to be set')
            sys.exit(1)
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

    logger.critical('Generating a new ed25519 keypair')
    newkey = SigningKey.generate()

    # Make sure we write it as 0600
    def priv_opener(path, flags):
        return os.open(path, flags, 0o0600)

    with open(skey, 'wb', opener=priv_opener) as fh:
        fh.write(base64.b64encode(bytes(newkey)))
        logger.critical('Wrote: %s', skey)

    with open(pkey, 'wb') as fh:
        fh.write(base64.b64encode(newkey.verify_key.encode()))
        logger.critical('Wrote: %s', pkey)

    # Also copy it into our local keyring
    spkey = os.path.join(pdir, make_pkey_path('ed25519', config.get('identity'), identifier))
    Path(os.path.dirname(spkey)).mkdir(parents=True, exist_ok=True)
    with open(spkey, 'wb') as fh:
        fh.write(base64.b64encode(newkey.verify_key.encode()))
        logger.critical('Wrote: %s', spkey)
    dpkey = os.path.join(pdir, make_pkey_path('ed25519', config.get('identity'), 'default'))
    if not os.path.exists(dpkey):
        # symlink our new key to be the default
        os.symlink(identifier, dpkey)

    logger.critical('Add the following to your .git/config (or global ~/.gitconfig):')
    logger.critical('---')
    if cmdargs.section:
        logger.critical('[patatt "%s"]', cmdargs.section)
    else:
        logger.critical('[patatt]')
    logger.critical('    signingkey = ed25519:%s', identifier)
    logger.critical('    selector = %s', identifier)
    logger.critical('---')
    logger.critical('Next, communicate the contents of the following file to the')
    logger.critical('repository keyring maintainers for inclusion into the project:')
    logger.critical(pkey)


def cmd_install_hook(cmdargs, config: dict):  # noqa
    gitrepo = get_git_toplevel()
    if not gitrepo:
        logger.critical('Not in a git tree, cannot install hook')
        sys.exit(1)
    hookfile = os.path.join(gitrepo, '.git', 'hooks', 'sendemail-validate')
    if os.path.exists(hookfile):
        logger.critical('Hook already exists: %s', hookfile)
        sys.exit(1)
    Path(os.path.join(gitrepo, '.git', 'hooks')).mkdir(parents=True, exist_ok=True)
    with open(hookfile, 'w') as fh:
        fh.write('#!/bin/sh\n')
        fh.write('# installed by patatt install-hook\n')
        fh.write('patatt sign --hook "${1}"\n')
        os.chmod(hookfile, 0o755)
    logger.critical('Hook installed as %s', hookfile)


def command() -> None:
    import argparse
    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(
        prog='patatt',
        description='Cryptographically attest patches before sending out',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Be a bit more verbose')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Show debugging output')
    parser.add_argument('-s', '--section', dest='section', default=None,
                        help='Use config section [patatt "sectionname"]')
    parser.add_argument('--version', action='version', version=__VERSION__)

    subparsers = parser.add_subparsers(help='sub-command help', dest='subcmd')

    sp_sign = subparsers.add_parser('sign', help='Cryptographically attest an RFC2822 message')
    sp_sign.add_argument('--hook', dest='hookmode', action='store_true', default=False,
                         help='Git hook mode')
    sp_sign.add_argument('msgfile', nargs='*', help='RFC2822 message files to sign')
    sp_sign.set_defaults(func=cmd_sign)

    sp_val = subparsers.add_parser('validate', help='Validate a devsig-signed message')
    sp_val.add_argument('msgfile', nargs='*', help='Individual signed message files to validate or an mbox')
    sp_val.set_defaults(func=cmd_validate)

    sp_gen = subparsers.add_parser('genkey', help='Generate a new ed25519 keypair')
    sp_gen.add_argument('-n', '--keyname', default=None,
                        help='Name to use for the key, e.g. "workstation", or "default"')
    sp_gen.add_argument('-f', '--force', action='store_true', default=False,
                        help='Overwrite any existing keys, if found')
    sp_gen.set_defaults(func=cmd_genkey)

    sp_install = subparsers.add_parser('install-hook', help='Install sendmail-validate hook into the current repo')
    sp_install.set_defaults(func=cmd_install_hook)

    _args = parser.parse_args()

    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    try:
        if _args.hookmode:
            formatter = logging.Formatter('patatt: %(message)s')
    except AttributeError:
        pass
    ch.setFormatter(formatter)

    if _args.verbose:
        ch.setLevel(logging.INFO)
    elif _args.debug:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.CRITICAL)

    logger.addHandler(ch)
    config = get_config_from_git(r'patatt\..*', section=_args.section, multivals=['keyringsrc'])
    # Append some extra keyring locations
    if 'keyringsrc' not in config:
        config['keyringsrc'] = list()
    config['keyringsrc'] += ['ref:::.keys', 'ref:::.local-keys', 'ref::refs/meta/keyring:']
    set_bin_paths(config)
    logger.debug('config: %s', config)

    if 'func' not in _args:
        parser.print_help()
        sys.exit(1)

    try:
        _args.func(_args, config)
    except RuntimeError:
        sys.exit(1)


if __name__ == '__main__':
    command()
