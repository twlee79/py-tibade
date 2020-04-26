#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
py-tibade: Python Titanium Backup Decrypt
-----------------------------------------
Author: Tet Woo Lee

This is a Python/[pycryptodome]-based implementation of [TitaniumBackupDecrypt],
which was originally authored by Brian T. Hafer. It will decrypt backups made 
by [Titanium Backup for Android].

[pycryptodome]: https://www.pycryptodome.org/en/latest/
[TitaniumBackupDecrypt]: https://github.com/bhafer/TitaniumBackupDecrypt
[Titanium Backup for Android]: https://www.titaniumtrack.com/titanium-backup.html
"""


_PROGRAM_NAME = 'py-tibade'
# -------------------------------------------------------------------------------
# Author        |Tet Woo Lee
# --------------|----------------------------
# Created       | 2020-04-26
# Copyright     | © 2020 Tet Woo Lee
# License       | GPLv3
# Dependencies  | pycryptodome, tested with v3.8.2
# -------------------------------------------------------------------------------

_PROGRAM_VERSION = '1.0.0dev1'
# -------------------------------------------------------------------------------
# ### Change log
#
# + version 1.0.dev1 2020-04-26
#   Working version
# -------------------------------------------------------------------------------

import argparse
import base64
import getpass
import glob
import hmac
import io
import os
import pathlib
import re
import sys
from hashlib import sha1

import Crypto.Util.Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5


class RawDescription_ArgumentDefaultsHelpFormatter(
    argparse.RawDescriptionHelpFormatter,
    argparse.ArgumentDefaultsHelpFormatter):
    pass
    """
    Combined HelpFormatter class for keeping raw description as well
    as formatting argument defaults using mutiple inheritance.
    Works with Python 3.7.6 as implementation methods of these classes do not
    interfere with each other, but since implementation of these classes
    are considered 'implementation details', there is no guarantee
    that this will keep working in the future.
    """

example_file = "C:/_del/com.authy.authy-20200426-045104.tar.gz"
output_file = "C:/_del/com.authy.authy-20200426-045104dec.tar.gz."

def tibade_decrypt(input_path, passphrase, output_path, verbose = 0):
    """
    Decrypt `input_path` to `output_path` with `passphrase`.
    `input_path` and `output_path` are `pathlib.Path` objects.
    """
    expected_signature = b"TB_ARMOR_V1"
    header_read_chunk = 1024*200 # size of initial chunk of data to read header
    decrypt_chunk = 10*1024*1024 # size of chunk when decrypting

    with input_path.open("rb") as input_handle:
        # Header, expect "TB_ARMOR_V1" '\n' pass_hmac_key '\n' 
        # pass_hmac_result '\n' public_key '\n' encrypted_private_key '\n' 
        # encrypted_session_key '\n' Data
        signature = input_handle.read(len(expected_signature))
        if signature!=expected_signature:
            raise ValueError(f"invalid signature {signature}, expected {expected_signature}")

        header_newlines = 6 # new \n characters present in header before data payload
        header_bytes = input_handle.read(header_read_chunk)

        newlines = 0
        
        for i, header_byte in enumerate(header_bytes):
            if header_byte==ord("\n"): 
                newlines += 1 
                if newlines>=header_newlines: 
                    header_end = i
                    data_start = len(expected_signature)+i+1 # +1 to skip last newline
                    break
        else:
            raise ValueError("could not find header")

        # decode header
        header = header_bytes[:header_end].decode('utf-8').split('\n')
        pass_hmac_key = base64.b64decode(header[1])
        pass_hmac_result = base64.b64decode(header[2])
        public_key = base64.b64decode(header[3]) 
        encrypted_private_key = base64.b64decode(header[4])
        encrypted_session_key = base64.b64decode(header[5])

        len_HmacKey = len(pass_hmac_key)*8 # in bits
        len_public_key = len(public_key)*8
        len_encrypted_private_key = len(encrypted_private_key)*8
        len_encrypted_session_key = len(encrypted_session_key)*8
        if verbose>=2:
            print(f"   Key lengths: hmac {len_HmacKey} bits, "
                  f"public key {len_public_key} DER bits, "
                  f"private key {len_encrypted_private_key} DER bits, "
                  f"encrypted session key {len_encrypted_session_key} bits")

        ## Check passphrase using hmac-sha1
        passphrase_encoded = passphrase.encode("utf-8")
        pp_hmac = hmac.digest(pass_hmac_key, passphrase_encoded, sha1)
        if hmac.compare_digest(pp_hmac,pass_hmac_result):
            if verbose>=3: print("   Passphrase matches")
        else:
            raise ValueError("invalid passphrase")

        ## Hash passphrase
        hasher = sha1()
        hasher.update(passphrase_encoded)
        hashed_pp = hasher.digest()

        ## Decrypt private key with AES-256, using iv of sixteen 0x00 bytes
        key_aes = hashed_pp+bytearray(12)
        cipher_aes = AES.new(key_aes, AES.MODE_CBC, iv=bytearray(16))
        decrypted_key = cipher_aes.decrypt(encrypted_private_key)
        private_key = Crypto.Util.Padding.unpad(decrypted_key, block_size = 16, 
            style='pkcs7')
            # PKCS5 is PKCS7 with block_size 8, info says PKCS5
            # but block_size 8 gives errors with 4096 bit RSA keys 
            # and block_size 16 is expected for AES, so assume this is correct
            # tested and works with 1024 and 4096 bit keys
        
        ## Decrypt the session key with the private RSA key

        # create a RSA keypair instance with decryped private RSA key
        keypair_rsa = RSA.import_key(private_key)

        # sanity check: calculated public key should match that stored in header
        if hmac.compare_digest(keypair_rsa.publickey().exportKey(format='DER'),
            public_key):
            if verbose>=3: print("   public_key matches")
        else:
            raise ValueError("calculated public key differs from one in header")
        
        # create cipher with keypair and decrypt session key
        cipher_rsa = PKCS1_v1_5.new(keypair_rsa)
        session_key = cipher_rsa.decrypt(encrypted_session_key, None)
        if session_key is None:
            raise ValueError("could not decrypt session key")
        len_session_key = len(session_key)*8
        if verbose>=2:
            print(f"   Session key length: {len_session_key} bits")

        payload_cipher_aes = AES.new(session_key, AES.MODE_CBC, iv=bytearray(16))
        input_handle.seek(data_start)
        n_encrypted_bytes = 0
        n_decrypted_bytes = 0
        input_filesize = os.fstat(input_handle.fileno()).st_size
        eof = False
        with output_path.open("wb") as out_handle:
            while not eof:
                block = input_handle.read(decrypt_chunk)
                if input_handle.tell()==input_filesize: 
                    eof = True # need to track eof here for unpadding purposes
                n_encrypted_bytes += len(block)
                decrypted_block = payload_cipher_aes.decrypt(block)
                if eof:
                    # remove padding in final block
                    decrypted_block = Crypto.Util.Padding.unpad(decrypted_block, block_size = 16, style='pkcs7')
                n_decrypted_bytes += len(decrypted_block)
                out_handle.write(decrypted_block)
        print("   File decrypted")
        if verbose>=1:
            print(f"    Bytes: {n_encrypted_bytes} encrypted, {n_decrypted_bytes} decrypted")

def main(argv = None):
    # INITIALISATION
    print('{} {}'.format(_PROGRAM_NAME, _PROGRAM_VERSION))
    parser = argparse.ArgumentParser(prog=_PROGRAM_NAME,
                                     description=__doc__,
                                     formatter_class=RawDescription_ArgumentDefaultsHelpFormatter)
    parser.add_argument('--version', action='version',
                        version='{} {}'.format(_PROGRAM_NAME, _PROGRAM_VERSION))
    parser.add_argument('inputfiles', nargs='+',
                        help='Input file(s), either a list of filenames or '
                        'as an unexpanded glob wildcards that is expanded '
                        'internally')
    parser.add_argument('-s', '--suffix', type=str, default="-decrypted",
                        help='Suffix to add to base filename of decrypted files, '
                        'appended to stem before any extensions')
    parser.add_argument('-m', '--match_basename', type=str, 
                        default="(^.*-[0-9\\-]+)[.]([a-z]{3})([.a-z]{0,4})",
                        help='Regular expression to match base filename of a '
                        'file, applied to filename without directory; first '
                        'capturing group should be base filename; an error is '
                        'produced if files don\'t match this pattern, which can '
                        'be ignored with the `-c` option')
    parser.add_argument('-p', '--passphrase', type=str, 
                        help='Passphrase used to encrypt the backup files, if '
                        'not present then user will be prompted to enter one; '
                        'same passphrase used for all files.')
    parser.add_argument('-c', '--continue', action='store_true', dest='cont',
                        help='Continue processing next file even if error '
                        'encountered; by default script will stop on first '
                        'error')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase logging verbosity, available levels 1 to 3 '
                             'with `-v` to `-vvv`')

    args = parser.parse_args(argv)
    if argv is None: argv = sys.argv[1:] # if parameters not provided, use sys.argv

    input_patterns = args.inputfiles
    verbose = args.verbose
    suffix = args.suffix
    match_basename = args.match_basename
    passphrase = args.passphrase
    should_continue = args.cont


    if verbose>=1: print("Provided input files:\n {}".format('\n '.join(input_patterns)))

    input_files = []
    for input_pattern in input_patterns:
        for input_file in glob.glob(input_pattern):
            input_files.append(input_file)
    if len(input_files)<1:
        print("Did not find any files to process")
        return
    if verbose>=1: print("Found input files:\n {}".format('\n '.join(input_files)))
    if passphrase is None:
        passphrase = getpass.getpass("Enter passphrase: ")

    n_errors = 0
    for input_file in input_files:
        try:
            input_path = pathlib.Path(input_file)
            print(f"Processing: {input_file}")
            rex = re.match(match_basename, input_path.name)
            if not rex:
                raise ValueError(f"unable to find basename in {input_file}")
            basename = rex.group(1)
            output_name = basename+suffix
            if verbose>=2: 
                print(f"  Basename: {basename}")
                print(f"  Output name: {output_name}")
            output_filename = input_file.replace(basename,output_name)
            output_path = pathlib.Path(output_filename)
            if verbose>=1: 
                print(f"  Output filename: {output_filename}")
            #output_file = 
            tibade_decrypt(input_path, passphrase, output_path, verbose)
        #if verbose>=1: 
        except ValueError as e:
            if should_continue: 
                print(f"ERROR: {e}")
                n_errors+=1
            else: raise
    print(f"Errors: {n_errors}")
    
    
if __name__ == '__main__':
    main()

