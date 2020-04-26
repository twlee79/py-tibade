py-tibade: Python Titanium Backup Decrypt
-----------------------------------------
Author: Tet Woo Lee

This is a Python/[pycryptodome]-based implementation of [TitaniumBackupDecrypt],
which was originally authored by Brian T. Hafer. It will decrypt backups made 
by [Titanium Backup for Android].

[pycryptodome]: https://www.pycryptodome.org/en/latest/
[TitaniumBackupDecrypt]: https://github.com/bhafer/TitaniumBackupDecrypt
[Titanium Backup for Android]: https://www.titaniumtrack.com/titanium-backup.html

An alternative Python implementation is is [TiBUdecrypter](https://github.com/phyber/TiBUdecrypter)
created by David O'Rourke.

## Installation

This is available on both PyPi:
```
pip install pytibade
pytibade --version
```

and conda:
```
conda create -n pytibade -c twlee79 pytibade
cona activate pytibade
pytibade --version
```

## Usage
```
positional arguments:
  inputfiles            Input file(s), either a list of filenames or as an
                        unexpanded glob wildcards that is expanded internally

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -s SUFFIX, --suffix SUFFIX
                        Suffix to add to base filename of decrypted files,
                        appended to stem before any extensions (default:
                        -decrypted)
  -m MATCH_BASENAME, --match_basename MATCH_BASENAME
                        Regular expression to match base filename of a file,
                        applied to filename without directory; first capturing
                        group should be base filename; an error is produced if
                        files don't match this pattern, which can be ignored
                        with the `-c` option (default:
                        (^.*-[0-9\-]+)[.]([a-z]{3})([.a-z]{0,4}))
  -p PASSPHRASE, --passphrase PASSPHRASE
                        Passphrase used to encrypt the backup files, if not
                        present then user will be prompted to enter one; same
                        passphrase used for all files. (default: None)
  -c, --continue        Continue processing next file even if error
                        encountered; by default script will stop on first
                        error (default: False)
  -v, --verbose         Increase logging verbosity, available levels 1 to 3
                        with `-v` to `-vvv` (default: 0)
```

Simplest usage: `pytibade com.my.favourite.app-20200426-111127.tar.gz`

The script will then prompt for the passphrase. 

The script can be used to decrypt a batch of files by specifying multiple 
`inputfiles` or wildcards in `inputfiles`. The same `passphrase` is used 
for all files. The `--continue` option is useful to persistently attempt to 
decrypt all specified files despite earlier failures (useful, for example, if 
there is a mixture of encrypted and unencrypted files).


## Titanium Backup File Format

### Information Source

This information was originally taken from a post on Christian Egger's G+ page
[that has now disappeared](https://plus.google.com/+ChristianEgger/posts/MQBmYhKDex5).
It has been reformatted a little for markdown by [David O'Rourke](https://github.com/phyber/TiBUdecrypter/blob/master/docs/FORMAT.md).

### File Format

```
"TB_ARMOR_V1" '\n'
pass_hmac_key '\n'
pass_hmac_result '\n'
public_key '\n'
enc_privkey_spec '\n'
enc_sesskey_spec '\n'
data
```

### Explanation of format

Each of the 5 "variables" (`pass_hmac_key`, `pass_hmac_result`,
`public_key`, `enc_privkey_spec`, `enc_sesskey_spec`) is stored in
Base64 format without linewraps (of course) and can be decoded with:
`Base64.decode(pass_hmac_key, Base64.NO_WRAP)`

Then the user-supplied passphrase (`String`) can be verified as follows:

```
Mac mac = Mac.getInstance("HmacSHA1");
mac.init(new SecretKeySpec(pass_hmac_key, "HmacSHA1"));
byte[] sigBytes = mac.doFinal(passphrase.getBytes("UTF-8"));
boolean passphraseMatches = Arrays.equals(sigBytes, pass_hmac_result);
```

Then the passphrase is independently hashed with SHA-1. We append [twelve] `0x00` 
bytes to the 160-bit result to constitute the 256-bit AES key which is used to
decrypt `enc_privkey_spec` (with an IV of [sixteen] `0x00` bytes). [Decrypt 
using AES-256 in CBC mode and perform PKCS7 unpadding with block size 16.]

Then we build the KeyPair object as follows:

```
KeyFactory keyFactory = KeyFactory.getInstance("RSA");
PrivateKey privateKey2 = keyFactory.generatePrivate(
    new PKCS8EncodedKeySpec(privateKey)
);
PublicKey public_key2 = keyFactory.generatePublic(
    new X509EncodedKeySpec(public_key)
);
KeyPair keyPair = new KeyPair(public_key2, privateKey2);
```

Then we decrypt the session key as follows:

```
Cipher rsaDecrypt = Cipher.getInstance("RSA/NONE/PKCS1Padding");
rsaDecrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
ByteArrayOutputStream baos = new ByteArrayOutputStream();
CipherOutputStream cos = new CipherOutputStream(baos, rsaDecrypt);
cos.write(enc_sesskey_spec); cos.close();
byte[] sessionKey = baos.toByteArray();
```

And finally, we decrypt the data itself with the session key (which can be
either a 128-bit, 192-bit or 256-bit key) and with a `0x00` IV. [Remember
to PKCS7 unpad with block size 16].

While the "zero" IV is suboptimal from a security standpoint, it allows
files to be encoded faster - because every little bit counts, especially
when we store backups with LZO compression.

-------------------------------------------------------------------------------

Author        |Tet Woo Lee
--------------|----------------------------
Created       | 2020-04-26
Copyright     | © 2020 Tet Woo Lee
License       | GPLv3
Dependencies  | pycryptodome, tested with v3.8.2

### Change log

+ version 1.0.dev1 2020-04-26  
  Working version

