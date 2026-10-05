# Copy Shelter Repository Format: Versions 1 and 2

**Status:** Normative. This document is written to be published verbatim (D-007).
**Audience:** implementers of Copy Shelter, and anyone writing an independent reader.

If it is on disk, it is described here. There are no undocumented fields, no reserved-for-internal-use
regions, and no behavior that depends on state outside the repository.

Keywords MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

---

## 1. Design constraints

The format exists to satisfy six properties. Every decision below traces to one of them.

| P1 | An interrupted write MUST NOT produce an object that appears valid. |
| P2 | A repository MUST be fully recoverable using only its own contents plus a key. |
| P3 | Replication MUST reduce to "copy the objects the target lacks", in any order, resumably. |
| P4 | Deleting one snapshot MUST NOT invalidate any other retained snapshot. |
| P5 | The destination holder MUST NOT learn filenames, paths, sizes of individual files, or content. |
| P6 | The format MUST tolerate destinations that are slow, case-insensitive, eventually consistent, and hostile to many small files. |

---

## 2. Layout

```
<repository-root>/
    copyshelter.repo                     plaintext, ~1 KB
    keys/
        <keyID>.key                      wrapped master key, one per unwrap path
    packs/
        <first-2-hex>/<pack-id>.pack     immutable, 32-64 MB target
    index/
        <index-id>.idx                   immutable
    snapshots/
        <snapshot-id>.snap               immutable
    refs/
        head                             mutable, signed
        retention                        mutable, signed; absent until chosen
    replicas/
        <replica-id>.state               mutable, signed
    gc/
        <run-id>.mark                    mutable, signed
    holds/
        <hold-id>.hold                   mutable, signed
    locks/
        <lock-id>.lock                   ephemeral
    devices/
        <device-id>.status               mutable, signed
    tmp/
        <uuid>                           scratch; deleted on open
```

Every filename is a hexadecimal identifier or a fixed literal. **No user-derived string ever appears in
a path** (P5).

`packs/` is sharded by the first two hex characters of the pack ID, giving 256 directories, so no
directory exceeds a few thousand entries on realistic repositories. This matters on SMB and File Provider (P6).

### 2.1 In object storage

The same layout, as object keys. There are no directories in a bucket, so every
path above becomes the key itself, joined with `/`, under an optional prefix:

```
<prefix>/copyshelter.repo
<prefix>/packs/<first-2-hex>/<pack-id>.pack
<prefix>/refs/head
```

With no prefix the keys start at `copyshelter.repo`. A prefix lets one bucket
hold more than one repository; it is an ordinary key prefix and nothing else,
and a trailing slash on it means the same place as none.

Two properties the layout relies on are not free in a bucket and are stated
here because a reader has to know which:

- **Listing is by prefix.** Where a filesystem reader lists a directory, an
  object reader lists keys beginning with that prefix and treats the next `/`
  as the boundary. The sharding in `packs/` is the same shape either way.
- **There is no atomic rename.** `refs/head` is written by overwriting the key.
  The rollback counter in §10 is what makes that safe to read, and it is the reason the counter exists.

This section exists because the document described a filesystem and Copy
Shelter writes to buckets, and somebody rebuilding a reader from it for a
backup with no drive had to guess at both of those (F-729).

---

## 3. `copyshelter.repo`

The only plaintext file. It contains public parameters required to *attempt* decryption; it contains
no secrets.

```json
{
  "magic": "copyshelter-repository",
  "formatVersion": 2,
  "repositoryID": "1HQ702Et94FXRv7oucFuqjKXHvYpXUYPovlrUyFZK9Y=",
  "createdAt": "2026-09-01T14:22:31.000Z",
  "createdBy": "CopyShelter/1.0 (26.5.0)",
  "cipher": "ChaCha20-Poly1305",
  "chunker": {
      "algorithm": "FastCDC",
      "minSize": 524288,
      "avgSize": 1048576,
      "maxSize": 4194304,
      "normalization": 2
  },
  "hash": "SHA-256",
  "blobID": "HMAC-SHA256",
  "signature": "Ed25519",
  "packTargetSize": 67108864
}
```

`repositoryID` is **base64 of the 32 raw bytes**, not hex. Those 32 raw bytes, decoded, are what
every derivation below uses as its HKDF salt. This document said "32 hex bytes" until an independent
reader was written against it and failed on the first field it needed.

Keys are sorted alphabetically and timestamps carry milliseconds, because this file is written with a
canonical encoder so that two implementations produce identical bytes.

There is a `kdf` block **only where a passphrase key file exists**, and only that unwrap path reads
it:

```json
"kdf": { "algorithm": "PBKDF2-HMAC-SHA256", "salt": "base64, 16 bytes", "iterations": 600000 }
```

A writer MUST emit it when it writes a `passphrase` key file and MUST NOT emit it otherwise. A reader
MUST NOT require one: a repository without it simply has no passphrase path, which is true of every
repository written before this section existed, and those MUST keep opening. A reader offered a
passphrase for a repository with no `kdf` block MUST say that none is set, and MUST NOT report a wrong passphrase for one that was never chosen.

The salt is per repository, not per key file, because two people choosing the same passphrase
for two different backups must not derive the same wrapping key, and because a reader has to find it
before it has opened anything.

**Why PBKDF2 and not Argon2id.** Earlier drafts of this document specified Argon2id, and Argon2id is
the better primitive: it costs an attacker memory as well as time, which is what defeats the GPU
farms that make offline passphrase cracking cheap. It is not used, and the reason is the first
promise this format makes. That promise is that somebody can open a backup with nothing but this
document and a machine. Argon2id is roughly five hundred lines of subtle code that is dangerous to
get wrong, and requiring it puts that on every independent reader in every language.
PBKDF2-HMAC-SHA256 is in every standard library and is a dozen lines from RFC 8018. The cost is real
and is paid down elsewhere: the iteration count is high, and a writer MUST refuse a passphrase
shorter than 12 characters, below which the difference between the two primitives is not what saves
anybody. The recovery key remains 200 bits, so the ceiling for anyone who uses it is unchanged.

A passphrase MUST be normalized to NFC before derivation. The same passphrase typed on two keyboards
is otherwise two different byte sequences, and only one of them would ever open the backup.

A reader MUST refuse to operate on a `formatVersion` it does not understand. A reader MUST NOT trust
any value here to be authentic: this file is unauthenticated by necessity, since it describes how to
derive the keys that would authenticate it. Tampering with it can only cause key derivation to fail,
never to succeed with a wrong key: every subsequent object is AEAD-authenticated.

---

## 4. Keys

### 4.1 Derivation

```
masterKey            := 32 cryptographically random bytes, generated once per repository

dedupKey             := HKDF-SHA256(ikm: masterKey, salt: repositoryID, info: "copyshelter.v1.dedup",  L: 32)
objectKeyRoot        := HKDF-SHA256(ikm: masterKey, salt: repositoryID, info: "copyshelter.v1.object", L: 32)
signingSeed          := HKDF-SHA256(ikm: masterKey, salt: repositoryID, info: "copyshelter.v1.sign",   L: 32)
metadataKey          := HKDF-SHA256(ikm: masterKey, salt: repositoryID, info: "copyshelter.v1.meta",   L: 32)

signingKey           := Ed25519 private key seeded with signingSeed
```

`masterKey` MUST NOT be stored anywhere in plaintext, including logs, crash reports and diagnostics.

### 4.2 `keys/<keyID>.key`

One file per unwrap path. `keyID` = first 16 bytes of `SHA-256(wrappingParameters)`, hex.

```json
{
  "keyID": "d9150c93124da8e969a47973763cc04d",
  "method": "recoveryKey" | "keychain" | "passphrase",
  "createdAt": "2026-09-01T14:22:31.000Z",
  "hint": "optional, user-supplied, MAY be empty",
  "nonce": "base64, 12 bytes",
  "wrapped": "base64, 48 bytes: the 32-byte masterKey sealed with ChaCha20-Poly1305, tag appended"
}
```

**The `method` string is the associated data.** The seal is

```
wrapped := ChaCha20-Poly1305.seal(masterKey, key: wrappingKey, nonce: nonce, aad: utf8(method))
```

so a key file cannot be relabelled from `recoveryKey` to `keychain` and offered to a different unwrap
path. This was missing from earlier drafts of this section, and without it every unwrap fails its
authentication tag with nothing to say why.

There is no separate `check` field. Earlier drafts described one, over the literal ASCII
`copyshelter-key-check`; nothing has ever written it. The AEAD tag on `wrapped` already answers the
only question a check field would: a wrong key fails to open it. A reader MUST NOT require a `check`
field and MUST NOT treat its absence as damage.

Wrapping key by method:

| Method | Wrapping key |
|---|---|
| `passphrase` | `PBKDF2-HMAC-SHA256(NFC(passphrase), kdf.salt, kdf.iterations, L: 32)` |
| `recoveryKey` | `HKDF-SHA256(ikm: recoveryKeyBytes, salt: repositoryID, info: "copyshelter.v1.recovery", L: 32)` |
| `keychain` | 32 random bytes stored in the macOS Keychain, referenced by `keyID` |

A repository MUST have at least two key files at all times, and MUST have at least one that is not
`keychain`. Implementations MUST refuse to delete the last non-`keychain` key file.

### 4.3 Recovery key encoding

`recoveryKeyBytes` is **25 random bytes (200 bits)**, not 16. This is deliberate, not a rounding
error: 200 bits is exactly 40 Crockford Base32 characters (200 / 5 = 40) with nothing left over, so
the encoding below is a straight bijection. There is no padding bit, no derived filler, and nothing
implementation-defined. An earlier draft of this section specified 128 bits rendered as 40
characters, which is inconsistent (128 bits needs only 26 Crockford characters) and was caught
during CS-031: it could not have been implemented interoperably as written. 200 bits costs nothing
extra to generate or store and removes the ambiguity entirely.

**Alphabet.** Crockford Base32, no `I`, `L`, `O`, `U`:

```
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

**Encoding (data characters).** Read the 25 bytes as a single 200-bit big-endian integer. Starting
from the most significant bit, take 5 bits at a time and map each 5-bit value through the alphabet
above by index. This produces exactly 40 characters, grouped for display as 8 groups of 5. Decoding
is the exact inverse: concatenate the bits each character represents, most significant character
first, and read the result back out as 25 bytes.

**Checksum (group 9).** Let `data` be the 40 characters above, upper case, with no hyphens.

```
mac      := HMAC-SHA256(key: literal "copyshelter.v1.rkcheck", message: data)   // 32 bytes
checkBits:= mac[0], mac[1], mac[2]                                              // first 3 bytes, 24 bits
```

24 bits is one bit short of the 25 bits five Crockford characters hold. Append a single `0` bit at
the least significant end (standard base32 tail padding) to make 25 bits, then split those 25 bits
into 5 groups of 5 bits, most significant first, and map each through the alphabet. That is group 9.

**Normalization on input.** Decoding MUST accept lower case, and MUST map `I` and `L` (either case)
to `1`, and `O` (either case) to `0`. Hyphens and any whitespace are ignored, in any position.

**Validation order.** A reader MUST validate the checksum before attempting Argon2/HKDF, so a
mistyped key produces "that key is mistyped" and never "wrong key".

**Worked example**, so an independent implementation can check itself byte-for-byte:

```
input (25 bytes, hex):
  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18

data characters (40):
  000G40R40M30E209185GR38E1W8124GK2GAHC5RR

checksum (group 9, 5 characters):
  7X3W6

formatted (45 characters, 9 groups of 5):
  000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-7X3W6
```

A reader that decodes `000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR` back to bytes MUST get the
25-byte input above exactly, and MUST compute `7X3W6` as the checksum over the 40 data characters.

---

## 4.4 Timestamps

Every timestamp in a repository is ISO 8601 with fractional seconds, in UTC, and carries
**millisecond precision**. For example `2026-09-01T14:22:31.482Z`.

Implementations MUST round a timestamp to milliseconds before writing it. This is stated explicitly because a value taken straight from a system clock has finer precision than the
encoding, so writing it unrounded makes a record that is not equal to itself after a round trip.
Nothing fails when that happens: timestamps simply drift by microseconds between memory and disk,
and comparisons quietly start lying.

## 5. Blobs

A **blob** is the unit of deduplication. Every blob has a type and an ID.

```
blobID := HMAC-SHA256(key: dedupKey, message: plaintext)        // 32 bytes
```

Keying the hash with a per-repository secret means a party holding the repository but not the key
cannot test whether a known file is present (P5).

| Blob type | Contents |
|---|---|
| `0x01 data` | A chunk of file content produced by the chunker |
| `0x02 tree` | A directory object (§7) |
| `0x03 meta` | Reserved. Format versions 1 and 2 store every `xattrs` value and `acl` inline in the tree entry (§7), with no size limit other than the field's own u32 length prefix. Nothing in format version 1 produces a `0x03` blob; a future version MAY use it to spill oversized metadata out of a tree entry, which would be a new `formatVersion`, not a change to existing objects. |

### 5.1 Blob encryption

```
objectKey := HKDF-SHA256(ikm: objectKeyRoot, salt: blobID, info: "copyshelter.v1.blob", L: 32)
stored    := the framed, possibly compressed plaintext (§7a)
```

**Format version 2** keeps the nonce in front of the ciphertext:

```
nonceKey  := HKDF-SHA256(ikm: objectKeyRoot, salt: blobID, info: "copyshelter.v2.blobnonce", L: 32)
nonce     := first 12 bytes of HMAC-SHA256(nonceKey, stored)
sealed    := nonce || ChaCha20-Poly1305.seal(stored, key: objectKey, nonce: nonce, aad: blobID || blobType)
```

**Format version 1** uses a fixed nonce and stores none:

```
nonce     := 12 zero bytes
sealed    := ChaCha20-Poly1305.seal(stored, key: objectKey, nonce: nonce, aad: blobID || blobType)
```

A pack directory's `length` covers the whole of `sealed`, nonce included. A reader takes the layout from
`formatVersion` in `copyshelter.repo`; it never has to guess per blob.

Both give identical stored bytes identical sealed bytes, which deduplication requires. They differ when
one blob is stored as different bytes, because compression happens inside the seal. Under version 1, two
writers compressing one blob differently seal two messages under one key and one nonce, which exposes the
difference between them and lets a party holding both forge a third that the tag accepts. Under version 2
different stored bytes get different nonces. The nonce is computed under a key only the repository's owner
holds, so it reveals nothing about the content.

A writer to a version 1 repository MUST produce exactly the stored bytes §7a defines for every blob, because
that repository stays at version 1 (§17) and its safety depends on it.

In both versions a reader MUST recompute `blobID` from the opened plaintext and refuse a blob whose
identity does not match, exactly as it refuses a blob whose tag does not verify. The key is derived from the
identity, so the tag alone only proves the sealer held that key; the recomputed identity proves the
content.

Implementations MUST include `blobID || blobType` as associated data, so a blob cannot be relabelled
or substituted for another.

---

## 6. Pack files

A pack is an immutable concatenation of sealed blobs plus a sealed directory.

```
offset 0                                                        
┌────────────────────────────────────────────────────────────────────┐
│ HEADER          8 bytes   "CSPK" 0x01 0x00 0x00 0x00               │
├────────────────────────────────────────────────────────────────────┤
│ BLOB 0          sealed bytes                                       │
│ BLOB 1          sealed bytes                                       │
│ ...                                                                │
├────────────────────────────────────────────────────────────────────┤
│ DIRECTORY       sealed with metadataKey; a packed array of fixed   │
│                 size records, 45 bytes each:                       │
│                   blobID(32) type(u8) offset(u64 LE) length(u32 LE)│
│                 preceded by a u32 LE record count                  │
├────────────────────────────────────────────────────────────────────┤
│ TRAILER        12 bytes   directoryLength(u32 LE)                  │
│                           "CSPKEND" 0x00                           │
└────────────────────────────────────────────────────────────────────┘

packID := hex( SHA-256( all bytes of the file ) )
filename := packs/<packID[0..2]>/<packID>.pack
```

**A pack is self-verifying.** Its name is the hash of its own contents, so a truncated or corrupted
pack can never be mistaken for a valid one (P1). A reader MUST verify the pack hash before trusting
its directory, except during streaming restore where it MUST verify each blob's AEAD tag instead and
MUST verify the whole-file hash before reporting the pack as verified.

Packs SHOULD target 64 MB and MUST NOT exceed 256 MB. A pack MAY be smaller when a backup run ends.

The directory is sealed with `metadataKey` and a random 12-byte nonce stored in the first 12 bytes of
the sealed directory region, because directory plaintext is not content-addressed.

The directory is a packed array of fixed size records. A self describing encoding such as CBOR was not used. Every field is a fixed width integer or a fixed length identifier, so a self describing
encoding would add a parser and a dependency while describing nothing a reader does not already
know from this document. Tree objects (§7) use the same reasoning and the same style of encoding,
with a per-entry presence bitmap standing in for the optional fields a fixed size record cannot
express.

A reader MUST refuse a directory whose declared record count does not match the region length
exactly, and MUST refuse any record whose `offset + length` falls outside the blob region. A
directory pointing outside the pack is corruption and must be rejected before anything reads there.

---

## 7. Tree objects

A tree is a `0x02` blob describing one directory: a flat list of entries, one per child. It is
**packed binary with a per-entry field-presence bitmap, not CBOR.**

Every other self-describing decision in this document (§6) exists to preserve unknown keys across a
rewrite. Trees never rewrite: they are content addressed, so an entry with a changed field produces a
different blob under a different ID, not the same object edited in place. There is therefore nothing
for a self-describing encoding to protect here, and it would only add a parser and a dependency to
describe fields already fixed by this document. A future field addition bumps `formatVersion` (§17)
and does not rely on unknown-key preservation. Every field below is a fixed width integer or a
length-prefixed byte run, exactly like the pack directory (§6) and the index file (§8).

All integers are little endian.

```
u32 entryCount
per entry:
  u16 presenceBitmap    which optional fields follow, see the bitmap table below
  u8  entryType         1 file, 2 dir, 3 symlink, 4 fifo, 5 socket, 6 char, 7 block
  u8  status            0 ok, 1 unstable (changed during read), 2 unreadable
  u16 nameLength, then that many RAW name bytes
  u32 mode              POSIX mode bits
  u32 uid               uid as recorded
  u32 gid               gid as recorded
  i64 mtimeSeconds, u32 mtimeNanoseconds
  i64 ctimeSeconds, u32 ctimeNanoseconds
  then, only where the matching presence bit is set, in this fixed order:
    birthtime      i64 seconds + u32 nanoseconds
    size           u64                   logical size in bytes
    bsdFlags       u32                   BSD st_flags (UF_HIDDEN, UF_IMMUTABLE, ...)
    userName       u16 length + bytes    UTF-8 text; for cross-machine remapping
    groupName      u16 length + bytes    UTF-8 text
    symlinkTarget  u16 length + RAW bytes
    hardlinkGroup  u64                   hard-link group id, snapshot-local
    xattrs         u16 count, then per xattr:
                     u16 nameLength + name bytes
                     u32 valueLength + value bytes
    acl            u32 length + bytes    NFSv4 ACL text form, from acl_to_text
    sparseRanges   u16 count, then per range: u64 offset + u64 length
    contentBlobs   u32 count, then that many 32 byte blob identities, in order
    childTree      32 byte blob identity
```

**Presence bitmap.** Bit order and field order are the same thing on purpose: a reader never has to
jump around to know what comes next. Bit 0 is the least significant bit.

| Bit | Field |
|---|---|
| 0 | birthtime |
| 1 | size |
| 2 | bsdFlags |
| 3 | userName |
| 4 | groupName |
| 5 | symlinkTarget |
| 6 | hardlinkGroup |
| 7 | xattrs |
| 8 | acl |
| 9 | sparseRanges |
| 10 | contentBlobs |
| 11 | childTree |

Bits 12 through 15 are unused by format versions 1 and 2. A reader MUST ignore unset bits it does not
recognize only insofar as these versions define no such bits; in practice this means bits 12-15
MUST be zero when writing, and a reader of either version has nothing else to skip, because there is
no unknown-field region left to preserve the way there would be in a self-describing encoding. A
version that adds a field defines a new bit and a new `formatVersion`, per §17.

Notes that matter:

- **`name` and `symlinkTarget` are raw bytes, never text.** macOS stores NFD-normalised UTF-8 on
  HFS+/APFS; other filesystems do not, and some filenames are not valid UTF-8 at all. Copy Shelter
  stores exactly what the filesystem returned and restores exactly those bytes. It MUST NOT normalize,
  because normalizing is lossy and irreversible. `userName` and `groupName` are the one text field in
  an entry: they are POSIX account names used only for cross-machine remapping, never filesystem
  paths, so UTF-8 text is the right representation for them.
- **`hardlinkGroup`** groups hard links within a snapshot. On restore, the first occurrence is
  materialised and subsequent occurrences are linked to it. Hard links spanning outside the backup set
  cannot be preserved; they are restored as independent files and reported.
- **`status: 1` (unstable)** means the file changed while being read and Copy Shelter could not obtain
  a consistent copy after 3 attempts. The content stored is the last read attempt. This MUST be
  surfaced in the UI and MUST NOT be reported as a clean backup.
- **`acl`** is the NFSv4 ACL text form produced by `acl_to_text`. On restore to a different machine,
  entries referencing unresolvable principals are dropped and reported, and the rest of the file still reads.
- Compressed files (`com.apple.decmpfs`): content is stored **decompressed**. The compression xattr is
  not preserved. Restored files are functionally identical and occupy more space.
- An xattr with a zero-length value is not the same as the xattr being absent: the former is an entry
  in the `xattrs` list with `valueLength == 0`; the latter never appears in the list at all. The same
  distinction holds one level up: `presenceBitmap` bit 7 set with `xattrs` count 0 (the field is
  present, the directory has no xattrs to report) differs from bit 7 unset (the field was not
  captured).
- A reader MUST bounds-check every length and count field against the bytes remaining in the blob
  before using it to read further, and MUST refuse the object. It MUST NOT read out of range or return a partially decoded result. A truncated or corrupted tree is corruption, not a smaller tree.
- **Windows entries** (F-1020) write these same fields honestly, never a fabricated POSIX value:
  - `mode` carries only the one real, OS-enforced fact Windows has that corresponds to a POSIX write
    bit, `FILE_ATTRIBUTE_READONLY` (`0o444`/`0o555` when set, `0o644`/`0o755` otherwise, owner, group
    and other identical since Windows draws no such distinction). Restoring this mode onto POSIX
    applies it like any other captured mode; restoring a POSIX mode onto Windows applies only its
    write bit back through `SetFileAttributesW`.
  - `uid`/`gid` are always `0`. `userName` carries the owning account's display name
    (`DOMAIN\User`) for cross-machine remapping, the same role it plays for a POSIX capture;
    `groupName` is `nil`.
  - `acl` is always absent: Windows' DACL/SACL security-descriptor model is not the NFSv4 ACL text
    this field stores, and no translation between the two is attempted. Restoring a POSIX entry's real
    ACL onto Windows reports it unpreserved, the same shape already used when a Linux restore cannot
    apply one.
  - `bsdFlags` is always absent: Windows has no BSD file flags, and its own hidden/system/archive
    attribute bits are not the same bit positions as `UF_HIDDEN`/`UF_IMMUTABLE`, so they are never
    written into this field (doing so would apply the wrong flag if that same entry were later restored
    onto a Mac). They travel through `xattrs` instead, see below.
  - `xattrs` carries two Windows-specific record shapes, both ordinary xattr entries with no format
    change: a name of `windows:file-attributes` and a 4-byte little-endian value holds the raw
    `dwFileAttributes` bitmask (hidden/system/archive/read-only), applied back via
    `SetFileAttributesW` on a Windows restore; a name of `windows-ads:<stream name>` holds one
    alternate data stream's bytes verbatim, up to a fixed size cap, applied back as a real named stream
    on a Windows restore. Restoring either on a non-Windows machine writes an ordinary, harmless,
    self-describing xattr under that literal name. A stream over the cap is left out of capture
    entirely, the same best-effort policy an ordinary POSIX xattr that fails to read already has.

---

### 7a. Blob compression

Every blob is compressed before it is encrypted, and the result is stored as:

```
[method: 1 byte][original size: 8 bytes, little endian][payload]
```

That whole structure is what gets sealed, so the marker and the size are covered
by the same authentication tag as the content and cannot be altered
independently.

`method` is `0` for stored as-is and `1` for LZFSE. A reader MUST refuse a blob
whose method it does not recognize, and MUST NOT return the payload unchanged.

**Order.** Compression happens before encryption because that is the only order
that achieves anything: ciphertext is indistinguishable from random and does not
compress. **Identity** is still the keyed hash of the ORIGINAL plaintext, so
deduplication is unaffected and two implementations that make different
compression choices still agree on what a blob is.

**A blob is only stored compressed if it shrank by at least 10%.** Marginal wins
are not worth decompressing on every read for the rest of the backup's life, and
refusing them keeps already-compressed media on the fast path. Blobs under 1 KiB
are not attempted at all.

**A writer may decline to attempt compression at all.** This implementation
compresses a 64 KiB sample, spread across the blob as 128 windows, not taken from one place, and skips the full attempt when the sample saves less than
5%. That is a writer's choice about how to spend its own time and it changes
nothing a reader has to do: the method byte says what happened, and a blob
stored uncompressed is read the same way whether that was because compression
did not help or because it was never tried. Two writers that make different
choices here still agree on every blob's identity, because identity is taken
over the original plaintext.

**The original size is recorded, not inferred.** `compression_decode_buffer` and
its equivalents fill whatever buffer they are given and return a non-zero count
when the output did not fit, so a reader that grows a buffer until the call
"succeeds" never grows and returns a truncated file that looks whole. A reader
MUST decode into a buffer of exactly the recorded size and MUST refuse the blob
if the number of bytes produced differs.

**What compressing before encrypting costs.** The size of a stored blob reveals
something about its plaintext: compressible data produces smaller blobs. Against
somebody holding a stolen drive this is a weak signal, roughly "this chunk was text, not a photo". It becomes a real attack only where an adversary can
inject chosen content and observe the resulting size, which is the CRIME class of
attack against TLS and does not apply to a backup: nobody is choosing what goes
into somebody's Documents folder and then measuring their drive. The trade is stated here explicitly.

**Measured.** On a mixed corpus of source code and prose, 11.2 MB of files
stored in a 4.9 MB repository. On photographs it saves nothing, which is expected and is why the attempt is abandoned.

---

## 8. Index files

```
index/<indexID>.idx      indexID := random UUIDv4, hex without hyphens
```

Sealed with `metadataKey`, random nonce in the first 12 bytes. Plaintext is **packed binary**, in the
same style as the pack directory (§6) and for the same reason: every field is fixed width, so a
self-describing encoding would add a parser and a dependency while describing nothing this document
does not already fix. All integers are little endian.

```
u32 sectionCount
per section:
  packID(32)
  u32 entryCount
  per entry:
    blobID(32) type(u8) offset(u64) length(u32)      // 45 bytes, exactly as in §6
```

Earlier drafts of this section said CBOR. Nothing has ever written CBOR here. The 45-byte record is
byte-identical to the pack directory record, which is the point: an implementation reads one record
shape whether it is rebuilding from packs or loading an index.

Index files are **immutable and additive**. A reader loads all of them and merges. Duplicate blobIDs
across index files are permitted and MUST resolve to any one of the entries: they are byte-identical
by construction.

Index files are a **cache derivable from the packs themselves.** An implementation MUST be able to
rebuild the entire index by reading every pack directory, and MUST do so automatically when the index
is missing, unreadable, or inconsistent. This is what makes P2 hold even after catastrophic partial loss.

Index compaction: write a new merged index file, flush it to stable media, then delete the superseded ones. Safe in any
crash ordering, because deleting an index never loses data.

**Before a pack is deleted, every index entry naming it MUST be gone.** In that
order, and never the other way round.

The index is what a writer consults to decide a blob is already stored. An index
naming a pack that no longer exists will tell the next backup that a blob is
present when it is not, so that backup writes nothing, and commits a snapshot
referencing bytes that are not there. It reports success and cannot be restored,
and no reader can detect it until somebody tries to get the file back.

The rebuild path does not save an implementation from this. It runs when the
index is missing or unreadable, and an index that is merely wrong is neither: it
loads cleanly and lies. So the compaction above is not an optimization to
perform when convenient. It is the step that has to happen first.

Written down because this implementation had the bug and shipping the document
without the rule would hand it to the next one. It was found by interleaving a
backup after a prune, which is a sequence no test here had ever run.

---

## 9. Snapshot objects

```
snapshots/<snapshotID>.snap      snapshotID := random UUIDv4, hex without hyphens
```

Layout:

```
┌──────────────────────────────────────────────────────┐
│ nonce            12 bytes                            │
│ sealed payload   ChaCha20-Poly1305 with metadataKey  │
│ signature        64 bytes, Ed25519 over (nonce||sealed)│
└──────────────────────────────────────────────────────┘
```

`snapshotID` is a UUID. It appears **with hyphens** inside `refs/head` and inside the payload, and
**without hyphens, lower case** in the filename. A reader MUST strip hyphens when turning an
identifier into a path.

Payload (**JSON**, keys sorted, UTF-8, no trailing newline):

```
{
  "v": 1,
  "id": snapshotID,
  "counter": u64,                  // strictly increasing per repository
  "deviceID": bytes(16),
  "deviceName": text,
  "parent": snapshotID or null,
  "createdAt": "2026-09-01T14:22:31Z",
  "hostPlatform": "macOS 26.1",
  "appVersion": "1.0.0",
  "sources": [ { "path": bytes, "kind": "folder"|"wholeMac"|"photos"|"mobileSync" } ],
  "rootTree": blobID,
  "excludeRules": [ text ],           // absent in snapshots written before 1.0;
                                      // absent and empty mean different things
  "stats": { "files": u64, "dirs": u64, "bytesLogical": u64, "bytesNew": u64,
             "bytesDeduped": u64, "unstableFiles": u64, "unreadableFiles": u64 },
  "flags": [ "anomalyDetected", "partial", "inconsistentSource", ... ],
  "anomaly": { "signals": [...], "detectedAt": "..." }        // present iff flagged
}
```

Every field holding raw bytes, including `rootTree` and `deviceID`, is **base64**. Earlier drafts of
this section said CBOR; nothing has ever written CBOR here, and an implementer following it decoded
the first byte as a CBOR major type and stopped.

A snapshot is written **only after every blob it transitively references has been durably committed**
(P1, P3). A reader encountering a snapshot referencing a missing blob MUST report the repository as
damaged and MUST identify the affected files. It MUST NOT silently restore a truncated tree.

---

## 10. `refs/head`

The only frequently-mutated file in the repository.

```
┌──────────────────────────────────────────────────────┐
│ nonce            12 bytes                            │
│ sealed payload   ChaCha20-Poly1305 with metadataKey  │
│ signature        64 bytes, Ed25519                   │
└──────────────────────────────────────────────────────┘

payload = JSON, keys sorted, UTF-8:
{
  "counter": u64,                    // max snapshot counter ever committed
  "snapshots": [ snapshotID ],       // the authoritative set, in commit order, hyphenated UUIDs
  "updatedAt": "...",
  "writerDeviceID": base64 of 16 bytes
}
```

JSON, not CBOR, for the same reason as §9: it is what is written. The signature covers
`nonce || sealed`, and the sealed payload has no associated data.

### Rollback protection
A client MUST persist, per destination, the highest `counter` it has ever observed. On open:

- observed `counter` **>** remembered → normal, update the remembered value.
- observed `counter` **==** remembered → normal.
- observed `counter` **<** remembered → **rollback suspected.** The destination is marked `Degraded`,
  the user is alerted, and no pruning may run against it. Backups may continue.

A client SHOULD additionally compare counters across destinations of the same repository and flag
divergence.

`refs/head` is written with the standard write protocol (§11). A crash mid-update leaves the previous
`refs/head` intact; the new snapshot exists on disk but is not yet referenced, and is collected as
garbage on a later prune. Data is never lost by this ordering: only invisible for a moment.

---

## 11. Write protocol (normative)

Every write to a repository, without exception:

```
1. create  tmp/<uuid>
2. write   the complete contents
3. F_FULLFSYNC the file descriptor (see note below)
4. rename  tmp/<uuid> → final path
5. F_FULLFSYNC the containing directory

> **Why F_FULLFSYNC and not fsync.** On macOS, `fsync` hands the data to the
> drive and returns. The drive may keep it in its own volatile cache and lose it
> on power loss, and Apple documents `F_FULLFSYNC` as the only request for
> stable media. Every ordering guarantee in this format assumes that a pack
> genuinely survives before an index or a snapshot refers to it; with `fsync`
> alone, a power cut can produce a repository whose contents point at bytes that
> were never written. Implementations of this format must use `F_FULLFSYNC` on
> macOS, or the equivalent elsewhere, and may fall back to `fsync` only where a
> filesystem refuses it outright.
>
> It costs. Measured on an Apple silicon SSD, sequential writes went from
> 949 MB/s to 201 MB/s. The first number was page cache speed and never
> represented anything reaching a disk.
```

For content-addressed files (`packs/`) the final path is derived from the completed bytes, so step 4
is what makes the object exist. A crash before step 4 leaves an orphan in `tmp/`, which is deleted on
next open. A crash between 4 and 5 may lose the rename on some filesystems, which is equivalent to a
crash before 4.

On destinations where `capabilities.durableFsync == false` (some SMB servers, all File Provider
volumes), step 3 and 5 are best-effort and the destination is marked as offering **weak durability**.
Such a destination MUST NOT be used as Primary without an explicit user acknowledgement, and its
objects MUST be re-verified by read-back after write.

---

## 12. Locking

```
locks/<lockID>.lock          lockID := random UUIDv4 hex
```

Plaintext-authenticated CBOR (sealed with `metadataKey`):

```
{ "v":1, "kind": "shared"|"exclusive", "deviceID": bytes(16), "pid": u32,
  "createdAt": "...", "refreshedAt": "...", "ttlSeconds": 300 }
```

- A holder refreshes `refreshedAt` every 60 s.
- A lock is **stale** when `now > refreshedAt + ttlSeconds`. Stale locks MAY be removed by any client.
- `exclusive` requires no other lock to exist. `shared` requires no `exclusive` lock to exist.
- Acquisition is: write the lock, re-list the directory, and confirm no conflicting lock appeared.
  On conflict, remove your own lock and back off with jitter. This is safe without atomic
  compare-and-swap because the only exclusive operation (prune) is never time-critical.

| Operation | Lock |
|---|---|
| Backup | shared |
| Replication | shared |
| Restore | shared |
| Verification | shared |
| Prune: mark | shared |
| Prune: sweep | **exclusive** |

Concurrent writers from *different devices* are outside the format's guarantees. Each device MUST use
its own repository (D-014).

---

## 13. Garbage collection marks

```
gc/<runID>.mark        sealed + signed, same envelope as snapshots
{ "v":1, "runID":..., "markedAt":"...", "candidates":[packID],
  "reachableDigest": SHA-256 over the sorted reachable blobID set,
  "retainedSnapshots":[snapshotID] }
```

Sweep MUST recompute the reachable set and MUST abort if `reachableDigest` differs. Sweep MUST NOT run
until at least 7 days after `markedAt`.

---

## 13a. Retention holds

```
holds/<hold-id>.hold        sealed + signed
{ "v":1, "id":..., "reason":"anomalyDetected"|"entitlementDowngrade"|"userRequested"|"verificationFailure",
  "note": text or null, "protectsSnapshotsBefore":"...", "createdAt":"...", "clearedAt":"..." or null }
```

A hold forbids pruning any snapshot created before `protectsSnapshotsBefore`, whatever the retention
policy says.

**Holds live in the repository, not on the machine that made them.** A hold is what stops a former
customer's history being deleted after their subscription ends. If it lived only in a local
database, reinstalling the application would lose it and the next prune would delete exactly what
the hold existed to defend.

A reader that does not recognize a `reason` MUST still honor the hold. Refusing to understand a
hold is not a reason to ignore it and delete data.

## 13b. Retention setting

```
refs/retention        sealed + signed
{ "v":1, "rule":"freeDefault"|"lastN"|"duration"|"smart"|"size",
  "count":n, "days":n, "hourly":n, "daily":n, "monthly":n, "yearly":n, "bytes":n }
```

Only the fields the rule uses are present. The file is absent until somebody chooses a rule, and a
repository without it is pruned by the free default.

`size` keeps the newest snapshots whose packs fit in `bytes`. Snapshots are counted newest first, and
each one adds the packs it needs that no newer snapshot already needs, because a sweep removes whole
packs and nothing smaller. Counting stops at the first snapshot that does not fit: the sizes after it
were measured with it kept, so they no longer say what keeping them would cost. The newest snapshot
and every held snapshot are kept whatever the budget says.

A reader that does not recognize `rule`, or finds a field the rule needs missing, MUST keep every
snapshot. So MUST a reader that finds the file and cannot open it. The free default prunes the most,
and not understanding a setting is no reason to delete history.

**The setting lives in the repository, like holds.** A new Mac, or a replica restored from after the
first drive is gone, prunes by the rule that was chosen, never by a default nobody picked.
Replication copies `holds/` and `refs/retention` on every run and overwrites, because both change.

## 14. Replica state

```
replicas/<replicaID>.state     sealed + signed
{ "v":1, "replicaID":..., "kind":"external"|"network"|"cloud"|"local",
  "label": text, "lastSyncAt":"...", "holdsSnapshots":[snapshotID],
  "holdsPacksDigest": SHA-256 over sorted packIDs held,
  "durability":"writtenLocally"|"believedUploaded"|"verified",
  "lastVerifiedAt":"..." }
```

Written to **each** destination, describing that destination, so a foreign machine can reconstruct the
replication picture from any single copy (P2).

---

## 15. Device status

```
devices/<deviceID>.status      sealed + signed
{ "v":1, "deviceID":..., "deviceName": text, "platform":"macOS"|"iOS"|"iPadOS",
  "appVersion":"1.0.0", "lastSnapshotID":..., "lastBackupAt":"...",
  "lastVerificationAt":"...", "repositoryHealth":"healthy"|"degraded"|"damaged",
  "bytesPending": u64, "destinationCount": u32 }
```

Deliberately minimal. It MUST NOT contain filenames, paths, source lists, or any content-derived value.

---

## 16. What the format protects, and what it leaks

| Protected from a party holding the destination | Leaked to that party |
|---|---|
| File contents | Total repository size |
| File and directory names | Number of snapshots and their approximate times (file mtimes) |
| Directory structure | Volume of change per backup |
| Individual file sizes | Pack count |
| Timestamps, xattrs, ACLs | Repository ID, format version, cipher and KDF parameters |
| Whether a specific known file is present (keyed blob IDs) | That Copy Shelter is in use |
| Device names, source paths | |

Pack sizes are held near a uniform target specifically to limit inference from size distribution.

**Not protected against:** an adversary who can delete files. Authentication detects tampering and
rollback; it cannot prevent destruction. See `04-THREAT-MODEL.md`.

---

## 17. Versioning and compatibility

- `formatVersion` is a single integer. Readers MUST refuse versions they do not implement.
- Copy Shelter MUST read every format version it has ever written, indefinitely.
- New repositories are made at the newest version Copy Shelter supports.
- A repository is never upgraded in place, so every writer to it writes the version it was made at.
  Migrating to a new format version means writing a new repository and copying the backups into it,
  with both readable throughout.
- Version 2 differs from version 1 only in how a blob's nonce is chosen and stored (§5.1). A reader of
  version 2 reads version 1 by taking the other branch there.
- Unknown CBOR keys in snapshots and replica state MUST be preserved on rewrite and ignored on read.
  Tree objects (§7) are exempt from this requirement: they are packed binary, not CBOR, and they are
  never rewritten. A field a reader does not recognize cannot occur within one `formatVersion`, because
  §7 defines every presence bit that version writes; a field addition is a new `formatVersion` instead.
  Unknown *blob types* MUST be preserved by replication and treated as opaque.

---

## 18. Minimum viable independent reader

An independent implementation needs, in order:

1. Read `copyshelter.repo`; check `formatVersion` is 1 or 2, which decides the blob layout in §5.1.
2. Read `keys/*.key`; unwrap `masterKey` with a passphrase or recovery key (§4).
3. Derive `dedupKey`, `objectKeyRoot`, `signingSeed`, `metadataKey`.
4. Read and verify `refs/head`; pick a snapshot.
5. Read the snapshot; verify signature; decrypt.
6. Load `index/*.idx`, or rebuild by scanning pack directories (§8).
7. Walk from `rootTree`, resolving blob IDs through the index to `(packID, offset, length)`.
8. Read, verify and decrypt each blob; concatenate content blobs in order.

Everything required is inside the repository. No network, no server, no original machine.

`csctl restore` is the reference implementation of exactly this algorithm and is published alongside
the specification.

**This document is checked against a real repository on every build.** `tools/independent-reader.py`
implements the algorithm above from this document alone, in another language, sharing no code with
the product, and `scripts/check-format-doc.sh` runs it against a repository the shipping app just
wrote. `csctl` could never have caught the errors that check found, because `csctl` is built from the
same source as the app and therefore only demonstrates that the code agrees with itself.

When it was first written, this document was wrong in seven ways that each stopped an independent
reader dead: `repositoryID` documented as hex and written as base64; a `check` field in the key file
that nothing writes; the key file's associated data undocumented; `refs/head`, snapshot payloads and
index files all documented as CBOR and all written as JSON or packed binary; and snapshot identifiers
hyphenated in one place and not the other. Every one of them is now corrected above, and the check
exists so that "if we disappear, your backups still open" is something this repository verifies, and does not merely assert.
