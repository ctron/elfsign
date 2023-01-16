# elfsign

## Overview

The idea is to create digest of the ELF binary, including all content relevant for executing or inspecting the binary.
This includes program code as well as debug or dependency information. However, it does not just create a digest of
the full file. That wouldn't make sense, as adding the signature would alter the file.

## Digest

Currently, it digests selected ELF header fields (like the entry address) as well as all sections, excluding the
signature section itself.

The digest algorithm can be chosen by the user.

## Signature

The digest is signed with a private key. The public key and the signature are stored in a "note" section of the ELF
binary together with the information what digest/signature algorithms have been used.

## Verification

The ELF file is parsed for the signature information. Based on it, a digest is calculated and verified against the
signature.

Currently, all valid signatures are returned. If there is at least one, the verification is considered "ok". This is
not enough. It requires a policy setup which defines if a public key can be trusted. Or for example, if all stored
signatures must be valid, …

This is future work, and should be configurable.

## Thoughts

### Wouldn't it make sense to store the signature information externally?

Yes, that would work too. One could store all information in a companion file.

On the pro-side, this would make processing a bit easier. For example would it be possible to just digest the whole
file.

The downside is that one would always need to think about the companion file too. Downloading a binary from e.g. 
GitHub would mean one would need to download the companion file too. We already have this with e.g. Maven artifacts,
and most people just don't use it.

Having the signature embedded into the binary makes it available without knowing where th companion file is.

### Couldn't this be stored in an "extended attribute"

Yes, but that also wouldn't survive an upload/download cycle.

### Can this be used to prevent people from running binaries

Potentially. One could craft a system which enforces such signatures and prevent executing of unsigned/invalid-signed
binaries. But that is not the goal of this effort.

### Why sigstore?

Sigstore just came in handy. Maybe it has enough benefit to just adopt it. Maybe adding plain certificates makes sense
too. There are traits in place which should allow building something without sigstore. Right now, it's pure laziness.