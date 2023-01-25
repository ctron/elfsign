# elfsign

Trying to sign elf files.

## Motivation

You download a binary from the internet, but what is in there? `cargo auditable` can put a dependency list into the
final binary. But anyone could modify this.

Unless, you would sign the binary.

The idea of this PoC is to sign ELF binaries, ensuring that the information inside it was indeed created by the person
who created the binary.

There is a bit of documentation in the [docs/](docs/) folder.

## State

This is a PoC. This is full of bugs and not finished. Also is the content format not stable.

## Usage (the idea)

Sign with Sigstore:

```shell
elfsign sign my-bin my-bin-signed
```

Validate with:

```shell
elfsign verify my-bin-signed
```

## ToDo

* [x] Find a way to add a signature record to the file
* [x] Capture all content subject to signing
  * [ ] Check it is really everything
  * [ ] Re-iterate over digesting the "program sections" (aka "memory segments")
  * [ ] Add more fields from the header
  * [x] Add data from `.shstrtab` (minus the `.note.signature.v1` string)
* [x] Implement sign & store
  * [ ] Implement re-signing 
* [x] Improve storing stuff, this is a mess right now (good for now)
* [ ] Implement verify
  * [x] verify the signature
  * [x] add the certificate, and allow enforcing policies 
* [x] check using "digest" vs "digested signer"
* [ ] allow more options, currently this is highly opinionated towards sigstore and rekor