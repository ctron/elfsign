# elfsign

Trying to sign elf files.

## Motivation

You download a binary from the internet, but what is in there? `cargo auditable` can put a dependency list into the
final binary. But anyone could modify this.

Unless, you would sign the binary.

The idea of this PoC is to sign ELF binaries, ensuring that the information inside it was indeed created by the person
who created the binary.

## State

This is a PoC. It most likely is full of bugs and far from finished.

## ToDo

* [x] Find a way to add a signature record to the file
* [x] Capture all content subject to signing
  * [ ] Check it is really everything
  * [ ] Re-iterate over digesting the "program sections" (aka "memory segments")
  * [ ] Add more fields from the header
* [x] Implement sign & store
* [ ] Improve storing stuff, this is a mess right now
* [ ] Implement verify
  * [x] verify the signature
  * [ ] add the certificate, and allow enforcing policies 
* [ ] check using "digest" vs "digested signer"
