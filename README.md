# AES-SID: AES-based Synthetic IDs

Authenticated deterministic encryption for 64-bit integers based on the
AES-CMAC-SIV construction.

## About

AES-SID is a technique for deterministically encrypting 64-bit integers
(e.g. database primary keys) as 128-bit ciphertexts which can be serialized
as e.g. UUIDs.

While many schemes exist which offer these general properties, AES-SID
detects forgeries via techniques adapted from misuse-resistant authenticated
encryption (i.e. synthetic initialization vectors)

## Security Warning

<img alt="DANGER: EXPERIMENTAL" src="https://miscreant.io/images/experimental.svg" width="400px" height="50px">

Both the design and Rust implementation of this scheme have received no
external review. There are properties/limits of this scheme that need to be
mathematically quantified which are presently undescribed.

This scheme uses deterministic encryption which, if applied improperly
(e.g. naive inverted search index) can lead to *catastrophic failures*
including [full plaintext recovery][cryptdb].

Before attempting to *experiment* with this scheme, please make sure to read
the full threat model section and make sure the cryptographic properties of
this scheme actually apply to your intended threat model.

DO NOT USE THIS CODE IN PRODUCTION!

## Threat Model

AES-SID encrypts 64-bit values as 128-bit values. However, if naively (mis)used
as a general-purpose construction for encrypting 64-bit values, it can
fail catastrophically (and similar constructions have in-practice, as
described in the "Security Warning" section above).

### Unguessable / Unforgeable

The auto-incrementing primary key model utilized by many databases is extremely
convenient for developers for many reasons. However, it comes at a cost:
primary keys are easily guessable by attackers, who are able to enumerate and
explore the entire key space. Some notable examples of this problem include
[an AT&T security flaw which exposed the email addresses of all iPad users][att].

More recently these low-entropy identifiers have enabled so-called
"[Zoom Bombing][zoom]", where attackers are able to guess the identifiers of
valid Zoom channels and thereby gain access to them.

These identifiers are a standard feature of all SQL databases, easily
remembered, easy-to-communicate (in text or spoken form), and generally
ubiquitous in many applications.

AES-SID is designed to allow developers to retrofit applications which
use low-entropy auto-incrementing primary keys in such a way that they can be
deterministically and reversibly mapped to 128-bit external/"masked" values
(that can be serialized as e.g. a UUID), while ensuring that the "masked" values
are randomly distributed and unguessable by an attacker (with greater-than-chance
success in the 128-bit integer space, which is widely regarded as the baseline
for symmetric cryptography).

One way to solve this problem is to use a (cryptographically) random UUID as a
primary key instead of an auto-incrementing one. This is a perfectly valid
approach, and one worth considering, but it comes at a price: UUIDs are long
and high-entropy, which means they aren't easily spoken, or even remembered
or manually typed by someone who has read them.

However, if applications are already leveraging auto-incrementing integer
identifiers, a migration to randomized UUIDs is potentially complex. That said,
even for greenfield applications, low-cardinality auto-incrementing IDs
starting at `(0,1)` are extremely convenient from a developer experience
perspective: they're easy to remember, to type, and to speak.

For this reason, schemes for "masking" / encrypting low-entropy numerical
developers have been developed. Historically, these schemes have at least one
of these two problems:

- Identifiers are *malleable*, providing an advantage to attackers who are
  interested in guessing any valid encrypted identifier
- Identifiers are *long*, e.g. exceeding 128-bits and therefore cannot be
  serialized as e.g. a UUID

AES-SID attempts to create a space-optimal *authenticated* identifier which
includes a cryptographic MAC. While other schemes providing the same
properties exist, this scheme is notable as being based on the
[SIV Mode of Operation][siv] as described by cryptographer Phil Rogaway.

SIV was originally designed for the purposes of "key wrapping"
(i.e. encryption). AES-SID is a specialization of that notion intended for
"primary key wrapping".

### Information Leakage

In addition to being guessable, primary keys leak information about the
records they identify: they often expose the total cardinality of the record
type they identify as well as a lexicographic ordering, almost certainly by
insertion order, which often also exposes a creation date and allows an
honest-but-curious attacker to potentially scrape and compute a complete
graph of the record type of interest.

Apps which both utilize auto-incrementing low-entropy IDs and expose a creation
timestamp are leaking valuable competitive intelligence to potential
competitors/attackers.

### Out-Of-Scope: Encrypted Databases

An encrypted primary key may seem like a powerful building block for encrypted
databases. For example, 64-bits is enough to store the UTF-8 encodings of most
"short words" in most languages which can be represented in Unicode and/or the
primary keys of encrypted documents. Naively it might seem deterministic
ciphertexts of keywords could be used to build an encrypted "inverted index"
providing fulltext search, however such systems are unsound and fail
catastrophically in practice.

As noted in the "Security Warning" section above, attempting to abuse
deterministic encryption for these purposes can have disastrous results
including full plaintext recovery and for this reason many cryptography
professionals may react adversely to the phrase "deterministic encryption"
(and rightfully so!)

Problems like searchable symmetric encryption (SSE) and private information
retrieval (PIR) are ongoing research areas which fraught with peril and an
ongoing history of broken schemes, implementations, and compromises.

The most promising solutions in these spaces involve much more complex schemes
than AES-SID, such as [structured encryption][ste] and [oblivious ram][oram].

DO NOT USE AES-SID TO BUILD AN ENCRYPTED DATABASE!

## Construction

AES-SID is a simplification of the AES-CMAC-SIV scheme as described in the paper
[The SIV Mode of Operation for Deterministic Authenticated-Encryption (Key Wrap) and Misuse-Resistant Nonce-Based Authenticated-Encryption][siv]
by Phil Rogaway and later specified as [RFC 5297].

### AES-CMAC-SIV (for context)

Below is a pseudocode description of AES-CMAC-SIV encryption:

```
enc_key = key[0..Kenclen]
prf_key = key[Kenclen..Ktotal]
siv = vPRF(prf_key, header0, header1, ... headerN, plaintext)
ciphertext = siv || AES-CTR(enc_key, siv, plaintext)
```

Where the terms are as follows:

- `key`: input encryption + PRF key
- `Kenclen`: size of the encryption key in bytes
- `Ktotal`: size of the combined encryption + PRF key in bytes
- `enc_key`: encryption key
- `prf_key`: (v)PRF key
- `vPRF`: vectorized pseudorandom function: a "keyed hash" which operates
  over an arbitrary-sized vector of input messages. The AES-CMAC-SIV
  construction function specifies a vPRF called "S2V" which is based on [CMAC].
- `header1` .. `headerN`: an arbitrary number of "additional associated data"
  messages to authenticate along with the plaintext, typically a single AAD
  string and a nonce
- `siv`: synthetic initialization vector (SIV): a dual purpose IV and message
  authentication tag
- `AES-CTR`: the AES block cipher (with a `Kenclen` key size) instantiated as a
  stream cipher in counter mode (CTR)
- `ciphertext`: authenticated ciphertext which is a concatenation of `siv`
  and the AES-CTR encryption of the plaintext

While naively this might appear to be a "MAC-then-encrypt" scheme, which are classically
vulnerable to things like padding oracle attacks (e.g. BEAST, Lucky 13), SIV modes are
provably secure from these attacks for two reasons:

- The "Synthetic IV" (SIV) provides a cryptographic binding/linkage between the
  plaintext and its encryption not present in naive "MAC-then-encrypt"
  constructions
- By using AES as a stream cipher (i.e. AES-CTR) rather than a block cipher
  mode with padding (e.g. CBC), there is no padding and therefore no padding
  oracle. As an added benefit when short ciphertexts are desirable, the length
  of the ciphertext is the same as the length of the plaintext, i.e. stream
  ciphers like AES-CTR provide zero-overhead encryption for any length message.

### AES-SID

Below is pseudocode of AES-SID and a comparison to AES-CMAC-SIV:

```
enc_key = KDF(key, 0, Kenclen)
prf_key = KDF(key, Kenclen, Ktotal)
siv = PRF(prf_key, plaintext)[0..8bytes]
ciphertext = siv || AES-CTR(enc_key, siv, plaintext)
```

Where the terms (not already described above) are as follows:

- `KDF`: key derivation function. AES-SID uses a [CTR_DRBG]-style KDF, namely
  the one described in [RFC 8452 Section 4] as used by AES-GCM-SIV
- `PRF`: pseudorandom function. AES-SID replaces the vectorized PRF used
  above with a single-input PRF: [CMAC], making it deterministic.
  AES-SID as instantiated with CMAC can be more specifically described as
  AES-CMAC-SID. It could potentially be instantiated with another secure PRF
  (e.g. HMAC-SHA-256).
- `siv`: PRF output truncated to 8-bytes (64-bits)
- `plaintext`: the little endian encoding of an unsigned 64-bit integer
- `ciphertext`: a 128-bit uniformly random deterministic encryption of the
  plaintext value comprising a 64-bit dual purpose IV/message authenticator
  and 64-bit AES-CTR encryption of the plaintext

## Frequently Asked Questions (FAQ)

### Q1: Should I actually consider using this?

A1: Not yet. We are awaiting cryptographic review of the scheme, which we
think we can encourage organically because we know a lot of cryptographers
and they are naturally cantankerous people who will provide their opinions
whether you want them or not.

### Q2: What makes AES-SID different from similar "masking" schemes?

A2: Many "masking" schemes which provide a 128-bit ciphertext for a 64-bit
integer plaintext use naive (unauthenticated) methods like ECB mode.

AES-SID is notable in its use of a synthetic initialization vector (SIV) mode
to solve the "masking" problem. which is both the only notable
cryptographically secure way to realize the goals described above in the threat
model in a deterministic encryption scheme.

### Q3: Are there test vectors?

A3: The test vectors are presently contained in the reference Rust
implementation. We realize that isn't ideal and plan on extracting them out
into a form which is more amenable to mechanical consumption.

### Q4: Will there be implementations of this scheme in other languages?

A4: If there is sufficient interest, we intend to build out implementations of
this scheme in Go, JavaScript, Ruby, and Python in addition to Rust. We would
also be interested to hear from potential users in other languages.

## License

Copyright © 2020 iqlusion

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you shall be licensed as above,
without any additional terms or conditions.

[//]: # (links)

[cryptdb]: https://arstechnica.com/information-technology/2015/09/ms-researchers-claim-to-crack-encrypted-database-with-old-simple-trick/
[snowflake]: https://developer.twitter.com/en/docs/basics/twitter-ids
[att]: https://gawker.com/5559346/apples-worst-security-breach-114000-ipad-owners-exposed
[zoom]: https://threatpost.com/fbi-threatens-zoom-bombing-trolls-with-jail-time/154495/
[siv]: https://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
[ste]: http://cs.brown.edu/~seny/2950-v/ste.pdf
[oram]: https://en.wikipedia.org/wiki/Oblivious_RAM
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[CMAC]: https://csrc.nist.gov/publications/detail/sp/800-38b/final
[CTR_DRBG]: https://en.wikipedia.org/wiki/NIST_SP_800-90A#CTR_DRBG
[RFC 8452 Section 4]: https://tools.ietf.org/html/rfc8452#section-4
