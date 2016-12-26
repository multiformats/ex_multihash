ex_multihash
============

[![hex.pm version](https://img.shields.io/hexpm/v/httpotion.svg?style=flat-square)](https://hex.pm/packages/ex_multihash)
[![API Docs](https://img.shields.io/badge/api-docs-yellow.svg?style=flat-square)](http://hexdocs.pm/ex_multihash/)
[![Travis CI](https://img.shields.io/travis/multiformats/ex_multihash.svg?style=flat-square&branch=master)](https://travis-ci.org/multiformats/ex_multihash)
[![Inline docs](http://inch-ci.org/github/multiformats/ex_multihash.svg)](http://inch-ci.org/github/multiformats/ex_multihash)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](https://github.com/multiformats/multiformats)
[![](https://img.shields.io/badge/freenode-%23ipfs-blue.svg?style=flat-square)](https://webchat.freenode.net/?channels=%23ipfs)
[![](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

> Multihash implementation in Elixir

This is the [Multihash](https://github.com/multiformats/multihash) implementation in Elixir.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
  - [Encoding](#encoding)
    - [Examples](#examples)
    - [Examples](#examples-1)
    - [Examples](#examples-2)
  - [Decoding](#decoding)
    - [Examples](#examples-3)
    - [Examples](#examples-4)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

To use ex_multihash add to your `mix.exs` file:

```elixir
defp deps do
  [
    {:ex_multihash, "~> 1.0"}
  ]
end
```

## Usage

### Encoding

Encode the provided hashed `digest` to the provided multihash of `hash_code`.

#### Examples

```elixir
iex> Multihash.encode(:sha1, :crypto.hash(:sha, "Hello"))
{:ok, <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}

iex> Multihash.encode(:sha2_256, :crypto.hash(:sha256, "Hello"))
{:ok, <<18, 32, 24, 95, 141, 179, 34, 113, 254, 37, 245, 97, 166, 252, 147, 139, 46, 38, 67, 6, 236, 48, 78, 218, 81, 128, 7, 209, 118, 72, 38, 56, 25, 105>>}
```

Invalid `hash_code` or `digest` corresponding to the hash function will return an error.

#### Examples

```elixir
iex> Multihash.encode(:sha2_unknow, :crypto.hash(:sha, "Hello"))
{:error, "Invalid hash function"}

iex> Multihash.encode(0x20, :crypto.hash(:sha, "Hello"))
{:error, "Invalid hash code"}
```

It's possible to [truncate a digest](https://github.com/multiformats/multihash/issues/1) by passing an optional `length` parameter. Passing a `length` longer than the default digest length of the hash function will return an error.

#### Examples

```elixir
iex> Multihash.encode(:sha1, :crypto.hash(:sha, "Hello"), 10)
{:ok, <<17, 10, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147>>}
iex> Multihash.encode(:sha1, :crypto.hash(:sha, "Hello"), 30)
{:error, "Invalid digest length"}
```

### Decoding

Decode the provided multihash to:

```elixir
%Multihash{name: atom, code: integer, length: integer, digest: bitstring}
```

#### Examples

```elixir
iex> Multihash.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
{:ok, %Multihash{name: :sha1, code: 17, length: 20, digest: <<247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}}
```

Invalid multihash will result in errors

#### Examples

```elixir
iex> Multihash.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171>>)
{:error, "Invalid size"}

iex> Multihash.decode(<<17, 22, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 20, 21, 22>>)
{:error, "Invalid digest length"}

iex> Multihash.decode(<<25, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
{:error, "Invalid hash code"}

iex> Multihash.decode(<<17, 32, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
{:error, "Invalid length of provided hash function"}

iex> Multihash.decode("Hello")
{:error, "Invalid hash code"}
```

## Maintainers

Captain: [@zabirauf](https://github.com/zabirauf).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/multiformats/ex_multihash/issues).

Check out our [contributing document](https://github.com/multiformats/multiformats/blob/master/contributing.md) for more information on how we work, and about contributing in general. Please be aware that all interactions related to multiformats are subject to the IPFS [Code of Conduct](https://github.com/ipfs/community/blob/master/code-of-conduct.md).

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License
[MIT](LICENSE) © 2015 Zohaib Rauf.
