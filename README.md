Multihash
=========

[Multihash](https://github.com/jbenet/multihash) implementation in Elixir


# How to use it

## Encoding
Encode the provided hashed `digest` to the provided multihash of `hash_code`

### Examples

```
iex> Multihash.encode(:sha1, :crypto.hash(:sha, "Hello"))
{:ok, <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}

iex> Multihash.encode(:sha2_256, :crypto.hash(:sha256, "Hello"))
{:ok, <<18, 32, 24, 95, 141, 179, 34, 113, 254, 37, 245, 97, 166, 252, 147, 139, 46, 38, 67, 6, 236, 48, 78, 218, 81, 128, 7, 209, 118, 72, 38, 56, 25, 105>>}
```

Invalid `hash_code`, `digest` length corresponding to the hash function will return an error

### Examples
```
iex> Multihash.encode(:sha2_unknow, :crypto.hash(:sha, "Hello"))
{:error, "Invalid hash function"}

iex> Multihash.encode(0x20, :crypto.hash(:sha, "Hello"))
{:error, "Invalid hash code"}
```

## Decoding

Decode the provided multi hash to %Multihash{code: , name: , length: , digest: }

### Examples

```
iex> Multihash.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
{:ok, %Multihash{name: "sha1", code: 17, length: 20, digest: <<247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}}
```

Invalid multihash will result in errors

### Examples
```
iex> Multihash.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171>>)
{:error, "Invalid size"}

iex> Multihash.decode(<<25, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
{:error, "Invalid hash code"}

iex> Multihash.decode(<<17, 32, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
{:error, "Invalid length of provided hash function"}

iex> Multihash.decode("Hello")
{:error, "Invalid hash code"}
```

# License
MIT
