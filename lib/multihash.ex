defmodule Multihash do
  @moduledoc """
  Multihash library that follows jbenet multihash protocol so that the hash contains information
  about the hashing algorithm used making it more generic so that one can switch algorithm in future without
  much consequences
  """

  require Monad.Error
  import Monad.Error

  @type t :: %Multihash{name: String.t, code: integer, length: integer, digest: integer}
  defstruct name: "", code: 0, length: 0, digest: 0

  @type hash_type :: :sha1 | :sha2_256 | :sha2_512 | :sha3 | :blake2b | :blake2s

  @type error :: {:error, String.t}

  @type on_encode :: {:ok, binary} | error

  @type on_decode :: {:ok, t} | error

  @hash_info [
    sha1:     [code: 0x11, length: 20],
    sha2_256: [code: 0x12, length: 32],
    sha2_512: [code: 0x13, length: 64],
    sha3:     [code: 0x14, length: 64],
    blake2b:  [code: 0x40, length: 64],
    blake2s:  [code: 0x41, length: 32]
  ]

  @code_hash_map %{
    0x11 => :sha1,
    0x12 => :sha2_256,
    0x13 => :sha2_512,
    0x14 => :sha3,
    0x40 => :blake2b,
    0x41 => :blake2s
  }


  # Error strings
  @error_invalid_digest_hash "Invalid digest or hash"
  @error_invalid_multihash "Invalid multihash"
  @error_invalid_length "Invalid length of provided hash function"
  @error_invalid_size "Invalid size"
  @error_invalid_hash_function "Invalid hash function"
  @error_invalid_hash_code "Invalid hash code"

  @doc ~S"""
  Encode the provided hashed `digest` to the provided multihash of `hash_code`

  ## Examples

      iex> Multihash.encode(:sha1, :crypto.hash(:sha, "Hello"))
      {:ok, <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}

      iex> Multihash.encode(:sha2_256, :crypto.hash(:sha256, "Hello"))
      {:ok, <<18, 32, 24, 95, 141, 179, 34, 113, 254, 37, 245, 97, 166, 252, 147, 139, 46, 38, 67, 6, 236, 48, 78, 218, 81, 128, 7, 209, 118, 72, 38, 56, 25, 105>>}

  Invalid `hash_code`, `digest` length corresponding to the hash function will return an error

      iex> Multihash.encode(:sha2_unknow, :crypto.hash(:sha, "Hello"))
      {:error, "Invalid hash function"}

      iex> Multihash.encode(0x20, :crypto.hash(:sha, "Hello"))
      {:error, "Invalid hash code"}

  """
  @spec encode(integer, binary) :: on_encode
  def encode(hash_code, digest) when is_number(hash_code) and is_binary(digest), do:
    Monad.Error.p({:ok, <<hash_code>>} |> encode(digest))

  @spec encode(binary, binary) :: on_encode
  def encode(<<_hash_code>> = hash_code, digest) when is_binary(digest) do
    Monad.Error.p do
         {:ok, hash_code}
      |> get_hash_function
      |> encode(digest)
    end
  end

  @spec encode(hash_type, binary) :: on_encode
  def encode(hash_func, digest) when is_atom(hash_func) and is_binary(digest) do
    Monad.Error.p do
         {:ok, hash_func}
      |> get_hash_info
      |> check_digest_length(digest)
      |> encode_internal(digest)
    end
  end

  def encode(_digest,_hash_code), do: {:error, @error_invalid_digest_hash}

  @doc ~S"""
  Decode the provided multi hash to %Multihash{code: , name: , length: , digest: }

  ## Examples

      iex> Multihash.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
      {:ok, %Multihash{name: "sha1", code: 17, length: 20, digest: <<247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>}}

  Invalid multihash will result in errors

      iex> Multihash.decode(<<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171>>)
      {:error, "Invalid size"}

      iex> Multihash.decode(<<25, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
      {:error, "Invalid hash code"}

      iex> Multihash.decode(<<17, 32, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>)
      {:error, "Invalid length of provided hash function"}

      iex> Multihash.decode("Hello")
      {:error, "Invalid hash code"}

  """
  @spec decode(binary) :: on_decode
  def decode(<<code, length, digest::binary>>) do
    Monad.Error.p do
       {:ok, <<code>>}
    |> get_hash_function
    |> get_hash_info
    |> check_length(length)
    |> check_digest_length(digest)
    |> decode_internal(digest)
    end
  end

  def decode(_), do: {:error, @error_invalid_multihash}

  @doc ~S"""
  Checks if the code is within application range

  ## Examples

      iex> Multihash.is_app_code(<<0x08>>)
      true

      iex> Multihash.is_app_code(<<0x10>>)
      false
  """
  @spec is_app_code(<<_ :: 8 >>) :: boolean
  def is_app_code(<<code>>), do: code >= 0 and code < 0x10

  @doc ~S"""
  Checks if the code is a valid code

  ## Examples

      iex> Multihash.is_valid_code(<<0x8>>)
      true

      iex> Multihash.is_valid_code(<<0x12>>)
      true

      iex> Multihash.is_valid_code(<<0x21>>)
      false
  """
  @spec is_valid_code(<<_ :: 8 >>) :: boolean
  def is_valid_code(<<_>> = code) do
    if is_app_code(code) do
      true
    else
      is_valid_hash_code code
    end
  end

  @doc """
  Checks if the `code` is a valid hash code
  """
  defp is_valid_hash_code(<<_>> = code), do: is_valid_hash_code get_hash_function(code)
  defp is_valid_hash_code({:ok, _}), do: true
  defp is_valid_hash_code({:error, _}), do: false

  @doc """
  Encode the digest to multihash
  """
  defp encode_internal([code: code, length: length], <<digest::binary>>) do
    Monad.Error.return <<code, length>> <> digest
  end

  @doc """
  Decode the multihash to %Multihash{name, code, length, digest} structure
  """
  defp decode_internal([code: code, length: length], <<digest::binary>>) do
    {:ok, name} = get_hash_function <<code>>
    Monad.Error.return %Multihash{
      name: to_string(name) |> String.replace("_", "-"),
      code: code,
      length: length,
      digest: digest}
  end

  @doc """
  Checks that the `code` is a valid hash code or the code is in application range
  """
  defp check_hash_code(code), do: check_hash_code(is_valid_code(code), code)
  defp check_hash_code(true, code), do: Monad.Error.return code
  defp check_hash_code(false, _), do: Monad.Error.fail @error_invalid_hash_code

  @doc """
  Checks that the `original_lenght` is same as the expected `length` of the hash function
  """
  defp check_length([code: _code, length: length] = hash_info, original_length) do
    case original_length do
      ^length -> Monad.Error.return hash_info
      _ -> Monad.Error.fail @error_invalid_length
    end
  end

  @doc """
  Checks if the length of the `digest` is same as the expected `length` of the has function
  """
  defp check_digest_length([code: _code, length: length] = hash_info, digest) when is_binary(digest) do
    case byte_size(digest) do
      ^length -> Monad.Error.return hash_info
      _ -> Monad.Error.fail @error_invalid_size
    end
  end

  @doc """
  Get hash info from the @hash_info keyword map based on the provided `hash_func`
  """
  defp get_hash_info(hash_func) when is_atom(hash_func), do:
    get_from_dict(@hash_info, hash_func, @error_invalid_hash_function)

  @doc """
  Get hash function from the @code_hash_map based on the `code` key
  """
  defp get_hash_function(<<code>>), do:
      get_from_dict(@code_hash_map, code, @error_invalid_hash_code)

  @doc """
  Generic function that retrieves a key from the dictionary and if the key is not there then returns {:error, `failure_message`}
  """
  defp get_from_dict(dict, key, failure_message) do
    case Dict.get(dict, key, :none) do
      :none -> Monad.Error.fail(failure_message)
      value-> Monad.Error.return(value)
    end
  end

end
