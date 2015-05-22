defmodule Multihash do
  require Monad.Error
  import Monad.Error

  defstruct name: "", code: 0, length: 0, digest: 0

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

  @doc ~S"""
  Encode the provided hashed `buffer` to the provided multihash of `hash_code`

  ## Examples

      iex> Multihash.encode(:sha1, :crypto(:sha, "Hello"))
      {:ok, <<17, 20, 3, 207, 111, 77, 15, 122, 5, 39, 156, 32, 84, 243, 87, 250, 58, 168, 116, 66, 222, 82>>}

      iex> Multihash.encode(:sha2_256, :crypto(:sha256, "Hello"))
      {:ok, <<18, 32, 223, 216, 169, 8, 99, 165, 81, 6, 11, 102, 87, 123, 210, 150, 7, 103, 230, 126, 204, 0, 96, 227, 155, 16, 148, 126, 206, 221, 168, 76, 25, 244>>}

      iex> Multihash.encode(:sha2_512, :crypto(:sha512, "Hello"))

  Invalid `hash_code`, `buffer` length corresponding to the hash function will return an error

      iex> Multihash.encode(:sha2_unknow, :crypt(:sha, "Hello"))
      {:error, "Invalid hash function"}

      iex> Multihash.encode(0x20, :crypt(:sha, "Hello"))
      {:error, "Invalid hash code"}
      
  """
  def encode(hash_code, buffer) when is_number(hash_code) and is_binary(buffer), do:
    Monad.Error.p({:ok, <<hash_code>>} |> encode(buffer))

  def encode(<<_hash_code>> = hash_code, buffer) when is_binary(buffer) do
    Monad.Error.p do
         {:ok, hash_code}
      |> get_hash_function
      |> encode(buffer)
    end
  end

  def encode(hash_func, buffer) when is_atom(hash_func) and is_binary(buffer) do
    Monad.Error.p do
         {:ok, hash_func}
      |> get_hash_info
      |> check_buffer_length(buffer)
      |> encode_internal(buffer)
    end
  end

  def encode(_buffer,_hash_code), do: {:error, "Invalid buffer or hash"}

  def decode(<<code, length, digest::binary>>) do
    Monad.Error.p do
       {:ok, <<code>>}
    |> get_hash_function
    |> get_hash_info
    |> check_length(length)
    |> check_buffer_length(digest)
    |> decode_internal(digest)
    end
  end

  def decode(_), do: {:error, "Invalid multihash"}

  defp encode_internal([code: code, length: length], <<buffer::binary>>) do
    Monad.Error.return <<code, length>> <> buffer
  end

  defp decode_internal([code: code, length: length], <<digest::binary>>) do
    {:ok, name} = get_hash_function <<code>>
    Monad.Error.return %Multihash{
      name: to_string(name) |> String.replace("_", "-"),
      code: code,
      length: length,
      digest: digest}
  end

  defp check_length([code: _code, length: length] = hash_info, original_length) do
    case original_length do
      ^length -> Monad.Error.return(hash_info)
      _ -> Monad.Error.fail("Invalid length of provided hash function")
    end
  end

  defp check_buffer_length([code: _code, length: length] = hash_info, buffer) when is_binary(buffer) do
    case byte_size(buffer) do
      ^length -> Monad.Error.return hash_info
      _ -> Monad.Error.fail("Invalid size")
    end
  end

  defp get_hash_info(hash_func) when is_atom(hash_func), do:
    get_from_dict(@hash_info, hash_func, "Invalid hash function")

  defp get_hash_function(<<code>>), do:
      get_from_dict(@code_hash_map, code, "Invalid hash code")

  defp get_from_dict(dict, key, failure_message) do
    case Dict.get(dict, key, :none) do
      :none -> Monad.Error.fail(failure_message)
      value-> Monad.Error.return(value)
    end
  end

end
