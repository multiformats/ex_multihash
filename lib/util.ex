defmodule Multihash.Util do
  @moduledoc """
  Utility functions to create multihash from data
  """

  @doc """
  Creates a multihash from the data provided. The hash options are
    * :sha1
    * :sha2_256
    * :sha2_512

  ## Examples

      iex> Multihash.Util.sum("Hello", :sha1)
      <<17, 20, 247, 255, 158, 139, 123, 178, 224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240>>

      iex> Multihash.Util.sum("Hello", :sha2_256)
      <<18, 32, 24, 95, 141, 179, 34, 113, 254, 37, 245, 97, 166, 252, 147, 139, 46, 38, 67, 6, 236, 48, 78, 218, 81, 128, 7, 209, 118, 72, 38, 56, 25, 105>>

      iex> Multihash.Util.sum("Hello", :sha2_512)
      <<19, 64, 54, 21, 248, 12, 157, 41, 62, 215, 64, 38, 135, 249, 75, 34, 213, 142, 82, 155, 140, 199, 145, 111, 143, 172, 127, 221, 247, 251, 213, 175, 76, 247, 119, 211, 215, 149, 167, 160, 10, 22, 191, 126, 127, 63, 185, 86, 30, 233, 186, 174, 72, 13, 169, 254, 122, 24, 118, 158, 113, 136, 107, 3, 243, 21>>

  """
  @spec sum(binary, Multihash.hash_type) :: binary
  def sum(data, :sha1), do: :crypto.hash(:sha, data) |> create_multihash(:sha1)
  def sum(data, :sha2_256), do: :crypto.hash(:sha256, data) |> create_multihash(:sha2_256)
  def sum(data, :sha2_512), do: :crypto.hash(:sha512, data) |> create_multihash(:sha2_512)

  @spec create_multihash(binary, Multihash.hash_type) :: binary
  defp create_multihash(digest, hash) do
    {:ok, multihash} = Multihash.encode(hash, digest)
    multihash
  end

end
