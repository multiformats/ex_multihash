defmodule Multihash.Util do

  @doc """
  Creates a multihash from the data provided. The hash options are
    * :sha1
    * :sha2_256
    * :sha2_512
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
