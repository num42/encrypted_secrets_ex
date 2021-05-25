defmodule EncryptedSecrets.Encryption do
  @moduledoc """
    Provides methods for reading creating keys and encrypting/decrypting payloads
  """

  @aes_block_size 16

  @doc """
    Generates a 256 bit (32 byte) random key to be used as the master key

  ## Examples
      iex> binary_key = Encryption.generate_aes_key()
      iex> random_string = binary_key |> Base.encode16
      iex> String.length(random_string)
      64
  """
  def generate_aes_key() do
    :crypto.strong_rand_bytes(32)
  end

  @doc """
    Encrypts `clear_text` using the given `key`
  """
  def encrypt(key, clear_text) do
    init_vec = :crypto.strong_rand_bytes(16)
    payload = pad(clear_text, @aes_block_size)

    {:ok,
     {init_vec,
      :crypto.crypto_init(:aes_256_cbc, key, init_vec, true)
      |> :crypto.crypto_update(payload)}}
  end

  @doc """
    Decrypts `cipher_text` using the given `key` and `init_vec`
  """
  def decrypt(key, init_vec, cipher_text) do
    {:ok,
     :crypto.crypto_init(:aes_256_cbc, key, init_vec, false)
     |> :crypto.crypto_update(cipher_text)
     |> unpad()}
  end

  defp pad(data, block_size) do
    to_add = block_size - rem(byte_size(data), block_size)
    data <> to_string(:string.chars(to_add, to_add))
  end

  defp unpad(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end
end
