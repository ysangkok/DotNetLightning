module EncryptDecrypt

open NUnit.Framework
open System
open DotNetLightning.Crypto.CryptoUtils

[<TestFixture>]
type EncryptDecryptTest() =
    let fromHex (s:string): byte[] = 
      s
      |> Seq.windowed 2
      |> Seq.mapi (fun i j -> (i,j))
      |> Seq.filter (fun (i,j) -> i % 2=0)
      |> Seq.map (fun (_,j) -> Byte.Parse(new System.String(j),System.Globalization.NumberStyles.AllowHexSpecifier))
      |> Array.ofSeq

    [<Test>]
    member __.``libsodium initiator encryption from bolt-08``() =
        let key = NBitcoin.uint256(ReadOnlySpan<byte> (fromHex "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f"))
        let nonce = (fromHex "000000000000000000000000", 0) |> BitConverter.ToUInt64
        let ad = ReadOnlySpan<byte> (fromHex "9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c")
        let plaintext = ReadOnlySpan<byte> (Array.zeroCreate 0)
        Assert.That(encryptWithAD(nonce, key, ad, plaintext), Is.EqualTo(fromHex "0df6086551151f58b8afe6c195782c6a"))

    [<Test>]
    member __.``bouncy-castle initiator encryption from bolt-08``() =
        let key = NBitcoin.uint256(ReadOnlySpan<byte> (fromHex "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f"))
        let nonce = (fromHex "000000000000000000000000", 0) |> BitConverter.ToUInt64
        let ad = ReadOnlySpan<byte> (fromHex "9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c")
        let plaintext = ReadOnlySpan<byte> (Array.zeroCreate 0)
        Assert.That(encryptWithAD2(nonce, key, ad, plaintext), Is.EqualTo(fromHex "0df6086551151f58b8afe6c195782c6a"))

    [<Test>]
    member __.``bouncy-castle initiator decryption test from bolt-08``() =
        let key = NBitcoin.uint256(ReadOnlySpan<byte> (fromHex "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f"))
        let nonce = uint64 0
        let ad = ReadOnlySpan<byte> (fromHex "9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c")
        let ciphertext = ReadOnlySpan<byte> (fromHex "0df6086551151f58b8afe6c195782c6a")
        Assert.That(decryptWithAD2(nonce, key, ad, ciphertext), Is.EqualTo(Array.empty))

    [<Test>]
    member __.``bouncy-castle encrypt equals nsec encrypt``() =
        let key = fromHex "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f"
        Assert.That(encryptWithoutAD (uint64 12, key, ReadOnlySpan [| 1uy |]),
         Is.EqualTo(encryptWithoutAD2(uint64 12, key, ReadOnlySpan [| 1uy |])))