namespace DotNetLightning.Crypto

open System
open System.Linq
open NBitcoin
open NBitcoin.Crypto

open DotNetLightning.Utils
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Macs

module SharedSecret =
    let FromKeyPair(pub: PubKey, priv: Key) =
        Hashes.SHA256 (pub.GetSharedPubkey(priv).ToBytes())

type CryptoUtils = { decryptWithAD: (uint64 * uint256 * byte[] * ReadOnlySpan<byte>) -> RResult<byte[]>
                     encryptWithAD: (uint64 * uint256 * ReadOnlySpan<byte> * ReadOnlySpan<byte>) -> byte[]
                     /// This is used for filler generation in onion routing (BOLT 4)
                     encryptWithoutAD: (uint64 * byte[] * ReadOnlySpan<byte>) -> byte[] }

module Sodium =
    let internal getNonce (n: uint64) =
        let nonceBytes = ReadOnlySpan(Array.concat[| Array.zeroCreate 4; BitConverter.GetBytes(n) |]) // little endian
        NSec.Cryptography.Nonce(nonceBytes, 0)

    let internal chacha20AD = NSec.Cryptography.ChaCha20Poly1305.ChaCha20Poly1305
    let internal chacha20 = NSec.Experimental.ChaCha20.ChaCha20

    let impl: CryptoUtils = {
        decryptWithAD = fun (n: uint64, key: uint256, ad: byte[], cipherText: ReadOnlySpan<byte>) ->
            let nonce = getNonce n
            let keySpan = ReadOnlySpan(key.ToBytes())
            let adSpan = ReadOnlySpan(ad)
            let blobF = NSec.Cryptography.KeyBlobFormat.RawSymmetricKey
            let chachaKey = NSec.Cryptography.Key.Import(chacha20AD, keySpan, blobF)
            match chacha20AD.Decrypt(chachaKey, &nonce, adSpan, cipherText) with
            | true, plainText -> Good plainText
            | false, _ -> RResult.rmsg "Failed to decrypt with AD. Bad Mac"

        encryptWithoutAD = fun (n: uint64, key: byte[], plainText: ReadOnlySpan<byte>) ->
            let nonce = getNonce n
            let keySpan = ReadOnlySpan(key)
            let blobF = NSec.Cryptography.KeyBlobFormat.RawSymmetricKey
            use chachaKey = NSec.Cryptography.Key.Import(chacha20, keySpan, blobF)
            let res = chacha20.XOr(chachaKey, &nonce, plainText)
            res

        encryptWithAD = fun (n: uint64, key: uint256, ad: ReadOnlySpan<byte>, plainText: ReadOnlySpan<byte>) ->
            let nonce = getNonce n
            let keySpan = ReadOnlySpan(key.ToBytes())
            let blobF = NSec.Cryptography.KeyBlobFormat.RawSymmetricKey
            use chachaKey = NSec.Cryptography.Key.Import(chacha20AD, keySpan, blobF)
            chacha20AD.Encrypt(chachaKey, &nonce, ad, plainText)
        }

module BouncyCastle =
    type internal Mode = ENCRYPT | DECRYPT

    let internal encryptOrDecrypt(mode: Mode, inp: byte[], key: byte[], nonce: byte[] , skip1block: bool): byte[] =
        let eng = ChaCha7539Engine()
        eng.Init((mode = ENCRYPT), ParametersWithIV(KeyParameter key, nonce))
        let out = Array.zeroCreate inp.Length
        if skip1block then
            let dummy = Array.zeroCreate 64
            eng.ProcessBytes(Array.zeroCreate 64, 0, 64, dummy, 0)
        else ()
        eng.ProcessBytes(inp, 0, inp.Length, out, 0)
        out

    let internal pad(mac: Poly1305, length: int): unit =
        match length % 16 with
        | 0 -> ()
        | n ->
            let padding = Array.zeroCreate <| 16 - n
            mac.BlockUpdate(padding, 0, padding.Length)

    let internal writeLE(mac: Poly1305, length: int): unit =
        let serialized = BitConverter.GetBytes(uint64 length)
        if not BitConverter.IsLittleEndian then
            Array.Reverse serialized
        else ()
        mac.BlockUpdate(serialized, 0, 8)

    let internal writeSpan(mac: Poly1305, span: ReadOnlySpan<byte>): unit =
        let byteArray = span.ToArray()
        mac.BlockUpdate(byteArray, 0, byteArray.Length)

    let internal calcMac(key, nonce, ciphertext, ad): byte[] =
        let mac = Poly1305()
        let polyKey = encryptOrDecrypt(ENCRYPT, Array.zeroCreate 32, key, nonce, false)
        mac.Init <| KeyParameter polyKey
        writeSpan(mac, ad)
        pad(mac, ad.Length)
        mac.BlockUpdate(ciphertext, 0, ciphertext.Length)
        pad(mac, ciphertext.Length)
        writeLE(mac, ad.Length)
        writeLE(mac, ciphertext.Length)
        let tag: byte[] = Array.zeroCreate 16
        let macreslen = mac.DoFinal(tag, 0)
        assert (macreslen = 16)
        tag

    let impl: CryptoUtils = {
        encryptWithAD = fun (n: uint64, key: uint256, ad: ReadOnlySpan<byte>, plainText: ReadOnlySpan<byte>) ->
            let key = key.ToBytes()
            let nonce = Array.concat [| Array.zeroCreate 4; BitConverter.GetBytes(n) |]
            let plainTextBytes = plainText.ToArray()
            let ciphertext = encryptOrDecrypt(ENCRYPT, plainTextBytes, key, nonce, true)
            let tag = calcMac(key, nonce, ciphertext, ad)
            Array.concat [| ciphertext; tag |]

        decryptWithAD = fun (n: uint64, key: uint256, ad: byte[], ciphertext: ReadOnlySpan<byte>) ->
            if ciphertext.Length < 16 then
                RResult.rmsg "ciphertext too short to have mac tag"
            else
                let key = key.ToBytes()
                let nonce = Array.concat[| Array.zeroCreate 4; BitConverter.GetBytes(n) |]
                let ciphertextWithoutMac = ciphertext.Slice(0, ciphertext.Length - 16).ToArray()
                let macToValidate = ciphertext.Slice(ciphertext.Length - 16).ToArray()
                let correctMac = calcMac(key, nonce, ciphertextWithoutMac, ReadOnlySpan ad)
                let ciphertextMacIsCorrect = correctMac.SequenceEqual(macToValidate)
                if not ciphertextMacIsCorrect then
                    RResult.rmsg "invalid message authentication code at then end of ciphertext"
                else
                    let plaintext = encryptOrDecrypt(DECRYPT, ciphertextWithoutMac, key, nonce, true)
                    Good plaintext

        encryptWithoutAD = fun (n: uint64, key: byte[], plainText: ReadOnlySpan<byte>) ->
            let nonce = Array.concat [| Array.zeroCreate 4; BitConverter.GetBytes(n) |]
            encryptOrDecrypt(ENCRYPT, plainText.ToArray(), key, nonce, false)
        }
