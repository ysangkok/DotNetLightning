namespace DotNetLightning.LN

open NBitcoin
open DotNetLightning.Utils
open DotNetLightning.Serialize.Msgs
open DotNetLightning.Utils.Aether

type PeerHandleError = {
    /// Used to indicate that we probably can't make any future connections to this peer, implying
    /// we should go ahead and force-close any channels we have with it.
    NoConnectionPossible: bool
}

exception PeerHandleException of PeerHandleError

type InitSyncTracker =
    | ChannelsSyncing of ChannelId
    | NodeSyncing of PubKey
    | NoSyncRequested

module private PeerConstants =
    [<Literal>]
    let INITIAL_SYNCS_TO_SEND = 5u

type Peer = {
    PeerId: PeerId
    ChannelEncryptor: PeerChannelEncryptor
    IsOutBound : bool
    TheirNodeId: NodeId option
    TheirGlobalFeatures: GlobalFeatures option
    TheirLocalFeatures: LocalFeatures option
    LengthDecoded: uint16 option

    SyncStatus: InitSyncTracker
}
    with
        static member CreateInbound(peerId, ourNodeSecret) = {
            PeerId = peerId
            ChannelEncryptor = PeerChannelEncryptor.newInBound(ourNodeSecret)
            IsOutBound = false
            TheirNodeId = None
            TheirGlobalFeatures = None
            TheirLocalFeatures = None
            LengthDecoded = None
            SyncStatus = NoSyncRequested
        }
        
        static member CreateOutbound(peerId, theirNodeId) = {
            PeerId = peerId
            ChannelEncryptor = PeerChannelEncryptor.newOutBound(theirNodeId)
            IsOutBound = true
            TheirNodeId = Some theirNodeId
            TheirGlobalFeatures = None
            TheirLocalFeatures = None
            LengthDecoded = None
            SyncStatus = NoSyncRequested
        }
        /// Returns true if the channel announcements/updates for the given channel should be
        /// Forwarded to this peer.
        /// If we are sending our routing table to this peer and we have not yet sent channel
        /// announceents/updates for the given channel_id then we will send it when we get to that
        /// point and we shouldn't send it yet to avoid sending
        member this.ShouldForwardChannel(channelId: ChannelId) =
            match this.SyncStatus with
            | NoSyncRequested -> true
            | ChannelsSyncing i -> i < channelId
            | NodeSyncing _ -> true
            
        static member ChannelEncryptor_: Lens<_,_> =
            (fun p -> p.ChannelEncryptor),
            (fun pce p -> { p with ChannelEncryptor = pce })
            
module Peer =
    let executeCommand (state: Peer) (cmd: PeerCommand) =
        let noiseStep = state.ChannelEncryptor.GetNoiseStep()
        match noiseStep, cmd with
        | ActOne, ProcessActOne (actOne, ourNodeSecret) ->
            state.ChannelEncryptor |> PeerChannelEncryptor.processActOneWithKey actOne ourNodeSecret
            |>> (ActOneProcessed >> List.singleton)
        | ActTwo, ProcessActTwo (actTwo, ourNodeSecret) ->
            state.ChannelEncryptor |> PeerChannelEncryptor.processActTwo actTwo ourNodeSecret
            |>> (ActTwoProcessed >> List.singleton)
        | ActThree, ProcessActThree(actThree) ->
            state.ChannelEncryptor |> PeerChannelEncryptor.processActThree actThree
            |>> (ActThreeProcessed >> List.singleton)
        | NoiseComplete, DecodeLength packet ->
            state.ChannelEncryptor |> PeerChannelEncryptor.decryptLengthHeader (fun _ -> ()) packet
            |>> (LengthDecrypted >> List.singleton)
        | NoiseComplete, DecodeCipherPacket packet ->
            state.ChannelEncryptor |> PeerChannelEncryptor.decryptMessage (fun _ -> ()) packet
            >>= fun (b, newPCE) ->
                LightningMsg.fromBytes b
                >>= fun msg ->
                match msg with
                | :? ErrorMessage as msg ->
                    [ReceivedError (msg, newPCE)] |> Good
                | :? Ping as msg ->
                    [ReceivedPing (msg, newPCE)] |> Good
                | :? Pong as msg ->
                    [ReceivedPong (msg, newPCE)] |> Good
                | :? Init as msg ->
                    [ReceivedInit (msg, newPCE)] |> Good
                | :? IRoutingMsg as msg ->
                    [ReceivedRoutingMsg (msg, newPCE)] |> Good
                | :? IChannelMsg as msg ->
                    [ReceivedChannelMsg (msg, newPCE)] |> Good
                | _ ->
                    failwithf "unreachable %A" msg
        | NoiseComplete, EncodeMsg (msg) ->
            state.ChannelEncryptor |> PeerChannelEncryptor.encryptMessage (fun _ -> ()) (msg.ToBytes())
            |> (MsgEncoded >> List.singleton >> Good)
        | s, cmd ->
            sprintf "Peer does not know how to handle %A while in noise step %A" cmd noiseStep
            |> RResult.rmsg
        
    let applyEvent (state: Peer) (event: PeerEvent): Peer =
        let noiseStep = state.ChannelEncryptor.GetNoiseStep()
        match noiseStep, event with
        | ActOne, ActOneProcessed (_, pce) ->
            { state with ChannelEncryptor = pce }
        | ActTwo, ActTwoProcessed(_, pce) ->
            { state with ChannelEncryptor = pce }
        | ActThree, ActThreeProcessed(_, pce) ->
            { state with ChannelEncryptor = pce }
        | NoiseComplete, LengthDecrypted (length, pce) ->
            { state with ChannelEncryptor = pce; LengthDecoded = Some length }
        | NoiseComplete, ReceivedError (_, pce)
        | NoiseComplete, ReceivedPing (_, pce)
        | NoiseComplete, ReceivedPong (_, pce)
        | NoiseComplete, ReceivedRoutingMsg (_, pce)
        | NoiseComplete, ReceivedChannelMsg (_, pce) ->
            { state with ChannelEncryptor = pce; LengthDecoded = None }
        | NoiseComplete, ReceivedInit (init, pce) ->
            { state with
                ChannelEncryptor = pce;
                LengthDecoded = None;
                TheirGlobalFeatures = Some init.GlobalFeatures;
                TheirLocalFeatures = Some init.LocalFeatures }
        | _ ->
            failwith "unreachable"