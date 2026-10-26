{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where

-- One request per process. No argv, filesystem secret output, or diagnostics.
-- The complete lab cgroup must deny swap before input; native KES additionally
-- uses mlocked keys with explicit forgetting. Process dumping is disabled.
import qualified Cardano.Api as Api
import Cardano.Binary.FixedSizeCodec (FixedSizeCodec (rawDecodeFixedSized, rawEncodeFixedSized))
import Cardano.Api.Experimental.Certificate (OperationalCertificate (..))
import qualified Cardano.Crypto.DSIGN as D
import Cardano.Crypto.DSIGN.Ed25519 (Ed25519DSIGN)
import Cardano.Crypto.KES.Class
import Cardano.Crypto.KES.Sum (Sum6KES)
import Cardano.Crypto.Hash.Blake2b (Blake2b_256)
import Cardano.Crypto.Libsodium (sodiumInit)
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.Crypto.Util (SignableRepresentation (getSignableRepresentation))
import Cardano.Protocol.Crypto (StandardCrypto)
import qualified Cardano.Protocol.TPraos.OCert as O
import Control.Exception
import Control.Monad (unless, when)
import qualified Data.Aeson as A
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Bits
import Data.Word
import Foreign.C.Types
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (castPtr)
import System.Exit (exitFailure)
import System.IO

foreign import ccall unsafe "prctl" noDump :: CInt -> CULong -> CULong -> CULong -> CULong -> IO CInt

type K = Sum6KES Ed25519DSIGN Blake2b_256
identity :: B.ByteString
identity = B.pack (map (fromIntegral . fromEnum) "kes-oracle/v1 node-11.1.3 API11.6.0.0 crypto2.5.1.0 Sum6KES")

bad :: IO a
bad = throwIO (userError "oracle request rejected")
exact :: Int -> B.ByteString -> IO ()
exact n b = unless (B.length b == n) bad
word :: B.ByteString -> Word64
word = B.foldl' (\a b -> shiftL a 8 .|. fromIntegral b) 0
be32 :: Int -> B.ByteString
be32 n = B.pack [fromIntegral (shiftR n s) | s <- [24,16,8,0]]
period :: Word8 -> IO Word
period p = if p < 64 then pure (fromIntegral p) else bad
withKey :: B.ByteString -> (SignKeyKES K -> IO a) -> IO a
withKey bytes action = do
  exact 608 bytes
  key <- rawDeserialiseSignKeyKES @K bytes >>= maybe bad pure
  bracket (pure key) forgetSignKeyKES action
vk :: B.ByteString -> IO (VerKeyKES K)
vk b = exact 32 b >> maybe bad pure (rawDecodeFixedSized @(VerKeyKES K) b)
message :: B.ByteString -> IO ()
message b = when (B.length b > 4096) bad
success :: B.ByteString -> IO ()
success payload = do
  let result = B.pack [1,0] <> payload
  B.hPut stdout (be32 (B.length result))
  B.hPut stdout result
  hFlush stdout

-- File operations take the exact conventional JSON bytes, not a path; no
-- intermediate key file is needed. Native envelope/CBOR decoders are the oracle.
envelope :: B.ByteString -> IO Api.TextEnvelope
envelope b = either (const bad) pure (A.eitherDecodeStrict' b)

generated :: MLockedSeed 32 -> IO B.ByteString
generated seed =
  bracket (genKeyKES @K seed) forgetSignKeyKES $ \key -> do
    state <- rawSerialiseSignKeyKES key
    exact 608 state
    public <- deriveVerKeyKES key
    pure (rawEncodeFixedSized public <> state)

run :: Word8 -> B.ByteString -> IO B.ByteString
run 0 b = exact 0 b >> pure identity
run 1 b = exact 0 b >> bracket (mlockedSeedNewRandom @32) mlockedSeedFinalize generated
run 2 b = withKey b $ \key -> rawEncodeFixedSized <$> deriveVerKeyKES key
run 3 b = do
  exact 609 b
  p <- period (B.head b)
  withKey (B.tail b) $ \key -> do
    next <- updateKES @K () key p
    case next of
      Nothing -> pure (B.singleton 0)
      Just key' -> bracket (pure key') forgetSignKeyKES $ \k -> do
        bytes <- rawSerialiseSignKeyKES k
        exact 608 bytes
        pure (B.singleton 1 <> bytes)
run 4 b = do
  when (B.length b < 609) bad
  p <- period (B.head b)
  let msg = B.drop 609 b
  message msg
  withKey (B.take 608 (B.tail b)) $ \key ->
    rawEncodeFixedSized <$> signKES @K () p msg key
run 5 b = do
  when (B.length b < 481) bad
  p <- period (B.head b)
  public <- vk (B.take 32 (B.drop 1 b))
  sig <- maybe bad pure (rawDecodeFixedSized @(SigKES K) (B.take 448 (B.drop 33 b)))
  let msg = B.drop 481 b
  message msg
  pure (B.singleton (either (const 0) (const 1) (verifyKES @K () public p msg sig)))
run 6 b = do
  exact 48 b
  public <- vk (B.take 32 b)
  let counter = word (B.take 8 (B.drop 32 b))
      start = O.KESPeriod (fromIntegral (word (B.drop 40 b)))
  pure (getSignableRepresentation (O.OCertSignable @StandardCrypto public counter start))
run 7 b = do
  env <- envelope b
  key <- either (const bad) pure (Api.deserialiseFromTextEnvelope env :: Either Api.TextEnvelopeError (Api.VerificationKey Api.KesKey))
  pure (Api.serialiseToRawBytes key)
run 8 b = do
  env <- envelope b
  key <- either (const bad) pure (Api.deserialiseFromTextEnvelope env :: Either Api.TextEnvelopeError (Api.SigningKey Api.KesKey))
  -- Derivation uses the native conventional-file key instance, not our codec.
  pure (Api.serialiseToRawBytes (Api.getVerificationKey key))
run 9 b = do
  env <- envelope b
  OperationalCertificate cert cold <- either (const bad) pure (Api.deserialiseFromTextEnvelope env)
  coldVk <- maybe bad pure (rawDecodeFixedSized @(D.VerKeyDSIGN Ed25519DSIGN) (Api.serialiseToRawBytes cold))
  let valid = D.verifySignedDSIGN () coldVk (O.ocertToSignable cert) (O.ocertSigma cert)
  pure (B.singleton (either (const 0) (const 1) valid) <> Api.serialiseToRawBytes cold <> getSignableRepresentation (O.ocertToSignable cert))
run 10 b = do
  exact 48 b
  public <- vk (B.take 32 b)
  -- The real release's DSIGN and certificate types issue a disposable cert.
  seed <- withBinaryFile "/dev/urandom" ReadMode (\h -> B.hGet h 32)
  exact 32 seed
  let cold = D.genKeyDSIGN @Ed25519DSIGN (mkSeedFromBytes seed)
      coldRaw = rawEncodeFixedSized (D.deriveVerKeyDSIGN cold)
      counter = word (B.take 8 (B.drop 32 b))
      start = O.KESPeriod (fromIntegral (word (B.drop 40 b)))
      signable = O.OCertSignable @StandardCrypto public counter start
      cert = O.OCert public counter start (D.signedDSIGN () signable cold)
  coldApi <- either (const bad) pure (Api.deserialiseFromRawBytes (Api.AsVerificationKey Api.AsStakePoolKey) coldRaw)
  pure (L.toStrict (A.encode (Api.serialiseToTextEnvelope Nothing (OperationalCertificate cert coldApi))))
run 11 b = do
  exact 32 b
  bracket (mlockedSeedNew @32) mlockedSeedFinalize $ \seed -> do
    B.useAsCString b $ \src ->
      mlockedSeedUseAsCPtr seed $ \dst -> copyBytes dst (castPtr src) 32
    generated seed
run _ _ = bad

main :: IO ()
main = handle (\(_ :: SomeException) -> exitFailure) $ do
  hSetBinaryMode stdin True
  hSetBinaryMode stdout True
  hSetBuffering stdout NoBuffering
  -- PR_SET_DUMPABLE=4; fresh cgroup-v2 no-swap isolation covers all transient
  -- serialized keys and native heap objects, not only native locked key cells.
  noDump 4 0 0 0 0 >>= \r -> unless (r == 0) bad
  membership <- readFile "/proc/self/cgroup"
  group <- case [drop 3 l | l <- lines membership, take 3 l == "0::"] of
    [g] | take 1 g == "/" && all (/= "..") (words (map (\c -> if c == '/' then ' ' else c) g)) -> pure g
    _ -> bad
  limits <- mapM (\name -> readFile ("/sys/fs/cgroup" ++ group ++ "/" ++ name)) ["memory.swap.max", "memory.swap.current"]
  unless (map words limits == [["0"], ["0"]]) bad
  sodiumInit
  header <- B.hGet stdin 4
  exact 4 header
  let size = word header
  when (size < 2 || size > 16384) bad
  body <- B.hGet stdin (fromIntegral size)
  exact (fromIntegral size) body
  trailing <- B.hGet stdin 1
  unless (B.null trailing && B.head body == 1) bad
  output <- run (B.index body 1) (B.drop 2 body)
  when (B.length output > 16382) bad
  success output
