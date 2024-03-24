{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.GPGME.Internals where

import Data.Bits
import Foreign.C
import Foreign.C.ConstPtr
import Foreign.Ptr
import Foreign.Storable

data {-# CTYPE "gpgme.h" "struct gpgme_context" #-} GpgmeContext
data {-# CTYPE "gpgme.h" "struct _gpgme_op_keylist_result" #-} GpgmeKeylistResult
  = GpgmeKeylistResult
  { truncated :: CUInt
  }
  deriving (Show, Eq)

instance Storable GpgmeKeylistResult where
  sizeOf _ = sizeOf (undefined :: CUInt)
  alignment _ = alignment (undefined :: CUInt)
  peek ptr = do
    truncated <- (`shiftR` 31) <$> peekByteOff ptr 0
    return GpgmeKeylistResult{..}
  poke ptr GpgmeKeylistResult{..} = pokeByteOff ptr 0 (truncated `shiftL` 31)

data {-# CTYPE "gpgme.h" "struct _gpgme_key" #-} GpgmeKey = GpgmeKey
  { _refs :: CUInt
  , flags :: CUInt
  , protocol :: CInt
  , issuer_serial :: CString
  , issuer_name :: CString
  , chain_id :: CString
  , owner_trust :: CInt
  , subkeys :: Ptr GpgmeSubkey
  , uids :: Ptr GpgmeUserId
  , _last_subkey :: Ptr GpgmeSubkey
  , _last_uid :: Ptr GpgmeUserId
  , keylist_mode :: CUInt
  , fpr :: CString
  , last_update :: CULong
  }
  deriving (Show, Eq)

instance Storable GpgmeKey where
  sizeOf _ = 104
  alignment _ = 8
  peek ptr = do
    _refs <- peekByteOff ptr 0
    flags <- peekByteOff ptr 4
    protocol <-
      peekByteOff ptr 8
    issuer_serial <-
      peekByteOff ptr 16
    issuer_name <-
      peekByteOff ptr 24
    chain_id <-
      peekByteOff ptr 32
    owner_trust <-
      peekByteOff ptr 40
    subkeys <-
      peekByteOff ptr 48
    uids <-
      peekByteOff ptr 56
    _last_subkey <-
      peekByteOff ptr 64
    _last_uid <-
      peekByteOff ptr 72
    keylist_mode <-
      peekByteOff ptr 80
    fpr <-
      peekByteOff ptr 88
    last_update <-
      peekByteOff ptr 96
    return GpgmeKey{..}
  poke _ _ = undefined

data {-# CTYPE "gpgme.h" "struct _gpgme_subkey" #-} GpgmeSubkey
  deriving (Show, Eq)

data {-# CTYPE "gpgme.h" "struct _gpgme_user_id" #-} GpgmeUserId
  deriving (Show, Eq)

foreign import capi "gpgme.h value GPGME_PROTOCOL_OPENPGP"
  c_GPGME_PROTOCOL_OPENPGP :: CInt

foreign import capi "gpgme.h gpgme_check_version"
  c_gpgme_check_version :: CString -> IO (ConstPtr CChar)

foreign import capi "gpgme.h gpgme_new"
  c_gpgme_new :: Ptr (Ptr GpgmeContext) -> IO CInt

foreign import capi "gpgme.h gpgme_set_protocol"
  c_gpgme_set_protocol :: Ptr GpgmeContext -> CInt -> IO CInt

foreign import capi "gpgme.h gpgme_op_keylist_start"
  c_gpgme_op_keylist_start ::
    Ptr GpgmeContext -> ConstPtr CChar -> CBool -> IO CInt

foreign import capi "gpgme.h gpgme_op_keylist_end"
  c_gpgme_op_keylist_end ::
    Ptr GpgmeContext -> IO CInt

foreign import capi "gpgme.h gpgme_op_keylist_result"
  c_gpgme_op_keylist_result :: Ptr GpgmeContext -> IO (Ptr GpgmeKeylistResult)

foreign import capi "gpgme.h gpgme_op_keylist_next"
  c_gpgme_op_keylist_next :: Ptr GpgmeContext -> Ptr (Ptr GpgmeKey) -> IO CInt
