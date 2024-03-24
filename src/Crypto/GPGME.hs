module Crypto.GPGME (
  module Crypto.GPGME,
  c_GPGME_PROTOCOL_OPENPGP,
) where

import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.State
import Crypto.GPGME.Internals
import Foreign.C
import Foreign.C.ConstPtr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
import Foreign.Ptr
import Foreign.Storable

type GpgmeState = StateT (Ptr GpgmeContext) IO

runGPGME :: GpgmeState a -> IO a
runGPGME gpgst =
  evalStateT
    ( do
        _ <- gpgmeCheckVersion
        gpgmeNew
        gpgmeSetProtocol c_GPGME_PROTOCOL_OPENPGP
        gpgst
    )
    nullPtr

gpgmeCheckVersion :: GpgmeState String
gpgmeCheckVersion = do
  res <- unConstPtr <$> liftIO (c_gpgme_check_version nullPtr)
  if res == nullPtr
    then fail "failed to get version"
    else liftIO (peekCString res)

gpgmeNew :: GpgmeState ()
gpgmeNew = do
  put
    =<< liftIO
      ( alloca $ \ctxPtr -> do
          err <- c_gpgme_new ctxPtr
          if err /= 0
            then fail "failed to create new gpgme context"
            else peek ctxPtr
      )

-- gpgListKeys :: Bool -> GpgmeState ()
gpgListKeys secret = do
  ctxPtr <- get
  startErr <-
    liftIO $ c_gpgme_op_keylist_start ctxPtr (ConstPtr nullPtr) (fromBool secret)
  when (startErr /= 0) (fail "failed to start list keys")

  liftIO $ alloca $ \ptr -> do
    err <- c_gpgme_op_keylist_next ctxPtr ptr
    when (err /= 0) (fail "failed to get next key")
    thing <- peek ptr >>= peek
    peekCString (fpr thing) >>= print
    print thing

  endErr <- liftIO $ c_gpgme_op_keylist_end ctxPtr
  when (endErr /= 0) (fail "failed to end list keys")

  _ <- liftIO $ c_gpgme_op_keylist_result ctxPtr
  return ()

gpgmeSetProtocol :: CInt -> GpgmeState ()
gpgmeSetProtocol protocol = do
  ctxPtr <- get
  err <- liftIO (c_gpgme_set_protocol ctxPtr protocol)
  when (err /= 0) (fail "set protocol failed")
