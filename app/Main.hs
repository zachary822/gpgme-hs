{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad.IO.Class
import Control.Monad.Trans.State
import Crypto.GPGME

main :: IO ()
main = do
  thing <- runGPGME $ do
    gpgListKeys False
  print thing
