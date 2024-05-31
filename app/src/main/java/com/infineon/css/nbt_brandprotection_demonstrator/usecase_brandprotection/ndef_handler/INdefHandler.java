// SPDX-FileCopyrightText: 2024 Infineon Technologies AG
// SPDX-License-Identifier: MIT

package com.infineon.css.nbt_brandprotection_demonstrator.usecase_brandprotection.ndef_handler;

import androidx.annotation.NonNull;

import com.infineon.hsw.ndef.exceptions.NdefException;

import java.security.cert.X509Certificate;

/**
 * Handler for Ndef file format
 */
public interface INdefHandler
{
        /**
         * Parses a X509 certificate from a raw ndef message
         *
         * @param rawMessage Raw ndef message from a nfc device
         * @return Returns the X509 certificate parsed from a raw ndef message
         * @throws NdefException An exception in the NDEF file specific library occurred
         */
        X509Certificate parseCertFromNdef(@NonNull byte[] rawMessage) throws NdefException;
}
