// SPDX-FileCopyrightText: 2024 Infineon Technologies AG
// SPDX-License-Identifier: MIT

package com.infineon.css.nbt_brandprotection_demonstrator.usecase_brandprotection.ndef_handler;

import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Handler using the default Android NDEF library to handle the standardized NDEF file format,
 * parse and validate the certificate
 */
@SuppressWarnings("unused")
public class AndroidHandler implements INdefHandler {

    /**
     * Certificate parser for the Android NDEF lib. handler, parses a certificate from a raw ndef message
     *
     * @param rawMessage Raw ndef message from a nfc device
     * @return Returns the X509 certificate parsed from a raw ndef message
     */
    @Override
    public X509Certificate parseCertFromNdef(@NonNull byte[] rawMessage) {

        try {

            NdefMessage message = new NdefMessage(rawMessage);
            NdefRecord[] records = message.getRecords();

            try (ByteArrayInputStream is = new ByteArrayInputStream(records[1].getPayload())) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                return (X509Certificate) certificateFactory.generateCertificate(is);
            } catch (Exception e) {
                Log.e("NBT", "Validation of certificate failed", e);
            }
        } catch (FormatException e) {
            e.printStackTrace();
        }

        return null;
    }
}
