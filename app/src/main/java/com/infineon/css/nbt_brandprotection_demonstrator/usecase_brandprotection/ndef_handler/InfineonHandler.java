// SPDX-FileCopyrightText: Copyright (c) 2024-2025 Infineon Technologies AG
// SPDX-License-Identifier: MIT

package com.infineon.css.nbt_brandprotection_demonstrator.usecase_brandprotection.ndef_handler;

import android.util.Log;

import androidx.annotation.NonNull;

import com.infineon.hsw.ndef.NdefManager;
import com.infineon.hsw.ndef.IfxNdefMessage;
import com.infineon.hsw.ndef.exceptions.NdefException;
import com.infineon.hsw.ndef.records.AbstractRecord;
import com.infineon.hsw.ndef.records.rtd.IfxNdefRecord;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Handler using the a Infineon Java NDEF library to handle the standardized NDEF file format,
 * parse and validate the certificate
 */
public class InfineonHandler implements INdefHandler {

    /**
     * Certificate parser using the Infineon Java NDEF lib. to parses a certificate from a raw ndef message
     *
     * @param rawMessage Raw ndef message from a nfc device
     * @return Returns the X509 certificate parsed from a raw ndef message
     * @throws NdefException An exception in the NDEF file specific library occurred
     */
    @Override
    public X509Certificate parseCertFromNdef(@NonNull byte[] rawMessage) throws NdefException {

        IfxNdefMessage decodedMessage = NdefManager.getInstance().decode(rawMessage);
        List<AbstractRecord> decodedRecords = decodedMessage.getNdefRecords();
        IfxNdefRecord decodedExtRecord = (IfxNdefRecord)decodedRecords.get(1);
        try (ByteArrayInputStream is = new ByteArrayInputStream(decodedExtRecord.getPayload())) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(is);
        } catch (Exception e) {
            Log.e("NBT", "Validation of certificate failed", e);
        }

        return null;
    }

}
