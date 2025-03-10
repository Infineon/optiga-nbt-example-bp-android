// SPDX-FileCopyrightText: Copyright (c) 2024-2025 Infineon Technologies AG
// SPDX-License-Identifier: MIT


package com.infineon.css.nbt_brandprotection_demonstrator;

import static com.infineon.css.nbt_brandprotection_demonstrator.usecase_brandprotection.utils.InterfaceChannel.InitializeChannel;

import androidx.appcompat.app.AppCompatActivity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Parcelable;
import android.widget.ImageView;
import android.widget.TextView;

import com.infineon.css.nbt_brandprotection_demonstrator.usecase_brandprotection.BrandProtectionUsecase;
import com.infineon.hsw.apdu.ApduChannel;
import com.infineon.hsw.channel.IChannel;

import java.io.InputStream;
import java.util.Scanner;

/**
 * This demonstrator allows the user to test the brand protection use case capabilities of a NBT device.
 * MainActivity() will trigger the steps to run the brand protection use case and present the
 * result to the user
 */
public class MainActivity extends AppCompatActivity {

    /**
     * GUI text view printing the validation status
     */
    TextView textViewState;

    /**
     * Image showing the validation state
     */
    ImageView imageViewState;

    /**
     * Flag to check if app is back in default state
     */
    boolean isDefault;

    /**
     * Waiting time until activity resets
     */
    private static final int WAITING_TIME = 3000;

    /**
     * To store manufacturing CA certificate of the NBT
     * <p>
     * Certificate has been verified against NFC_bridge_CL_tag_devices_root_CA.pem beforehand.
     */
    public static String manufacturing_ca_cert;

    /**
     * To store root ca certificate used by NBT example application (non-productive)
     */
    public static String usecase_ca_cert;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //GUI initialization
        textViewState = findViewById(R.id.textView_verify);
        imageViewState = findViewById(R.id.image_state);
        isDefault = true;

        //Read ca root certificates from file (stored in app resources)
        try {
            Resources res = getResources();
            InputStream in_s = res.openRawResource(R.raw.sample_root_certificate);
            Scanner s = new Scanner(in_s).useDelimiter("\\A");
            manufacturing_ca_cert = s.hasNext() ? s.next() : "";
            in_s.close();
            in_s = res.openRawResource(R.raw.nfc_bridge_cl_tag_devices_manufacturing_ca);
            s = new Scanner(in_s).useDelimiter("\\A");
            usecase_ca_cert = s.hasNext() ? s.next() : "";
            in_s.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    protected void onResume() {
        super.onResume();

        //Setting intent to recognized NFC Type A tags with NFC interface
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_MUTABLE);
        IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        try {
            ndef.addDataType("*/*");
        } catch (IntentFilter.MalformedMimeTypeException e) {
            throw new RuntimeException("fail", e);
        }
        IntentFilter[] intentFiltersArray = new IntentFilter[] {ndef, };
        String[][] techListsArray = new String[][] { new String[] { NfcA.class.getName() } };
        NfcAdapter.getDefaultAdapter(this).enableForegroundDispatch(this, pendingIntent, intentFiltersArray, techListsArray);
    }

    @Override
    protected void onPause() {
        super.onPause();
        NfcAdapter.getDefaultAdapter(this).disableForegroundDispatch(this);
    }

    /**
     * Intent is called when a NFC tag with a NDEF message is detected. Communication channel is
     * opened and further use case steps are triggered
     *
     * @param intent NFC tag intent
     */
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);

        if (isDefault && NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {

            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            IsoDep com = IsoDep.get(tag);
            IChannel channel = InitializeChannel(com);
            ApduChannel apduChannel = new ApduChannel(channel);

            Parcelable[] rawNdefMessage = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);

            handleUsecase(apduChannel, rawNdefMessage);
        }
    }


    /**
     * NFC communication channel is used to:
     * - Check if certificate is verified
     * - Send challenge to tag
     * - Check if responding ECDSA signature is verified
     * These steps are handled by the brandProtectionUsecase() class and triggered in its execute method
     *
     * @param apduChannel NFC communication channel
     * @param rawNdefMessage NDEF message of tag
     */
    private void handleUsecase(ApduChannel apduChannel, Parcelable[] rawNdefMessage) {

        try {

            if (rawNdefMessage != null) {
                apduChannel.connect();

                BrandProtectionUsecase brandProtectionUsecase = new BrandProtectionUsecase(apduChannel);
                brandProtectionUsecase.execute(rawNdefMessage);

                setValidGui();
                isDefault = false;
                resetState();

            }else{
                runOnUiThread(() -> textViewState.setText(R.string.string_empty_file));
            }
            apduChannel.disconnect();
        }catch (Exception e) {
            setInvalidGui();
        }

    }

    /**
     * Sets the user output and the GUI according to the certificate and signature validation
     */
    public void setInvalidGui() {
        runOnUiThread(() -> {
            textViewState.setText(R.string.string_bad_verification);
            imageViewState.setImageResource(R.drawable.icon_cert_red);
        });
    }

    /**
     * Sets the user output and the GUI according to the certificate and signature validation
     */
    public void setValidGui() {
        runOnUiThread(() -> {
            imageViewState.setImageResource(R.drawable.icon_cert_green);
            textViewState.setText(R.string.string_good_verification);
        });
    }

    /**
     * Resets the state of the App after a few seconds
     */
    private void resetState() {
            new Handler(Looper.getMainLooper()).postDelayed(() -> runOnUiThread(() -> {
                textViewState.setText(R.string.string_to_verify);
                imageViewState.setImageResource(R.drawable.icon_cert_lightgrey);
                isDefault = true;
            }), WAITING_TIME);
    }
}