package com.example.nfcinspector;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.MifareUltralight;
import android.nfc.tech.Ndef;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcV;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

public class MainActivity extends Activity implements NfcAdapter.ReaderCallback {
    NfcAdapter nfc;
    TextView out;
    String report = "";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0E1014);
        root.setPadding(24, 64, 24, 24);
        Button copy = new Button(this);
        copy.setText("Copier le rapport");
        copy.setTextSize(18);
        copy.setOnClickListener(v -> {
            ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("nfc", report));
            Toast.makeText(this, "Rapport copié", Toast.LENGTH_SHORT).show();
        });
        ScrollView sv = new ScrollView(this);
        out = new TextView(this);
        out.setTextColor(0xFFE8EAF0);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextSize(12);
        out.setTextIsSelectable(true);
        sv.addView(out);
        root.addView(copy, new LinearLayout.LayoutParams(-1, 180));
        root.addView(sv, new LinearLayout.LayoutParams(-1, 0, 1f));
        setContentView(root);
        nfc = NfcAdapter.getDefaultAdapter(this);
        show("Approchez le bracelet du dos du téléphone.");
    }

    @Override protected void onResume() {
        super.onResume();
        if (nfc == null) { show("Ce téléphone n'a pas de NFC."); return; }
        if (!nfc.isEnabled()) { show("NFC désactivé : activez-le dans les réglages, puis revenez ici."); return; }
        nfc.enableReaderMode(this, this,
                NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B
                        | NfcAdapter.FLAG_READER_NFC_F | NfcAdapter.FLAG_READER_NFC_V, null);
    }

    @Override protected void onPause() {
        super.onPause();
        if (nfc != null && nfc.isEnabled()) nfc.disableReaderMode(this);
    }

    void show(String s) {
        report = s;
        runOnUiThread(() -> out.setText(s));
    }

    @Override public void onTagDiscovered(Tag tag) {
        StringBuilder r = new StringBuilder();
        try { inspect(tag, r); } catch (Throwable t) { r.append("\nERREUR : ").append(t); }
        show(r.toString());
    }

    void inspect(Tag tag, StringBuilder r) {
        byte[] id = tag.getId();
        r.append("=== PUCE ===\n");
        r.append("Lu le : ").append(new SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.FRANCE).format(new Date())).append("\n");
        r.append("UID : ").append(hex(id, ":")).append(" (").append(id.length).append(" octets)\n");
        r.append("Fabricant (octet 1) : ").append(manuf(id[0] & 0xFF)).append("\n");
        r.append("Technologies : ").append(Arrays.toString(tag.getTechList()).replace("android.nfc.tech.", "")).append("\n");

        SharedPreferences sp = getSharedPreferences("scans", MODE_PRIVATE);
        String k = hex(id, "");
        int n = sp.getInt(k, 0) + 1;
        sp.edit().putInt(k, n).apply();
        r.append("Lectures de cette puce sur ce téléphone : ").append(n).append("\n");

        NfcA a = NfcA.get(tag);
        if (a != null) {
            r.append("ATQA : ").append(hex(a.getAtqa(), " ")).append("   SAK : 0x")
                    .append(String.format("%02X", a.getSak())).append("\n");
        }

        Ndef nd = Ndef.get(tag);
        if (nd != null) {
            r.append("\n=== NDEF ===\nType : ").append(nd.getType())
                    .append("\nCapacité : ").append(nd.getMaxSize()).append(" octets")
                    .append("\nEn écriture : ").append(nd.isWritable())
                    .append("\nPeut être verrouillée : ").append(nd.canMakeReadOnly()).append("\n");
            NdefMessage m = nd.getCachedNdefMessage();
            if (m != null) {
                for (NdefRecord rec : m.getRecords()) {
                    r.append("Record TNF=").append(rec.getTnf())
                            .append(" type=").append(printable(rec.getType()))
                            .append("\n  hex : ").append(hex(rec.getPayload(), " "))
                            .append("\n  texte : ").append(printable(rec.getPayload())).append("\n");
                }
            }
        }

        MifareUltralight mu = MifareUltralight.get(tag);
        if (mu != null) ultralight(mu, r);

        MifareClassic mc = MifareClassic.get(tag);
        if (mc != null) {
            r.append("\n=== MIFARE CLASSIC ===\nTaille : ").append(mc.getSize()).append(" octets, ")
                    .append(mc.getSectorCount()).append(" secteurs, ").append(mc.getBlockCount())
                    .append(" blocs\n(Contenu protégé par clés : non lu.)\n");
        }
        IsoDep d = IsoDep.get(tag);
        if (d != null) {
            r.append("\n=== ISO-DEP ===\nOctets historiques : ").append(hex(d.getHistoricalBytes(), " ")).append("\n");
        }
        NfcV v = NfcV.get(tag);
        if (v != null) {
            r.append("\n=== NFC-V ===\nDSFID : ").append(v.getDsfId()).append("\n");
        }
    }

    void ultralight(MifareUltralight mu, StringBuilder r) {
        r.append("\n=== NTAG / ULTRALIGHT ===\n");
        int pages = 16, cfg = -1;
        String name = "Modèle non identifié";
        boolean ntag = false;
        try {
            mu.connect();
            byte[] v = tx(mu, new byte[]{0x60});
            if (v != null && v.length >= 8) {
                int type = v[2] & 0xFF, st = v[6] & 0xFF;
                r.append("GET_VERSION : ").append(hex(v, " ")).append("\n");
                if (type == 4) {
                    ntag = true;
                    if (st == 0x0F) { name = "NTAG213"; pages = 45; cfg = 41; }
                    else if (st == 0x11) { name = "NTAG215"; pages = 135; cfg = 131; }
                    else if (st == 0x13) { name = "NTAG216"; pages = 231; cfg = 227; }
                    else if (st == 0x0B) { name = "NTAG210"; pages = 20; cfg = 16; }
                    else if (st == 0x0E) { name = "NTAG212"; pages = 41; cfg = 37; }
                } else if (type == 3) {
                    if (st == 0x0B) { name = "MIFARE Ultralight EV1 (MF0UL11)"; pages = 20; cfg = 16; }
                    else if (st == 0x0E) { name = "MIFARE Ultralight EV1 (MF0UL21)"; pages = 41; cfg = 37; }
                }
                r.append("Modèle : ").append(name).append("\n");
            } else {
                r.append("GET_VERSION non pris en charge (probablement un Ultralight de première génération).\n");
            }

            r.append("\n--- Mémoire (pages de 4 octets) ---\n");
            byte[] first = null;
            for (int p = 0; p < pages; p += 4) {
                byte[] d;
                try { d = mu.readPages(p); }
                catch (Exception e) { r.append("Lecture arrêtée à la page ").append(p).append(" : ").append(e.getMessage()).append("\n"); break; }
                if (p == 0) first = d;
                for (int i = 0; i < 4 && p + i < pages; i++) {
                    byte[] w = Arrays.copyOfRange(d, i * 4, i * 4 + 4);
                    r.append(String.format("%03d : %s  %s\n", p + i, hex(w, " "), printable(w)));
                }
            }
            if (first != null) {
                r.append("\nOctets de verrouillage statiques : ").append(hex(Arrays.copyOfRange(first, 10, 12), " "))
                        .append("\nCapability Container : ").append(hex(Arrays.copyOfRange(first, 12, 16), " ")).append("\n");
            }

            if (cfg > 0) {
                try {
                    byte[] c = mu.readPages(cfg);
                    r.append("\n--- Configuration (page ").append(cfg).append(") ---\n");
                    r.append("Brut : ").append(hex(Arrays.copyOf(c, 8), " ")).append("\n");
                    int auth0 = c[3] & 0xFF;
                    r.append("AUTH0 (1re page protégée par mot de passe) : ").append(auth0)
                            .append(auth0 >= pages ? " (aucune protection)" : " (protection active)").append("\n");
                    if (ntag) {
                        int acc = c[4] & 0xFF;
                        r.append("Compteur NFC activé : ").append((acc & 0x10) != 0 ? "oui" : "non").append("\n");
                        r.append("Compteur protégé par mot de passe : ").append((acc & 0x08) != 0 ? "oui" : "non").append("\n");
                        r.append("Écriture protégée par mot de passe : ").append((acc & 0x80) != 0 ? "oui" : "non (lecture libre)").append("\n");
                    }
                } catch (Exception e) { r.append("Configuration illisible : ").append(e.getMessage()).append("\n"); }
            }

            r.append("\n--- Authenticité et compteur ---\n");
            byte[] sig = tx(mu, new byte[]{0x3C, 0x00});
            r.append("Signature d'origine NXP (32 octets) : ").append(sig != null ? hex(sig, "") : "non disponible").append("\n");
            byte[] cnt = tx(mu, new byte[]{0x39, 0x02});
            if (cnt != null && cnt.length >= 3) {
                r.append("Compteur NFC : ").append((cnt[0] & 0xFF) | ((cnt[1] & 0xFF) << 8) | ((cnt[2] & 0xFF) << 16)).append("\n");
            } else {
                r.append("Compteur NFC : indisponible (désactivé sur cette puce)\n");
            }
        } catch (Exception e) {
            r.append("Erreur : ").append(e).append("\n");
        } finally {
            try { mu.close(); } catch (Exception ignore) { }
        }
    }

    byte[] tx(MifareUltralight mu, byte[] cmd) {
        try { return mu.transceive(cmd); }
        catch (Exception e) {
            try { mu.close(); mu.connect(); } catch (Exception ignore) { }
            return null;
        }
    }

    static String manuf(int b) {
        switch (b) {
            case 0x04: return "NXP Semiconductors";
            case 0x02: return "STMicroelectronics";
            case 0x05: return "Infineon";
            case 0x07: return "Texas Instruments";
            case 0x08: return "UID aléatoire";
            default: return String.format("code 0x%02X non répertorié", b);
        }
    }

    static String hex(byte[] b, String sep) {
        if (b == null) return "aucun";
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if (i > 0) s.append(sep);
            s.append(String.format("%02X", b[i]));
        }
        return s.toString();
    }

    static String printable(byte[] b) {
        if (b == null) return "";
        String s = new String(b, StandardCharsets.UTF_8);
        StringBuilder o = new StringBuilder();
        for (char c : s.toCharArray()) o.append(c >= 32 && c < 127 ? c : '.');
        return o.toString();
    }
}
