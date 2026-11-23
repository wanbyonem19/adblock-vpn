package com.bahlil.adblock;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.util.LinkedList;

public class MainActivity extends Activity {
    private static final int REQUEST_VPN = 0;
    private static final int REQUEST_NOTIF = 1;

    private TextView statusText;
    private TextView countText;
    private TextView recentText;
    private Button toggleButton;

    private final Handler handler = new Handler();
    private final Runnable updater = new Runnable() {
        @Override
        public void run() {
            updateUi();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        statusText = (TextView) findViewById(R.id.statusText);
        countText = (TextView) findViewById(R.id.countText);
        recentText = (TextView) findViewById(R.id.recentText);
        toggleButton = (Button) findViewById(R.id.toggleButton);
        toggleButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onToggle();
            }
        });
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQUEST_NOTIF);
        }
        updateUi();
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(updater);
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(updater);
    }

    private void onToggle() {
        if (AdBlockVpnService.running) {
            stopService(new Intent(this, AdBlockVpnService.class));
            updateUi();
            return;
        }
        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQUEST_VPN);
        } else {
            startService(new Intent(this, AdBlockVpnService.class));
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startService(new Intent(this, AdBlockVpnService.class));
        }
        updateUi();
    }

    private void updateUi() {
        boolean on = AdBlockVpnService.running;
        statusText.setText(on ? "Status: Aktif" : "Status: Mati");
        toggleButton.setText(on ? "MATIKAN" : "NYALAKAN");
        countText.setText("Iklan diblokir: " + AdBlockVpnService.blockedCount);
        LinkedList<String> recent = AdBlockVpnService.getRecentBlocked();
        if (recent.isEmpty()) {
            recentText.setText("Belum ada iklan diblokir");
        } else {
            StringBuilder sb = new StringBuilder();
            for (String d : recent) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append("• ").append(d);
            }
            recentText.setText(sb.toString());
        }
    }
}
