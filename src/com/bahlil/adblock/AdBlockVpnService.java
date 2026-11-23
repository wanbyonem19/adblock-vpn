package com.bahlil.adblock;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.LinkedList;

/**
 * VPN ad-blocker (DNS-only, no root).
 * Routes only DNS traffic through the TUN interface, checks the queried
 * domain against a blocklist, answers NXDOMAIN for blocked domains and
 * forwards everything else to 8.8.8.8.
 */
public class AdBlockVpnService extends VpnService {
    private static final String TAG = "AdBlockVpn";
    private static final int NOTIF_ID = 1;
    private static final String CHANNEL_ID = "adblock_vpn";
    private static final String UPSTREAM_DNS = "8.8.8.8";
    private static final int DNS_PORT = 53;

    public static volatile boolean running = false;
    public static volatile int blockedCount = 0;
    private static final LinkedList<String> recentBlocked = new LinkedList<String>();
    private static final int RECENT_MAX = 20;

    private ParcelFileDescriptor tunFd;
    private Thread worker;
    private HashSet<String> blocklist = new HashSet<String>();

    public static synchronized void noteBlocked(String domain) {
        blockedCount++;
        if (recentBlocked.isEmpty() || !recentBlocked.getFirst().equals(domain)) {
            recentBlocked.addFirst(domain);
            while (recentBlocked.size() > RECENT_MAX) {
                recentBlocked.removeLast();
            }
        }
    }

    public static synchronized LinkedList<String> getRecentBlocked() {
        return new LinkedList<String>(recentBlocked);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (running) {
            return START_STICKY;
        }
        startForeground(NOTIF_ID, buildNotification());
        loadBlocklist();
        worker = new Thread(new Runnable() {
            @Override
            public void run() {
                runVpn();
            }
        }, "AdBlockVpnWorker");
        worker.start();
        return START_STICKY;
    }

    private Notification buildNotification() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "AdBlock VPN", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("AdBlock VPN sedang aktif");
            nm.createNotificationChannel(ch);
        }
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
                this, 0, open, PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
        }
        return b.setContentTitle("AdBlock VPN aktif")
                .setContentText("Memblokir iklan dan pelacak")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }

    private void loadBlocklist() {
        blocklist = new HashSet<String>();
        try {
            InputStream is = getAssets().open("blocklist.txt");
            BufferedReader r = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim().toLowerCase();
                if (!line.isEmpty()) {
                    blocklist.add(line);
                }
            }
            r.close();
            Log.i(TAG, "Blocklist loaded: " + blocklist.size() + " domains");
        } catch (IOException e) {
            Log.e(TAG, "Failed to load blocklist", e);
        }
    }

    private boolean isBlocked(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        String d = domain.toLowerCase();
        while (true) {
            if (blocklist.contains(d)) {
                return true;
            }
            int dot = d.indexOf('.');
            if (dot < 0) {
                return false;
            }
            d = d.substring(dot + 1);
        }
    }

    private void runVpn() {
        try {
            Builder builder = new Builder();
            builder.setSession("AdBlock VPN");
            builder.addAddress("10.0.0.2", 32);
            builder.addDnsServer(UPSTREAM_DNS);
            builder.addRoute(UPSTREAM_DNS, 32);
            builder.addRoute("1.1.1.1", 32);
            tunFd = builder.establish();
            if (tunFd == null) {
                Log.e(TAG, "establish() returned null");
                stopSelf();
                return;
            }
            running = true;
            FileInputStream in = new FileInputStream(tunFd.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(tunFd.getFileDescriptor());
            byte[] buf = new byte[32767];
            DatagramSocket dnsSocket = new DatagramSocket();
            protect(dnsSocket);
            dnsSocket.setSoTimeout(3000);
            InetAddress upstream = InetAddress.getByName(UPSTREAM_DNS);
            while (running) {
                int len;
                try {
                    len = in.read(buf);
                } catch (IOException e) {
                    break;
                }
                if (len <= 0) {
                    continue;
                }
                byte[] packet = new byte[len];
                System.arraycopy(buf, 0, packet, 0, len);
                byte[] reply = handlePacket(packet, dnsSocket, upstream);
                if (reply != null) {
                    try {
                        out.write(reply);
                    } catch (IOException e) {
                        break;
                    }
                }
            }
            try {
                dnsSocket.close();
            } catch (Exception ignored) {
            }
            try {
                in.close();
            } catch (Exception ignored) {
            }
            try {
                out.close();
            } catch (Exception ignored) {
            }
        } catch (Exception e) {
            Log.e(TAG, "VPN loop failed", e);
        } finally {
            running = false;
            try {
                if (tunFd != null) {
                    tunFd.close();
                }
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Returns a full IPv4 packet to write back to the TUN, or null to drop.
     */
    private byte[] handlePacket(byte[] packet, DatagramSocket dnsSocket, InetAddress upstream) {
        if (packet.length < 20) {
            return null;
        }
        int version = (packet[0] >> 4) & 0xF;
        if (version != 4) {
            return null;
        }
        int ihl = (packet[0] & 0xF) * 4;
        if (ihl < 20 || packet.length < ihl + 8) {
            return null;
        }
        int protocol = packet[9] & 0xFF;
        if (protocol != 17) { // UDP only
            return null;
        }
        int srcPort = ((packet[ihl] & 0xFF) << 8) | (packet[ihl + 1] & 0xFF);
        int dstPort = ((packet[ihl + 2] & 0xFF) << 8) | (packet[ihl + 3] & 0xFF);
        if (dstPort != DNS_PORT) {
            return null;
        }
        int udpLen = ((packet[ihl + 4] & 0xFF) << 8) | (packet[ihl + 5] & 0xFF);
        int dnsLen = udpLen - 8;
        if (dnsLen <= 0 || packet.length < ihl + 8 + dnsLen) {
            return null;
        }
        byte[] dnsQuery = new byte[dnsLen];
        System.arraycopy(packet, ihl + 8, dnsQuery, 0, dnsLen);

        String domain = parseDomain(dnsQuery);
        byte[] dnsAnswer;
        if (domain != null && isBlocked(domain)) {
            noteBlocked(domain);
            dnsAnswer = buildNxdomain(dnsQuery);
        } else {
            dnsAnswer = forwardQuery(dnsQuery, dnsSocket, upstream);
            if (dnsAnswer == null) {
                return null;
            }
        }
        return buildIpPacket(packet, ihl, srcPort, dstPort, dnsAnswer);
    }

    /** Extract the QNAME domain from a DNS query message, or null. */
    private String parseDomain(byte[] dns) {
        if (dns.length < 12) {
            return null;
        }
        int qdCount = ((dns[4] & 0xFF) << 8) | (dns[5] & 0xFF);
        if (qdCount < 1) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int pos = 12;
        while (pos < dns.length) {
            int labelLen = dns[pos] & 0xFF;
            if (labelLen == 0) {
                break;
            }
            if ((labelLen & 0xC0) != 0) { // compression pointer, not in a query
                return null;
            }
            if (pos + 1 + labelLen > dns.length) {
                return null;
            }
            if (sb.length() > 0) {
                sb.append('.');
            }
            for (int i = 0; i < labelLen; i++) {
                sb.append((char) (dns[pos + 1 + i] & 0xFF));
            }
            pos += 1 + labelLen;
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    /** Build an NXDOMAIN (RCODE 3) response reusing the query's question. */
    private byte[] buildNxdomain(byte[] query) {
        int qLen = questionLength(query);
        if (qLen < 0) {
            return null;
        }
        byte[] resp = new byte[12 + qLen];
        resp[0] = query[0];
        resp[1] = query[1];
        int queryFlags = ((query[2] & 0xFF) << 8) | (query[3] & 0xFF);
        int flags = 0x8000 | 0x0080 | (queryFlags & 0x0100) | 0x0003;
        resp[2] = (byte) ((flags >> 8) & 0xFF);
        resp[3] = (byte) (flags & 0xFF);
        resp[4] = 0;
        resp[5] = 1; // QDCOUNT = 1
        resp[6] = 0;
        resp[7] = 0; // ANCOUNT = 0
        resp[8] = 0;
        resp[9] = 0; // NSCOUNT = 0
        resp[10] = 0;
        resp[11] = 0; // ARCOUNT = 0
        System.arraycopy(query, 12, resp, 12, qLen);
        return resp;
    }

    /** Length of the question section (QNAME + QTYPE + QCLASS), or -1. */
    private int questionLength(byte[] dns) {
        int pos = 12;
        while (pos < dns.length) {
            int labelLen = dns[pos] & 0xFF;
            if (labelLen == 0) {
                pos++;
                break;
            }
            if ((labelLen & 0xC0) != 0) {
                return -1;
            }
            pos += 1 + labelLen;
        }
        if (pos + 4 > dns.length) {
            return -1;
        }
        return (pos + 4) - 12;
    }

    private byte[] forwardQuery(byte[] query, DatagramSocket socket, InetAddress upstream) {
        try {
            DatagramPacket req = new DatagramPacket(query, query.length, upstream, DNS_PORT);
            socket.send(req);
            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            socket.receive(resp);
            byte[] out = new byte[resp.getLength()];
            System.arraycopy(resp.getData(), resp.getOffset(), out, 0, out.length);
            return out;
        } catch (IOException e) {
            return null;
        }
    }

    /** Wrap a DNS payload in a swapped IPv4/UDP packet addressed back to the sender. */
    private byte[] buildIpPacket(byte[] orig, int ihl, int srcPort, int dstPort, byte[] dns) {
        int totalLen = 20 + 8 + dns.length;
        byte[] pkt = new byte[totalLen];
        pkt[0] = 0x45; // IPv4, IHL 5
        pkt[1] = orig[1]; // TOS
        pkt[2] = (byte) ((totalLen >> 8) & 0xFF);
        pkt[3] = (byte) (totalLen & 0xFF);
        pkt[4] = orig[4]; // identification
        pkt[5] = orig[5];
        pkt[6] = orig[6]; // flags + fragment offset
        pkt[7] = orig[7];
        pkt[8] = 64; // TTL
        pkt[9] = 17; // UDP
        pkt[10] = 0; // checksum (filled below)
        pkt[11] = 0;
        // swap source/destination IPs
        System.arraycopy(orig, 16, pkt, 12, 4); // src = orig dst
        System.arraycopy(orig, 12, pkt, 16, 4); // dst = orig src
        // UDP header: swap ports, checksum 0 (allowed for IPv4)
        int u = 20;
        pkt[u] = (byte) ((dstPort >> 8) & 0xFF);
        pkt[u + 1] = (byte) (dstPort & 0xFF);
        pkt[u + 2] = (byte) ((srcPort >> 8) & 0xFF);
        pkt[u + 3] = (byte) (srcPort & 0xFF);
        int udpLen = 8 + dns.length;
        pkt[u + 4] = (byte) ((udpLen >> 8) & 0xFF);
        pkt[u + 5] = (byte) (udpLen & 0xFF);
        pkt[u + 6] = 0;
        pkt[u + 7] = 0;
        System.arraycopy(dns, 0, pkt, u + 8, dns.length);
        // IPv4 header checksum
        int sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += ((pkt[i] & 0xFF) << 8) | (pkt[i + 1] & 0xFF);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        int checksum = (~sum) & 0xFFFF;
        pkt[10] = (byte) ((checksum >> 8) & 0xFF);
        pkt[11] = (byte) (checksum & 0xFF);
        return pkt;
    }

    @Override
    public void onRevoke() {
        stopSelf();
    }

    @Override
    public void onDestroy() {
        running = false;
        try {
            if (tunFd != null) {
                tunFd.close();
            }
        } catch (Exception ignored) {
        }
        if (worker != null) {
            worker.interrupt();
        }
        super.onDestroy();
    }
}
