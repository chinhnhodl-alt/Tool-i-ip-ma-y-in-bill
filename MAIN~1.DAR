// ============================================================================
// DOI IP MAY IN (XP / Zywell / HPRT) - TAT CA TRONG 1 FILE
// Doi IP may in bill/tem/wifi khong can cung lop mang (qua UDP broadcast).
// ============================================================================
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:network_info_plus/network_info_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';

// ====================== MODEL: HANG & LOAI MAY IN ===========================
enum PrinterBrand {
  xprinter('XP / Xprinter'),
  zywell('Zywell'),
  hprt('HPRT'),
  unknown('Khong ro');

  const PrinterBrand(this.label);
  final String label;

  static PrinterBrand fromString(String? s) {
    if (s == null) return PrinterBrand.unknown;
    final v = s.toLowerCase();
    if (v.contains('xp') || v.contains('xprinter')) return PrinterBrand.xprinter;
    if (v.contains('zywell') || v.contains('zy')) return PrinterBrand.zywell;
    if (v.contains('hprt')) return PrinterBrand.hprt;
    return PrinterBrand.unknown;
  }
}

enum PrinterType {
  bill('May in bill (hoa don nhiet)'),
  label('May in tem nhan'),
  wifi('May in WiFi');

  const PrinterType(this.label);
  final String label;
}

// ====================== MODEL: MAY IN =======================================
class Printer {
  String name;
  String mac;
  String ip;
  String mask;
  String gateway;
  PrinterBrand brand;
  PrinterType type;
  int port;
  bool dhcp;

  Printer({
    required this.name,
    required this.mac,
    required this.ip,
    this.mask = '255.255.255.0',
    this.gateway = '',
    this.brand = PrinterBrand.unknown,
    this.type = PrinterType.bill,
    this.port = 9100,
    this.dhcp = false,
  });

  Map<String, dynamic> toJson() => {
        'name': name,
        'mac': mac,
        'ip': ip,
        'mask': mask,
        'gateway': gateway,
        'brand': brand.name,
        'type': type.name,
        'port': port,
        'dhcp': dhcp,
      };

  factory Printer.fromJson(Map<String, dynamic> j) => Printer(
        name: j['name'] ?? 'May in',
        mac: j['mac'] ?? '',
        ip: j['ip'] ?? '',
        mask: j['mask'] ?? '255.255.255.0',
        gateway: j['gateway'] ?? '',
        brand: PrinterBrand.values
            .firstWhere((b) => b.name == j['brand'], orElse: () => PrinterBrand.unknown),
        type: PrinterType.values
            .firstWhere((t) => t.name == j['type'], orElse: () => PrinterType.bill),
        port: j['port'] ?? 9100,
        dhcp: j['dhcp'] ?? false,
      );
}

// ====================== PROTOCOL: GOI UDP THEO HANG =========================
// LUU Y: moi firmware co dinh dang goi khac nhau. Day la dinh dang pho bien cua
// module WiFi gia re (dung chung boi nhieu dong XP/Zywell/HPRT). Neu may that
// khong phan hoi, dung Wireshark bat goi cua phan mem hang roi chinh lai o day.
abstract class PrinterProtocol {
  int get discoveryPort;
  Uint8List discoveryPacket();
  Printer? parseReply(Uint8List data, String fromIp);
  Uint8List ipConfigPacket(Printer printer,
      {required String newIp,
      required String mask,
      required String gateway,
      required bool dhcp});
  Uint8List wifiConfigPacket(Printer printer,
      {required String ssid, required String password});

  static PrinterProtocol forBrand(PrinterBrand brand) {
    switch (brand) {
      case PrinterBrand.xprinter:
        return XprinterProtocol();
      case PrinterBrand.zywell:
        return ZywellProtocol();
      case PrinterBrand.hprt:
        return HprtProtocol();
      case PrinterBrand.unknown:
        return GenericProtocol();
    }
  }

  static Uint8List ipToBytes(String ip) {
    final parts = ip.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    while (parts.length < 4) {
      parts.add(0);
    }
    return Uint8List.fromList(parts.take(4).toList());
  }

  static Uint8List macToBytes(String mac) {
    final clean = mac.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    final out = <int>[];
    for (var i = 0; i + 1 < clean.length && out.length < 6; i += 2) {
      out.add(int.parse(clean.substring(i, i + 2), radix: 16));
    }
    while (out.length < 6) {
      out.add(0);
    }
    return Uint8List.fromList(out);
  }

  static String bytesToMac(List<int> b) =>
      b.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':').toUpperCase();

  static String bytesToIp(List<int> b) => b.map((e) => e.toString()).join('.');
}

class GenericProtocol extends PrinterProtocol {
  @override
  int get discoveryPort => 3000;

  static const _probe = [0x50, 0x52, 0x4F, 0x42, 0x45]; // "PROBE"
  static const _setip = [0x53, 0x45, 0x54, 0x49, 0x50]; // "SETIP"
  static const _setwf = [0x53, 0x45, 0x54, 0x57, 0x46]; // "SETWF"

  @override
  Uint8List discoveryPacket() => Uint8List.fromList([..._probe, 0x00]);

  @override
  Printer? parseReply(Uint8List d, String fromIp) {
    if (d.length < 19) return null;
    final mac = PrinterProtocol.bytesToMac(d.sublist(0, 6));
    final ip = PrinterProtocol.bytesToIp(d.sublist(6, 10));
    final mask = PrinterProtocol.bytesToIp(d.sublist(10, 14));
    final gw = PrinterProtocol.bytesToIp(d.sublist(14, 18));
    final dhcp = d[18] == 1;
    String name = 'May in $fromIp';
    if (d.length > 19) {
      final end = d.indexOf(0x00, 19);
      final raw = d.sublist(19, end == -1 ? d.length : end);
      if (raw.isNotEmpty) name = String.fromCharCodes(raw).trim();
    }
    return Printer(
      name: name.isEmpty ? 'May in $fromIp' : name,
      mac: mac,
      ip: ip.startsWith('0.') ? fromIp : ip,
      mask: mask,
      gateway: gw,
      brand: PrinterBrand.fromString(name),
      dhcp: dhcp,
    );
  }

  @override
  Uint8List ipConfigPacket(Printer p,
      {required String newIp,
      required String mask,
      required String gateway,
      required bool dhcp}) {
    return Uint8List.fromList([
      ..._setip,
      ...PrinterProtocol.macToBytes(p.mac),
      ...PrinterProtocol.ipToBytes(newIp),
      ...PrinterProtocol.ipToBytes(mask),
      ...PrinterProtocol.ipToBytes(gateway.isEmpty ? '0.0.0.0' : gateway),
      dhcp ? 1 : 0,
    ]);
  }

  @override
  Uint8List wifiConfigPacket(Printer p,
      {required String ssid, required String password}) {
    final s = ssid.codeUnits;
    final pw = password.codeUnits;
    return Uint8List.fromList([
      ..._setwf,
      ...PrinterProtocol.macToBytes(p.mac),
      s.length,
      ...s,
      pw.length,
      ...pw,
    ]);
  }
}

class XprinterProtocol extends GenericProtocol {
  @override
  int get discoveryPort => 3000;
}

class ZywellProtocol extends GenericProtocol {
  @override
  int get discoveryPort => 3000;
}

class HprtProtocol extends GenericProtocol {
  @override
  int get discoveryPort => 3000;
}

// ====================== SERVICE: UDP QUET & CAU HINH ========================
class UdpService {
  static Future<List<Printer>> discover(
      {Duration timeout = const Duration(seconds: 4)}) async {
    final found = <String, Printer>{};
    final protocols = <PrinterProtocol>[
      XprinterProtocol(),
      ZywellProtocol(),
      HprtProtocol(),
      GenericProtocol(),
    ];
    final broadcasts = await _broadcastAddresses();
    final ports = protocols.map((p) => p.discoveryPort).toSet();

    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      socket.broadcastEnabled = true;
      final s = socket;
      final completer = Completer<List<Printer>>();
      final sub = s.listen((event) {
        if (event != RawSocketEvent.read) return;
        final dg = s.receive();
        if (dg == null) return;
        final data = Uint8List.fromList(dg.data);
        final fromIp = dg.address.address;
        for (final proto in protocols) {
          final printer = proto.parseReply(data, fromIp);
          if (printer != null && printer.mac.replaceAll(':', '').isNotEmpty) {
            found[printer.mac] = printer;
            break;
          }
        }
      });

      for (var round = 0; round < 3; round++) {
        for (final proto in protocols) {
          final pkt = proto.discoveryPacket();
          for (final b in broadcasts) {
            for (final port in ports) {
              try {
                s.send(pkt, InternetAddress(b), port);
              } catch (_) {}
            }
          }
        }
        await Future.delayed(const Duration(milliseconds: 400));
      }

      Timer(timeout, () {
        if (!completer.isCompleted) completer.complete(found.values.toList());
      });
      final result = await completer.future;
      await sub.cancel();
      return result;
    } finally {
      socket?.close();
    }
  }

  static Future<bool> setIp(Printer printer,
      {required String newIp,
      required String mask,
      required String gateway,
      required bool dhcp}) async {
    final proto = PrinterProtocol.forBrand(printer.brand);
    final pkt = proto.ipConfigPacket(printer,
        newIp: newIp, mask: mask, gateway: gateway, dhcp: dhcp);
    return _sendConfig(pkt, proto.discoveryPort);
  }

  static Future<bool> setWifi(Printer printer,
      {required String ssid, required String password}) async {
    final proto = PrinterProtocol.forBrand(printer.brand);
    final pkt = proto.wifiConfigPacket(printer, ssid: ssid, password: password);
    return _sendConfig(pkt, proto.discoveryPort);
  }

  static Future<bool> _sendConfig(Uint8List pkt, int port) async {
    final broadcasts = await _broadcastAddresses();
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      socket.broadcastEnabled = true;
      final s = socket;
      var ok = false;
      for (var i = 0; i < 4; i++) {
        for (final b in broadcasts) {
          try {
            s.send(pkt, InternetAddress(b), port);
            ok = true;
          } catch (_) {}
        }
        await Future.delayed(const Duration(milliseconds: 250));
      }
      return ok;
    } finally {
      socket?.close();
    }
  }

  static Future<List<String>> _broadcastAddresses() async {
    final list = <String>{'255.255.255.255'};
    try {
      final info = NetworkInfo();
      final ip = await info.getWifiIP();
      final mask = await info.getWifiSubmask();
      if (ip != null && mask != null) {
        final b = _calcBroadcast(ip, mask);
        if (b != null) list.add(b);
      }
    } catch (_) {}
    return list.toList();
  }

  static String? _calcBroadcast(String ip, String mask) {
    final ipP = ip.split('.').map(int.tryParse).toList();
    final mP = mask.split('.').map(int.tryParse).toList();
    if (ipP.length != 4 || mP.length != 4 || ipP.contains(null) || mP.contains(null)) {
      return null;
    }
    final out = <int>[];
    for (var i = 0; i < 4; i++) {
      out.add((ipP[i]! & mP[i]!) | (~mP[i]! & 0xFF));
    }
    return out.join('.');
  }
}

// ====================== SERVICE: LUU MAY IN =================================
class StorageService {
  static const _key = 'saved_printers';

  static Future<List<Printer>> load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_key);
    if (raw == null) return [];
    try {
      final list = jsonDecode(raw) as List;
      return list.map((e) => Printer.fromJson(e as Map<String, dynamic>)).toList();
    } catch (_) {
      return [];
    }
  }

  static Future<void> save(List<Printer> printers) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_key, jsonEncode(printers.map((e) => e.toJson()).toList()));
  }

  static Future<void> add(Printer p) async {
    final list = await load();
    list.removeWhere((e) => e.mac == p.mac && p.mac.isNotEmpty);
    list.add(p);
    await save(list);
  }
}

// ====================== SERVICE: IN THU / KIEM TRA ==========================
class TestPrintService {
  static Future<bool> ping(String ip, {int port = 9100}) async {
    try {
      final s = await Socket.connect(ip, port, timeout: const Duration(seconds: 3));
      s.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> printTest(String ip, {int port = 9100}) async {
    try {
      final s = await Socket.connect(ip, port, timeout: const Duration(seconds: 3));
      const esc = 0x1B;
      const gs = 0x1D;
      final data = <int>[
        esc, 0x40,
        ...'*** IN THU / TEST ***\n'.codeUnits,
        ...'IP: $ip\n'.codeUnits,
        ...'May in hoat dong OK\n\n\n'.codeUnits,
        gs, 0x56, 0x00,
      ];
      s.add(data);
      await s.flush();
      await Future.delayed(const Duration(milliseconds: 300));
      s.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }
}

// ====================== APP =================================================
void main() => runApp(const PrinterIpApp());

class PrinterIpApp extends StatelessWidget {
  const PrinterIpApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Doi IP May In',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: const Color(0xFF1565C0),
        scaffoldBackgroundColor: const Color(0xFFF4F6F9),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF1565C0),
          foregroundColor: Colors.white,
          elevation: 0,
          centerTitle: true,
        ),
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
          isDense: true,
        ),
        filledButtonTheme: FilledButtonThemeData(
          style: FilledButton.styleFrom(
            minimumSize: const Size.fromHeight(50),
            textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
          ),
        ),
      ),
      home: const HomeScreen(),
    );
  }
}

// ====================== WIDGET: THE MAY IN ==================================
class PrinterCard extends StatelessWidget {
  const PrinterCard({super.key, required this.printer, this.onTap});
  final Printer printer;
  final VoidCallback? onTap;

  IconData get _icon {
    switch (printer.type) {
      case PrinterType.bill:
        return Icons.receipt_long;
      case PrinterType.label:
        return Icons.label;
      case PrinterType.wifi:
        return Icons.wifi;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: ListTile(
        onTap: onTap,
        leading: CircleAvatar(
          backgroundColor: const Color(0xFFE3F0FF),
          child: Icon(_icon, color: const Color(0xFF1565C0)),
        ),
        title: Text(printer.name,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(fontWeight: FontWeight.bold)),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('IP: ${printer.ip}   ${printer.dhcp ? "(DHCP)" : "(IP tinh)"}'),
            Text('MAC: ${printer.mac}',
                style: const TextStyle(fontSize: 12, color: Colors.black54)),
            Text('Hang: ${printer.brand.label}',
                style: const TextStyle(fontSize: 12, color: Colors.black54)),
          ],
        ),
        isThreeLine: true,
        trailing: const Icon(Icons.chevron_right),
      ),
    );
  }
}

// ====================== MAN HINH CHINH ======================================
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  List<Printer> _found = [];
  List<Printer> _saved = [];
  bool _scanning = false;

  @override
  void initState() {
    super.initState();
    _loadSaved();
  }

  Future<void> _loadSaved() async {
    final s = await StorageService.load();
    if (mounted) setState(() => _saved = s);
  }

  Future<void> _scan() async {
    await [Permission.location, Permission.nearbyWifiDevices].request();
    setState(() {
      _scanning = true;
      _found = [];
    });
    try {
      final list = await UdpService.discover();
      if (mounted) setState(() => _found = list);
      if (mounted && list.isEmpty) {
        _toast('Khong tim thay may in. Dung "Them thu cong" hoac xem README.');
      }
    } catch (e) {
      _toast('Loi quet: $e');
    } finally {
      if (mounted) setState(() => _scanning = false);
    }
  }

  void _toast(String m) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(m), duration: const Duration(seconds: 4)));
  }

  Future<void> _openConfig(Printer p) async {
    final changed = await Navigator.push<bool>(
        context, MaterialPageRoute(builder: (_) => ConfigScreen(printer: p)));
    if (changed == true) _loadSaved();
  }

  Future<void> _addManual() async {
    _openConfig(Printer(name: 'May in moi', mac: '', ip: '192.168.1.100'));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Doi IP May In'),
        actions: [
          IconButton(
              tooltip: 'Them thu cong',
              icon: const Icon(Icons.add),
              onPressed: _addManual),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _scan,
        child: ListView(
          children: [
            Padding(
              padding: const EdgeInsets.all(12),
              child: FilledButton.icon(
                onPressed: _scanning ? null : _scan,
                icon: _scanning
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.wifi_find),
                label: Text(_scanning ? 'Dang quet...' : 'QUET MAY IN TREN MANG'),
              ),
            ),
            const _SectionTitle('May in tim thay'),
            if (_found.isEmpty && !_scanning)
              const _Empty('Nhan "QUET MAY IN" de tim. Dien thoai phai cung mang WiFi voi may in.'),
            ..._found.map((p) => PrinterCard(printer: p, onTap: () => _openConfig(p))),
            if (_saved.isNotEmpty) ...[
              const _SectionTitle('May in da luu'),
              ..._saved.map((p) => PrinterCard(printer: p, onTap: () => _openConfig(p))),
            ],
            const SizedBox(height: 24),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _addManual,
        icon: const Icon(Icons.add),
        label: const Text('Them thu cong'),
      ),
    );
  }
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle(this.text);
  final String text;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
        child: Text(text,
            style: const TextStyle(
                fontWeight: FontWeight.bold, fontSize: 15, color: Colors.black87)),
      );
}

class _Empty extends StatelessWidget {
  const _Empty(this.text);
  final String text;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
        child: Text(text, style: const TextStyle(color: Colors.black54)),
      );
}

// ====================== MAN HINH CAU HINH ===================================
class ConfigScreen extends StatefulWidget {
  const ConfigScreen({super.key, required this.printer});
  final Printer printer;
  @override
  State<ConfigScreen> createState() => _ConfigScreenState();
}

class _ConfigScreenState extends State<ConfigScreen> {
  final _form = GlobalKey<FormState>();
  late TextEditingController _name, _mac, _ip, _mask, _gw, _ssid, _pw;
  late PrinterBrand _brand;
  late PrinterType _type;
  late bool _dhcp;
  bool _busy = false;
  bool _showPw = false;

  @override
  void initState() {
    super.initState();
    final p = widget.printer;
    _name = TextEditingController(text: p.name);
    _mac = TextEditingController(text: p.mac);
    _ip = TextEditingController(text: p.ip);
    _mask = TextEditingController(text: p.mask);
    _gw = TextEditingController(text: p.gateway);
    _ssid = TextEditingController();
    _pw = TextEditingController();
    _brand = p.brand == PrinterBrand.unknown ? PrinterBrand.xprinter : p.brand;
    _type = p.type;
    _dhcp = p.dhcp;
  }

  @override
  void dispose() {
    for (final c in [_name, _mac, _ip, _mask, _gw, _ssid, _pw]) {
      c.dispose();
    }
    super.dispose();
  }

  Printer _current() => Printer(
        name: _name.text.trim().isEmpty ? 'May in' : _name.text.trim(),
        mac: _mac.text.trim(),
        ip: _ip.text.trim(),
        mask: _mask.text.trim(),
        gateway: _gw.text.trim(),
        brand: _brand,
        type: _type,
        dhcp: _dhcp,
      );

  void _toast(String m, {Color? color}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(m), backgroundColor: color, duration: const Duration(seconds: 4)));
  }

  Future<void> _applyIp() async {
    if (!_form.currentState!.validate()) return;
    if (_mac.text.trim().isEmpty) {
      _toast('Can co dia chi MAC de doi IP cross-subnet. Hay QUET de lay MAC.',
          color: Colors.orange.shade800);
      return;
    }
    setState(() => _busy = true);
    final ok = await UdpService.setIp(_current(),
        newIp: _ip.text.trim(),
        mask: _mask.text.trim(),
        gateway: _gw.text.trim(),
        dhcp: _dhcp);
    setState(() => _busy = false);
    _toast(
        ok
            ? 'Da gui lenh doi IP. May in se khoi dong lai ~10s, sau do nhan IP moi.'
            : 'Khong gui duoc goi. Kiem tra ket noi WiFi cua dien thoai.',
        color: ok ? Colors.green.shade700 : Colors.red.shade700);
  }

  Future<void> _applyWifi() async {
    if (_ssid.text.trim().isEmpty) {
      _toast('Nhap ten WiFi (SSID).', color: Colors.orange.shade800);
      return;
    }
    setState(() => _busy = true);
    final ok = await UdpService.setWifi(_current(),
        ssid: _ssid.text.trim(), password: _pw.text);
    setState(() => _busy = false);
    _toast(
        ok
            ? 'Da gui cau hinh WiFi. May in se ket noi vao WiFi "${_ssid.text.trim()}".'
            : 'Khong gui duoc cau hinh WiFi.',
        color: ok ? Colors.green.shade700 : Colors.red.shade700);
  }

  Future<void> _testPrint() async {
    setState(() => _busy = true);
    final reachable = await TestPrintService.ping(_ip.text.trim());
    if (!reachable) {
      setState(() => _busy = false);
      _toast('Khong ket noi duoc IP ${_ip.text.trim()}:9100. May in chua online o IP nay.',
          color: Colors.red.shade700);
      return;
    }
    final ok = await TestPrintService.printTest(_ip.text.trim());
    setState(() => _busy = false);
    _toast(ok ? 'Da gui lenh in thu.' : 'Loi khi in thu.',
        color: ok ? Colors.green.shade700 : Colors.red.shade700);
  }

  Future<void> _save() async {
    await StorageService.add(_current());
    _toast('Da luu may in.', color: Colors.green.shade700);
    if (mounted) Navigator.pop(context, true);
  }

  String? _ipValidator(String? v) {
    if (_dhcp) return null;
    final re = RegExp(r'^(\d{1,3}\.){3}\d{1,3}$');
    if (v == null || !re.hasMatch(v.trim())) return 'IP khong hop le (vd 192.168.1.50)';
    if (v.split('.').any((p) => (int.tryParse(p) ?? 999) > 255)) return 'Moi so phai <= 255';
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final isWifi = _type == PrinterType.wifi;
    return Scaffold(
      appBar: AppBar(title: const Text('Cau hinh may in')),
      body: AbsorbPointer(
        absorbing: _busy,
        child: Form(
          key: _form,
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _label('Ten may in'),
              TextFormField(controller: _name),
              const SizedBox(height: 16),
              _label('Hang may in'),
              DropdownButtonFormField<PrinterBrand>(
                value: _brand,
                items: [PrinterBrand.xprinter, PrinterBrand.zywell, PrinterBrand.hprt]
                    .map((b) => DropdownMenuItem(value: b, child: Text(b.label)))
                    .toList(),
                onChanged: (v) => setState(() => _brand = v!),
              ),
              const SizedBox(height: 16),
              _label('Loai may in'),
              SegmentedButton<PrinterType>(
                segments: const [
                  ButtonSegment(value: PrinterType.bill, label: Text('Bill'), icon: Icon(Icons.receipt_long)),
                  ButtonSegment(value: PrinterType.label, label: Text('Tem'), icon: Icon(Icons.label)),
                  ButtonSegment(value: PrinterType.wifi, label: Text('WiFi'), icon: Icon(Icons.wifi)),
                ],
                selected: {_type},
                onSelectionChanged: (s) => setState(() => _type = s.first),
              ),
              const SizedBox(height: 16),
              _label('Dia chi MAC (lay tu QUET - bat buoc de doi IP)'),
              TextFormField(
                controller: _mac,
                inputFormatters: [FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F:]'))],
                decoration: const InputDecoration(hintText: 'vd: 00:11:22:33:44:55'),
              ),
              const Divider(height: 40),
              Row(
                children: [
                  const Expanded(
                      child: Text('Dung DHCP (tu dong lay IP)',
                          style: TextStyle(fontWeight: FontWeight.w600))),
                  Switch(value: _dhcp, onChanged: (v) => setState(() => _dhcp = v)),
                ],
              ),
              if (!_dhcp) ...[
                const SizedBox(height: 8),
                _label('IP moi'),
                TextFormField(
                  controller: _ip,
                  keyboardType: TextInputType.number,
                  validator: _ipValidator,
                  decoration: const InputDecoration(hintText: '192.168.1.50'),
                ),
                const SizedBox(height: 12),
                _label('Subnet mask'),
                TextFormField(controller: _mask, keyboardType: TextInputType.number),
                const SizedBox(height: 12),
                _label('Gateway (de trong neu khong can)'),
                TextFormField(controller: _gw, keyboardType: TextInputType.number),
              ],
              const SizedBox(height: 20),
              FilledButton.icon(
                onPressed: _applyIp,
                icon: const Icon(Icons.lan),
                label: const Text('DOI IP NGAY'),
              ),
              if (isWifi) ...[
                const Divider(height: 40),
                _label('Ten WiFi (SSID)'),
                TextFormField(
                  controller: _ssid,
                  decoration: const InputDecoration(hintText: 'Ten mang WiFi'),
                ),
                const SizedBox(height: 12),
                _label('Mat khau WiFi'),
                TextFormField(
                  controller: _pw,
                  obscureText: !_showPw,
                  decoration: InputDecoration(
                    suffixIcon: IconButton(
                      icon: Icon(_showPw ? Icons.visibility_off : Icons.visibility),
                      onPressed: () => setState(() => _showPw = !_showPw),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: _applyWifi,
                  style: FilledButton.styleFrom(backgroundColor: Colors.teal),
                  icon: const Icon(Icons.wifi),
                  label: const Text('LUU WIFI VAO MAY IN'),
                ),
              ],
              const Divider(height: 40),
              OutlinedButton.icon(
                onPressed: _testPrint,
                icon: const Icon(Icons.print),
                label: const Text('In thu / Kiem tra ket noi'),
                style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(48)),
              ),
              const SizedBox(height: 10),
              OutlinedButton.icon(
                onPressed: _save,
                icon: const Icon(Icons.save),
                label: const Text('Luu may in'),
                style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(48)),
              ),
              const SizedBox(height: 30),
              if (_busy) const Center(child: CircularProgressIndicator()),
            ],
          ),
        ),
      ),
    );
  }

  Widget _label(String t) => Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Text(t, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13)),
      );
}
