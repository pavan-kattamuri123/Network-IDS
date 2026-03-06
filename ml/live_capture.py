import sys
import os
sys.dont_write_bytecode = True

import threading
import time
from datetime import datetime

# Feature names expected by the ONNX model (CIC-IDS-2017 78 features)
FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

NUM_FEATURES = len(FEATURE_NAMES)  # 78


def _extract_features(packet):
    """
    Extract a best-effort 78-feature numeric vector from a raw scapy packet.
    Fields that cannot be derived from a single packet are set to 0.
    """
    features = [0.0] * NUM_FEATURES

    try:
        # Import scapy layers lazily
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import Ether

        pkt_len = len(packet)
        proto = 0
        src_port = 0
        dst_port = 0
        fin = syn = rst = psh = ack = urg = 0

        if packet.haslayer(IP):
            proto_num = packet[IP].proto  # 6=TCP, 17=UDP, 1=ICMP

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            proto = 6
            flags = int(tcp.flags)
            fin = 1 if flags & 0x01 else 0
            syn = 1 if flags & 0x02 else 0
            rst = 1 if flags & 0x04 else 0
            psh = 1 if flags & 0x08 else 0
            ack = 1 if flags & 0x10 else 0
            urg = 1 if flags & 0x20 else 0
            hdr_len = tcp.dataofs * 4 if tcp.dataofs else 20
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            proto = 17
            hdr_len = 8
        else:
            hdr_len = 0

        # Map to feature vector indices (doing it strictly with direct indexing for O(1) Speed)
        features[0] = float(dst_port)
        features[2] = 1.0
        features[4] = float(pkt_len)
        features[6] = float(pkt_len)
        features[7] = float(pkt_len)
        features[8] = float(pkt_len)
        features[38] = float(pkt_len)
        features[39] = float(pkt_len)
        features[40] = float(pkt_len)
        features[43] = float(fin)
        features[44] = float(syn)
        features[45] = float(rst)
        features[46] = float(psh)
        features[47] = float(ack)
        features[48] = float(urg)
        features[52] = float(pkt_len)
        features[53] = float(pkt_len)
        features[55] = float(hdr_len)
        features[34] = float(hdr_len)
        features[62] = 1.0  # Subflow Fwd Packets
        features[63] = float(pkt_len)  # Subflow Fwd Bytes
        
        if proto == 6 and packet.haslayer(TCP):
            features[66] = float(packet[TCP].window)
            
        features[69] = float(hdr_len)


    except Exception:
        pass

    return features


def get_network_interfaces():
    """Return list of dicts with 'value' (NPF name for scapy) and 'label' (friendly name)."""
    try:
        # Windows: use scapy's full interface list which includes friendly names
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        result = []
        for iface in ifaces:
            friendly = iface.get('name', '') or iface.get('description', '')
            
            # Filter strictly to only exactly "Wi-Fi" or "Ethernet"
            if friendly not in ["Wi-Fi", "Ethernet"]:
                continue
                
            npf = iface.get('npf_name', '')
            if not npf:
                guid = iface.get('guid', '')
                if guid:
                    npf = f"\\Device\\NPF_{guid}"
                else:
                    npf = friendly
            if friendly or npf:
                result.append({"value": npf, "label": friendly or npf})
        if result:
            return result
    except Exception:
        pass

    # Fallback: plain interface list
    try:
        from scapy.arch import get_if_list
        return [{"value": i, "label": i} for i in get_if_list()]
    except Exception:
        return []



class LiveCaptureThread:
    """
    Manages a background thread that sniffs packets and classifies each one.
    Results are delivered via the `on_result` callback.
    """

    def __init__(self, on_result, iface=None):
        """
        on_result: callable(dict) called for each classified packet.
                   dict keys: timestamp, src, dst, proto, label, pkt_len
        iface: network interface name (None = scapy default)
        """
        self.on_result = on_result
        self.iface = iface
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def _run(self):
        try:
            from scapy.sendrecv import sniff
        except ImportError:
            self.on_result({
                "error": "scapy is not installed. Run: pip install scapy"
            })
            return

        # Import ALL layers BEFORE sniffing starts so scapy's dissector
        # registers them. Without this, haslayer(IP) always returns False.
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import Ether, ARP
        except Exception as e:
            self.on_result({"error": f"scapy layer import failed: {e}"})
            return

        def _process(pkt):
            if self._stop_event.is_set():
                return

            try:
                proto_name = "OTHER"
                src = "?"
                dst = "?"
                src_port = 0
                dst_port = 0
                pkt_len = len(pkt)

                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    if pkt.haslayer(TCP):
                        proto_name = "TCP"
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                    elif pkt.haslayer(UDP):
                        proto_name = "UDP"
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                    elif pkt.haslayer(ICMP):
                        proto_name = "ICMP"
                    else:
                        proto_name = "IP"

                elif pkt.haslayer(IPv6):
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                    if pkt.haslayer(TCP):
                        proto_name = "TCP"
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                    elif pkt.haslayer(UDP):
                        proto_name = "UDP"
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                    else:
                        proto_name = "IPv6"

                elif pkt.haslayer(ARP):
                    src = pkt[ARP].psrc
                    dst = pkt[ARP].pdst
                    proto_name = "ARP"

                elif pkt.haslayer(Ether):
                    # Last resort: show MAC addresses
                    src = pkt[Ether].src
                    dst = pkt[Ether].dst

                # Feature extraction + prediction
                features = _extract_features(pkt)
                label, confidence = self._classify(features)

                self.on_result({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "src": src,
                    "src_port": src_port,
                    "dst": dst,
                    "dst_port": dst_port,
                    "proto": proto_name,
                    "label": label,
                    "confidence": confidence,
                    "pkt_len": pkt_len,
                })

            except Exception:
                pass  # Skip malformed packets silently

        try:
            kwargs = {"prn": _process, "store": False}
            if self.iface:
                kwargs["iface"] = self.iface
            sniff(
                stop_filter=lambda _: self._stop_event.is_set(),
                timeout=None,
                **kwargs,
            )
        except Exception as e:
            self.on_result({"error": str(e)})

    def _classify(self, features):
        """Run the ONNX model on the extracted feature vector. Returns (label, confidence)."""
        try:
            import numpy as np
            import onnxruntime as ort
            from ml.predict import _get_onnx_session, _get_onnx_classes
        except ImportError:
            try:
                # When called from within the package
                import sys, os
                sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                import numpy as np
                import onnxruntime as ort
                from ml.predict import _get_onnx_session, _get_onnx_classes
            except Exception:
                return "UNKNOWN", 0.0

        try:
            sess = _get_onnx_session()
            classes = _get_onnx_classes()
            input_name = sess.get_inputs()[0].name
            expected = sess.get_inputs()[0].shape[1]

            feat = features[:expected] if expected and len(features) >= expected else features
            if expected and len(feat) < expected:
                feat = feat + [0.0] * (expected - len(feat))

            x = np.array([feat], dtype=np.float32)
            outputs = sess.run(None, {input_name: x})
            
            # Extract predicted index and the probabilities dictionary
            pred_idx = int(outputs[0][0])
            label = classes[pred_idx]
            
            # Extract max probability from the dictionary as confidence
            probs = outputs[1][0]
            confidence = probs.get(pred_idx, 0.0)
            
            return label, float(confidence)
        except Exception as e:
            return "UNKNOWN", 0.0
