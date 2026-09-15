import {
  Server,
  Zap,
  Radio,
  Globe,
  Lock,
  BrainCircuit,
  UploadCloud,
} from "lucide-react";

// Dynamic API detection: defaults to same host on port 8000
export const API_BASE =
  import.meta.env.VITE_API_BASE ||
  (typeof window !== "undefined" && window.location.hostname
    ? `http://${window.location.hostname}:8000`
    : "http://localhost:8000");

export const DETECTORS_CONFIG = [
  {
    type: "PORT_SCAN",
    label: "Port Scanning",
    category: "Reconnaissance",
    icon: Server,
    color: "#3b82f6",
    description: "Detects rapid destination port and host fan-out scans.",
  },
  {
    type: "SYN_FLOOD",
    label: "SYN Flood",
    category: "Volumetric DDoS",
    icon: Zap,
    color: "#ef4444",
    description: "Detects abnormal surges of incomplete TCP SYN handshakes.",
  },
  {
    type: "DATA_EXFILTRATION",
    label: "Data Exfiltration",
    category: "Data Loss",
    icon: UploadCloud,
    color: "#f59e0b",
    description: "Flags high asymmetric outbound-to-inbound byte volume.",
  },
  {
    type: "C2_BEACONING",
    label: "C2 Beaconing",
    category: "Botnet / C2",
    icon: Radio,
    color: "#8b5cf6",
    description: "Identifies regular, periodic inter-arrival check-ins.",
  },
  {
    type: "DGA_DNS_TUNNELLING",
    label: "DGA / DNS Tunnel",
    category: "DNS Evasion",
    icon: Globe,
    color: "#06b6d4",
    description: "Flags high-entropy or oversized domain queries.",
  },
  {
    type: "TLS_METADATA_ANOMALY",
    label: "TLS Anomaly",
    category: "Encrypted Malware",
    icon: Lock,
    color: "#ec4899",
    description: "Inspects ClientHello metadata, JA3 hashes, and missing SNI.",
  },
  {
    type: "ML_ANOMALY",
    label: "ML Anomaly (AI)",
    category: "Unsupervised",
    icon: BrainCircuit,
    color: "#10b981",
    description: "Isolation Forest evaluating 16-dimensional feature vectors.",
  },
];
