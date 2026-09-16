"""
CTD -- Pcap Replay Collector  (SIH-aligned ingest)

Replaces collector.packet_collector's LIVE `sniff()` on a NIC
with a strictly READ-ONLY replay of an existing .pcap/.pcapng
file -- e.g. a mirrored copy of a gateway/peering link exported
by a data diode, or a simulated multi-host traffic file.

Why this satisfies the SIH constraints:

  Read-only ingest
      PcapReader only opens a file for reading. There is no
      socket, no `send()`, no ability to complete a handshake
      or contact anything -- it is PHYSICALLY incapable of
      talking back, the same guarantee a hardware data diode
      gives you, not just a policy choice in the code.

  Streaming, not batch
      Packets are fed into the exact same one-second sliding
      window / flow engine / detector pipeline used by the
      live collector, via `packet_collector.process_packet`.
      Alerts are produced incrementally as the replay
      progresses, not as one report at the end.

  Defined throughput target
      This script tracks packets, bytes and completed flows
      as it replays, and prints sustained pps / Mbps / flows-
      per-second at the end -- the number you report as your
      "tested throughput" for the SIH writeup.

Usage:
    python -m collector.pcap_replay_collector path/to/file.pcap
    python -m collector.pcap_replay_collector path/to/file.pcap --speed 4
    python -m collector.pcap_replay_collector path/to/file.pcap --max-speed
"""

import argparse
import sys
import time

from scapy.utils import PcapReader

# Reuse the ENTIRE existing pipeline unmodified: flow engine,
# window manager, all 6 rule detectors + ML detector, alert
# manager. Only the packet SOURCE changes.
from collector import packet_collector as live


def replay(pcap_path: str, speed: float = 1.0, max_speed: bool = False):
    """
    Feed every packet in `pcap_path` through the existing
    detection pipeline (live.process_packet), preserving the
    file's original inter-packet timing unless max_speed is set.

    speed:
        1.0  = replay at the same pace it was originally
               captured at (real-time).
        4.0  = replay 4x faster than it was captured.
    max_speed:
        Ignore original timing entirely and feed packets as
        fast as the pipeline can process them -- use this to
        find your throughput ceiling for the benchmark.
    """

    print("=" * 70)
    print("CTD -- PCAP REPLAY COLLECTOR (one-directional, read-only)")
    print("=" * 70)
    print(f"Source file : {pcap_path}")
    print(f"Mode        : {'MAX SPEED' if max_speed else f'{speed}x real-time'}")
    print("Direction   : READ-ONLY (file input only, no socket opened)")
    print("Payload     : NOT INSPECTED (metadata only)")
    print("=" * 70)

    packet_count = 0
    byte_count = 0
    prev_pkt_ts = None
    first_pkt_ts = None

    wall_start = time.time()
    last_shifted_ts = wall_start

    initial_alerts = {a.alert_id: a.event_count for a in live.alert_manager.active_alerts()}

    windows_evaluated = 0
    original_evaluate_window = live.evaluate_window

    def tracked_evaluate_window(*args, **kwargs):
        nonlocal windows_evaluated
        windows_evaluated += 1
        return original_evaluate_window(*args, **kwargs)

    live.evaluate_window = tracked_evaluate_window

    with PcapReader(pcap_path) as reader:
        for packet in reader:

            pkt_ts = float(packet.time)
            if first_pkt_ts is None:
                first_pkt_ts = pkt_ts

            if not max_speed and prev_pkt_ts is not None:
                gap = (pkt_ts - prev_pkt_ts) / max(speed, 0.0001)
                if 0 < gap < 5.0:  # cap absurd gaps so demos don't stall
                    time.sleep(gap)

            prev_pkt_ts = pkt_ts

            packet_count += 1
            byte_count += len(packet)

            # Time-shift the packet to the current wall-clock time
            shifted_ts = wall_start + (pkt_ts - first_pkt_ts)
            packet.time = shifted_ts
            last_shifted_ts = shifted_ts

            # This one call does everything the live collector does:
            # flow tracking, feature windows, all 7 detectors, alerts.
            live.process_packet(packet)

            if packet_count % 2000 == 0:
                _print_progress(packet_count, byte_count, wall_start)

    # Force flush the final partial window
    if live.window_manager and live.window_manager.current:
        # Provide a timestamp slightly after the end of the current window
        final_ts = last_shifted_ts + live.window_manager.window_seconds + 0.1
        features = live.window_manager.flush_if_ready(final_ts)
        if features:
            source_features = live.source_aggregator.get_features(
                features["window_duration"]
            )
            communication_features = live.communication_context.snapshot()

            live.source_aggregator.reset()
            live.communication_context.reset()

            live.evaluate_window(
                features,
                source_features,
                final_ts,
                communication_features,
            )

    live.evaluate_window = original_evaluate_window

    final_alerts = live.alert_manager.active_alerts()
    alert_events = 0
    for a in final_alerts:
        if a.alert_id not in initial_alerts:
            alert_events += a.event_count
        elif a.event_count > initial_alerts[a.alert_id]:
            alert_events += (a.event_count - initial_alerts[a.alert_id])

    wall_elapsed = max(time.time() - wall_start, 1e-6)
    return _print_summary(packet_count, byte_count, wall_elapsed, windows_evaluated, alert_events)


def _print_progress(packet_count, byte_count, wall_start):
    elapsed = max(time.time() - wall_start, 1e-6)
    pps = packet_count / elapsed
    mbps = (byte_count * 8 / 1_000_000) / elapsed
    print(f"[progress] {packet_count} packets | {pps:.1f} pkt/s | {mbps:.2f} Mbps")


def _print_summary(packet_count, byte_count, wall_elapsed, windows_evaluated=0, alert_events=0):
    pps = packet_count / wall_elapsed
    mbps = (byte_count * 8 / 1_000_000) / wall_elapsed
    # FlowEngine keys flows by 5-tuple; entries persist until they
    # time out, so this is a good proxy for distinct flows observed
    # during a bounded replay run.
    flows_seen = len(live.flow_engine.flows)

    print()
    print("=" * 70)
    print("REPLAY COMPLETE -- THROUGHPUT BENCHMARK")
    print("=" * 70)
    print(f"Total packets processed : {packet_count}")
    print(f"Total bytes processed   : {byte_count:,}")
    print(f"Wall-clock duration     : {wall_elapsed:.2f} s")
    print(f"Sustained packet rate   : {pps:.1f} packets/sec")
    print(f"Sustained throughput    : {mbps:.2f} Mbps")
    if flows_seen is not None:
        print(f"Total flows observed    : {flows_seen}")
        print(f"Flow rate               : {flows_seen / wall_elapsed:.2f} flows/sec")
    print(f"Windows evaluated       : {windows_evaluated}")
    print(f"Alert events generated  : {alert_events}")
    print("=" * 70)
    print("Report the 'Sustained throughput' / 'Flow rate' lines above")
    print("as your demonstrated throughput target for the SIH writeup.")
    print("=" * 70)

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "wall_elapsed": float(wall_elapsed),
        "sustained_pps": float(pps),
        "sustained_mbps": float(mbps),
        "flows_seen": int(flows_seen) if flows_seen is not None else 0,
        "flow_rate": float(flows_seen / wall_elapsed) if flows_seen is not None else 0.0,
        "windows_evaluated": int(windows_evaluated),
        "alert_events": int(alert_events),
    }


def replay_continuous_loop(pcap_path: str, speed: float = 1.0, max_speed: bool = False):
    """Continuously replays a PCAP file in an infinite loop for continuous demo monitoring."""
    iteration = 1
    print(f"\n[CONTINUOUS MODE] Replaying '{pcap_path}' continuously in a loop (Ctrl+C to stop)...")
    try:
        while True:
            print(f"\n--- Starting Loop Iteration #{iteration} ---")
            replay(pcap_path, speed=speed, max_speed=max_speed)
            iteration += 1
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nContinuous replay loop stopped by user.")


def replay_directory_watch(dir_path: str, speed: float = 1.0, max_speed: bool = True):
    """Continuously monitors a directory for newly arrived PCAP chunks (Data Diode Spool Ingest)."""
    import glob
    print(f"\n[WATCH MODE] Monitoring directory '{dir_path}' for new .pcap files (Ctrl+C to stop)...")
    processed_files = set()
    try:
        while True:
            current_files = set(glob.glob(os.path.join(dir_path, "*.pcap")) + glob.glob(os.path.join(dir_path, "*.pcapng")))
            new_files = sorted(current_files - processed_files)
            for file_path in new_files:
                print(f"\n[Ingesting New PCAP Chunk]: {file_path}")
                replay(file_path, speed=speed, max_speed=max_speed)
                processed_files.add(file_path)
            time.sleep(2.0)
    except KeyboardInterrupt:
        print("\nDirectory watcher stopped by user.")


def main():
    parser = argparse.ArgumentParser(
        description="Replay a pcap file through the CTD detection pipeline."
    )
    parser.add_argument("pcap_path", nargs="?", default="demo.pcap", help="Path to a .pcap/.pcapng file")
    parser.add_argument(
        "--speed", type=float, default=1.0,
        help="Replay speed multiplier vs. real-time (default: 1.0)"
    )
    parser.add_argument(
        "--max-speed", action="store_true",
        help="Ignore original timing, replay as fast as possible (for benchmarking)"
    )
    parser.add_argument(
        "--loop", action="store_true",
        help="Continuously replay the PCAP file in an infinite loop (for continuous live dashboard monitoring)"
    )
    parser.add_argument(
        "--watch", type=str, default=None,
        help="Continuously watch a directory for incoming .pcap chunks (data diode spool mode)"
    )
    args = parser.parse_args()

    flusher_thread_started = False
    try:
        import threading
        t = threading.Thread(target=live.background_flusher, daemon=True)
        t.start()
        flusher_thread_started = True
    except Exception:
        pass

    try:
        if args.watch:
            replay_directory_watch(args.watch, speed=args.speed, max_speed=args.max_speed)
        elif args.loop:
            replay_continuous_loop(args.pcap_path, speed=args.speed, max_speed=args.max_speed)
        else:
            replay(args.pcap_path, speed=args.speed, max_speed=args.max_speed)
    except FileNotFoundError:
        print(f"ERROR: pcap file not found: {args.pcap_path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
