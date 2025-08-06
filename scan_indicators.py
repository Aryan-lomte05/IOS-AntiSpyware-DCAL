# import os
# import json
# import re
# import argparse
# from pathlib import Path
# from collections import Counter
# def load_indicators(indicators_dir):
#     indicators = []
#     for file in os.listdir(indicators_dir):
#         if file.endswith('.json'):
#             path = os.path.join(indicators_dir, file)
#             print(f"Loading indicator: {file}")
#             try:
#                 with open(path, 'r', encoding='utf-8') as f:
#                     content = f.read().strip()
#                     if not content:
#                         print(f"Warning: {file} is empty, skipping.")
#                         continue
#                     obj = json.loads(content)
#                     obj['compiled_patterns'] = [re.compile(p, re.IGNORECASE) for p in obj['patterns']]
#                     indicators.append(obj)
#             except json.JSONDecodeError as e:
#                 print(f"Error decoding JSON in file {file}: {e}")
#             except Exception as e:
#                 print(f"Unexpected error loading file {file}: {e}")
#     print(f"Loaded {len(indicators)} indicators.")
#     return indicators


# def extract_app_or_process(line):
#     """
#     Tries to extract an attribution (app or process) from a log line.
#     Update the patterns per your logs!
#     """
#     # Examples: "[Photos.app]" or "Process: Safari" or "com.apple.Safari:" or "App: Instagram"
#     match = re.search(r'\[([A-Za-z0-9\._\-]+\.app)\]', line)
#     if match:
#         return match.group(1)
#     match = re.search(r'Process:\s*([A-Za-z0-9\._\-]+)', line)
#     if match:
#         return match.group(1)
#     match = re.search(r'([A-Za-z0-9\._\-]+)\.app', line)
#     if match:
#         return match.group(0)
#     match = re.search(r'([A-Za-z0-9\._\-]+):\s', line)
#     if match:
#         return match.group(1)
#     return "Unknown"

# def scan_file(filepath, indicators):
#     """
#     Reads each file line by line and checks all patterns from all indicators.
#     If match, stores result with context, file, and app/process (if possible).
#     """
#     results = []
#     try:
#         with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
#             lines = f.readlines()
#     except Exception as e:
#         print(f"Could not read {filepath}: {e}")
#         return results

#     for idx, line in enumerate(lines):
#         for indicator in indicators:
#             for pat, regex in zip(indicator['patterns'], indicator['compiled_patterns']):
#                 for m in regex.finditer(line):
#                     app_or_process = extract_app_or_process(line)
#                     results.append({
#                         'filepath': filepath,
#                         'line_num': idx + 1,
#                         'indicator': indicator['name'],
#                         'description': indicator['description'],
#                         'pattern': pat,
#                         'matched_text': m.group(0),
#                         'severity': indicator.get('severity', 'Unknown'),
#                         'context': line.strip(),
#                         'app_or_process': app_or_process,
#                         'attribution': indicator.get('attribution', {})
#                     })
#     return results

# def scan_directory(root_dir, indicators, file_exts={'.log', '.txt', '.plist', '.json', '.xml', '.csv','.sysdiagnose', '.trace'  }):
#     """
#     Walks through root_dir recursively and scans every text-based file using scan_file.
#     """
#     all_results = []
#     for root, dirs, files in os.walk(root_dir):
#         for file in files:
#             ext = Path(file).suffix.lower()
#             if ext in file_exts:
#                 fp = os.path.join(root, file)
#                 all_results.extend(scan_file(fp, indicators))
#     return all_results

# def detect_fake_apps(processes):
#     # processes = list of all "cmdline" entries from ps.txt or system log
#     suspicious = []
#     for proc in processes:
#         # e.g., suspicious if extra dot, non-Apple bundle prefix, or abnormal path
#         if (re.search(r'\b\w+\.app\.app\b', proc) or 
#             (".app" in proc and "com.apple" not in proc and "/Applications" not in proc)):
#             suspicious.append(proc)
#     return suspicious
# import re

# def detect_app_masquerade(ps_lines):
#     findings = []
#     # e.g., 'com.apple.Safari1.app', '/private/var/mobile/Containers/Bundle/.app' etc.
#     for line in ps_lines:
#         # Search for Unicode or doubled-app indicators
#         if re.search(r"\b\w+\.app\.app\b", line) or re.search(r"[^\x00-\x7F]", line):
#             findings.append(line.strip())
#         # Look for .app with odd name or path
#         m = re.search(r'/Applications/(.+?\.app)', line)
#         if m and (not m.group(1).startswith("com.apple") and " " in m.group(1)):
#             findings.append(line.strip())
#     return findings
# # Usage: Call on each line from ps.txt or app list logs; report lines found as suspicious.

# def detect_stealthy_launchagents(plist_paths):
#     suspicious = []
#     import plistlib
#     for path in plist_paths:
#         try:
#             with open(path, 'rb') as f:
#                 data = plistlib.load(f)
#             if data.get("KeepAlive") == True and not data['Label'].startswith("com.apple"):
#                 suspicious.append({"path": path, "label": data.get("Label"), "desc": "User-writable, persistent, non-Apple LaunchAgent"})
#         except Exception: pass
#     return suspicious
# # Usage: Pass absolute paths of all LaunchAgent-style plists in user and system locations.

# def print_results(results):
#     """
#     Outputs results to the terminal, showing attribution (file, app/process), description, etc.
#     """
#     if not results:
#         print("No indicators triggered.")
#         return
#     print("\n=== Indicator Matches ===")
#     for hit in results:
#         attr = hit.get('attribution', {})
#         print(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit['line_num']})")
#         print(f"    > Matched: {hit['matched_text']}")
#         print(f"    > App/Process: {hit['app_or_process']}")
#         print(f"    > Context: {hit['context']}")
#         if attr:
#             print(f"    > Source: {attr.get('source','')}, Author: {attr.get('author','')}, Date: {attr.get('date_created','')}")
#         print()

# def save_report(results, output_path): 
#     with open(output_path, 'w', encoding='utf-8') as f:
#         for hit in results:
#             f.write(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit['line_num']}):\n")
#             f.write(f" > Matched: {hit['matched_text']}\n")
#             f.write(f" > App/Process: {hit['app_or_process']}\n")
#             f.write(f" > Context: {hit['context']}\n")
#             attr = hit.get('attribution', {})
#             if attr:
#                f.write(f"> Source: {attr.get('source', '')}, Author: {attr.get('author', '')}, Date: {attr.get('date_created', '')}\n")
#             f.write("-----\n")
#     print(f"Report saved to {output_path}")


# def detect_hooked_system_binary(ps_lines):
#     suspicious = []
#     for line in ps_lines:
#         # Example: PID/PPID/Process/Parent info, platform-specific
#         parts = line.split()
#         if len(parts) >= 4:
#             proc_name = parts[0]
#             parent = parts[-1]
#             # If system binary launched by non-root, or parent not system process
#             if proc_name in ["login", "bash", "sh", "launchd"] and parent not in ["launchd", "init"]:
#                 suspicious.append({"process": proc_name, "parent": parent, "line": line.strip()})
#     return suspicious
# # Usage: Call on all lines of process list (ps) output. 



# def detect_unknown_vpn_profile(profile_lines):
#     suspicious = []
#     for line in profile_lines:
#         if re.search(r'VPNType\s*:\s*(?!IPSec|IKEv2|L2TP)\w+', line):
#             suspicious.append(line.strip())
#         if re.search(r'proxy\s+[A-Za-z0-9]+', line, re.IGNORECASE) and not re.search(r'Apple|Nord|Express|TunnelBear', line):
#             suspicious.append(line.strip())
#         if "RemoteManagement" in line:
#             suspicious.append(line.strip())
#     return suspicious
# # Usage: Call on all lines of .plist, profile, or config files relating to VPN/proxy settings.




# def detect_multistage_download_exec(log_lines):
#     matches = []
#     events = []
#     for idx, line in enumerate(log_lines):
#         if re.search(r"\bcurl\b|\bwget\b", line):
#             events.append(("download", idx, line))
#         if re.search(r"\bchmod\b.*\+x", line):
#             events.append(("chmod", idx, line))
#         if re.search(r"\./[A-Za-z0-9\-_]+\b", line):
#             events.append(("exec", idx, line))
#     # Correlate events: did all 3 occur within N lines?
#     for i in range(len(events) - 2):
#         if (events[i][0] == "download" and
#             events[i+1][0] == "chmod" and
#             events[i+2][0] == "exec" and
#             events[i+2][1] - events[i][1] < 10):
#             matches.append({"download": events[i][2], "chmod": events[i+1][2], "exec": events[i+2][2]})
#     return matches
# # Usage: Pass log lines from bash_hist, process/system logs.











# def main():
#     parser = argparse.ArgumentParser(description="Sysdiagnose Indicator Scanner (from Level 0)")
#     parser.add_argument("--dir", required=True, help="Extracted logs root directory")
#     parser.add_argument("--indicators", required=True, help="Indicator JSON directory")
#     parser.add_argument("--report", help="Optional: Path to save text report")
#     args = parser.parse_args()

#     indicators = load_indicators(args.indicators)
#     results = scan_directory(args.dir, indicators)
#     print_results(results)
#     if args.report:
#         save_report(results, args.report)

# if __name__ == "__main__":
#     main()
# def parse_plain_results(filepath):
#     """Parse your results.txt plain-text into a list of dicts."""
#     with open(filepath, 'r', encoding='utf-8') as f:
#         lines = f.readlines()

#     hits = []
#     current_hit = {}

#     indicator_re = re.compile(r'\[(.*?)\] (.*?) in (.*?) \(line (\d+)\)')
#     matched_re = re.compile(r'\s*> Matched: (.*)')
#     app_re = re.compile(r'\s*> App/Process: (.*)')

#     for line in lines:
#         line = line.strip()
#         if not line:
#             if current_hit:
#                 hits.append(current_hit)
#                 current_hit = {}
#             continue

#         m_indicator = indicator_re.match(line)
#         if m_indicator:
#             current_hit['severity'] = m_indicator.group(1)
#             current_hit['indicator'] = m_indicator.group(2)
#             current_hit['filepath'] = m_indicator.group(3)
#             current_hit['line_num'] = int(m_indicator.group(4))
#             continue
#         m_matched = matched_re.match(line)
#         if m_matched:
#             current_hit['matched_text'] = m_matched.group(1)
#             continue
#         m_app = app_re.match(line)
#         if m_app:
#             current_hit['app_or_process'] = m_app.group(1)
#             continue

#     if current_hit:
#         hits.append(current_hit)

#     return hits

# def generate_simple_summary(hits):
#     """Generate a human-readable aggregated summary string."""
#     if not hits:
#         return "No indicators triggered in the scan."

#     indicator_counts = Counter(hit['indicator'] for hit in hits)
#     severity_counts = Counter(hit['severity'] for hit in hits)
#     file_counts = Counter(hit['filepath'].split('\\')[-1].split('/')[-1] for hit in hits)
#     app_counts = Counter(hit.get('app_or_process', 'Unknown') for hit in hits)

#     summary = []

#     summary.append(f"Scan Summary:")
#     summary.append(f"Total alerts detected: {len(hits)}")
#     summary.append("Alert counts by type:")
#     for ind, count in indicator_counts.most_common():
#         summary.append(f"  - {ind}: {count} hits")

#     summary.append("\nAlert counts by severity:")
#     for sev, count in severity_counts.most_common():
#         summary.append(f"  - {sev}: {count}")

#     summary.append("\nTop 5 files with alerts:")
#     for f, count in file_counts.most_common(5):
#         summary.append(f"  - {f}: {count}")

#     summary.append("\nTop 5 attributed apps/processes:")
#     for app, count in app_counts.most_common(5):
#         summary.append(f"  - {app}: {count}")

#     summary_text = "\n".join(summary)
#     return summary_text

# if __name__ == "__main__":
#     # Example usage: summarize after scan is done
#     results_file = 'results.txt'  # or pass as argument
#     hits_data = parse_plain_results(results_file)
#     summary_report = generate_simple_summary(hits_data)

#     print("\n" + "="*60)
#     print(summary_report)
#     print("="*60)

#     # Optional: Write summary to file
#     with open('summary_report.txt', 'w', encoding='utf-8') as f:
#         f.write(summary_report)
# import os
# import json
# import re
# import argparse
# import plistlib
# from pathlib import Path
# from collections import Counter

# # ------------------------------
# # Basic Pattern/JSON Indicators
# # ------------------------------
# def load_indicators(indicators_dir):
#     indicators = []
#     for file in os.listdir(indicators_dir):
#         if file.endswith('.json'):
#             path = os.path.join(indicators_dir, file)
#             print(f"Loading indicator: {file}")
#             try:
#                 with open(path, 'r', encoding='utf-8') as f:
#                     content = f.read().strip()
#                     if not content:
#                         print(f"Warning: {file} is empty, skipping.")
#                         continue
#                     obj = json.loads(content)
#                     obj['compiled_patterns'] = [re.compile(p, re.IGNORECASE) for p in obj['patterns']]
#                     indicators.append(obj)
#             except json.JSONDecodeError as e:
#                 print(f"Error decoding JSON in file {file}: {e}")
#             except Exception as e:
#                 print(f"Unexpected error loading file {file}: {e}")
#     print(f"Loaded {len(indicators)} indicators.")
#     return indicators

# def extract_app_or_process(line):
#     match = re.search(r'\[([A-Za-z0-9\._\-]+\.app)\]', line)
#     if match:
#         return match.group(1)
#     match = re.search(r'Process:\s*([A-Za-z0-9\._\-]+)', line)
#     if match:
#         return match.group(1)
#     match = re.search(r'([A-Za-z0-9\._\-]+)\.app', line)
#     if match:
#         return match.group(0)
#     match = re.search(r'([A-Za-z0-9\._\-]+):\s', line)
#     if match:
#         return match.group(1)
#     return "Unknown"

# def scan_file(filepath, indicators):
#     results = []
#     try:
#         with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
#             lines = f.readlines()
#     except Exception as e:
#         print(f"Could not read {filepath}: {e}")
#         return results

#     for idx, line in enumerate(lines):
#         for indicator in indicators:
#             for pat, regex in zip(indicator['patterns'], indicator['compiled_patterns']):
#                 for m in regex.finditer(line):
#                     app_or_process = extract_app_or_process(line)
#                     results.append({
#                         'filepath': filepath,
#                         'line_num': idx + 1,
#                         'indicator': indicator['name'],
#                         'description': indicator['description'],
#                         'pattern': pat,
#                         'matched_text': m.group(0),
#                         'severity': indicator.get('severity', 'Unknown'),
#                         'context': line.strip(),
#                         'app_or_process': app_or_process,
#                         'attribution': indicator.get('attribution', {})
#                     })
#     return results

# # ----------------------------------------
# # Advanced "Crazy" Python Indicator Logic
# # ----------------------------------------

# def detect_app_masquerade(ps_lines):
#     findings = []
#     for line in ps_lines:
#         if re.search(r"\b\w+\.app\.app\b", line) or re.search(r"[^\x00-\x7F]", line):
#             findings.append(line.strip())
#         m = re.search(r'/Applications/(.+?\.app)', line)
#         if m and (not m.group(1).startswith("com.apple") and " " in m.group(1)):
#             findings.append(line.strip())
#     return findings

# def detect_stealthy_launchagents(plist_paths):
#     suspicious = []
#     for path in plist_paths:
#         try:
#             with open(path, 'rb') as f:
#                 data = plistlib.load(f)
#             if data.get("KeepAlive") == True and not str(data.get('Label', '')).startswith("com.apple"):
#                 suspicious.append({"path": path, "label": data.get("Label"), "desc": "User-writable, persistent, non-Apple LaunchAgent"})
#         except Exception:
#             pass
#     return suspicious

# def detect_hooked_system_binary(ps_lines):
#     suspicious = []
#     for line in ps_lines:
#         parts = line.split()
#         if len(parts) >= 4:
#             proc_name = parts[0]
#             parent = parts[-1]
#             if proc_name in ["login", "bash", "sh", "launchd"] and parent not in ["launchd", "init"]:
#                 suspicious.append({"process": proc_name, "parent": parent, "line": line.strip()})
#     return suspicious

# def detect_unknown_vpn_profile(profile_lines):
#     suspicious = []
#     for line in profile_lines:
#         if re.search(r'VPNType\s*:\s*(?!IPSec|IKEv2|L2TP)\w+', line):
#             suspicious.append(line.strip())
#         if re.search(r'proxy\s+[A-Za-z0-9]+', line, re.IGNORECASE) and not re.search(r'Apple|Nord|Express|TunnelBear', line):
#             suspicious.append(line.strip())
#         if "RemoteManagement" in line:
#             suspicious.append(line.strip())
#     return suspicious

# def detect_multistage_download_exec(log_lines):
#     matches = []
#     events = []
#     for idx, line in enumerate(log_lines):
#         if re.search(r"\bcurl\b|\bwget\b", line):
#             events.append(("download", idx, line))
#         if re.search(r"\bchmod\b.*\+x", line):
#             events.append(("chmod", idx, line))
#         if re.search(r"\./[A-Za-z0-9\-_]+\b", line):
#             events.append(("exec", idx, line))
#     for i in range(len(events) - 2):
#         if (events[i][0] == "download" and
#             events[i+1][0] == "chmod" and
#             events[i+2][0] == "exec" and
#             events[i+2][1] - events[i][1] < 10):
#             matches.append({"download": events[i][2], "chmod": events[i+1][2], "exec": events[i+2][2]})
#     return matches

# # ----------------------
# # Main Directory Walker
# # ----------------------
# def scan_directory_adv(root_dir, indicators, file_exts=None):
#     if file_exts is None:
#         file_exts = {'.log', '.txt', '.plist', '.json', '.xml', '.csv','.sysdiagnose', '.trace'}
#     all_results = []
#     ps_lines = []
#     all_plist_paths = []
#     profile_lines = []
#     all_log_lines = []

#     for root, dirs, files in os.walk(root_dir):
#         for file in files:
#             ext = Path(file).suffix.lower()
#             fp = os.path.join(root, file)
#             # Collect process list (ps.txt)
#             if file == 'ps.txt':
#                 try:
#                     with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
#                         ps_lines.extend(f.readlines())
#                 except Exception:
#                     continue
#             # Collect all plists for LaunchAgents/Daemons
#             if 'launchagent' in file.lower() or 'launchdaemon' in file.lower() or file.endswith('.plist'):
#                 all_plist_paths.append(fp)
#             # Collect VPN/profile files
#             if 'vpn' in file.lower() or 'profile' in file.lower() or file.endswith('.plist'):
#                 try:
#                     with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
#                         profile_lines.extend(f.readlines())
#                 except Exception:
#                     continue
#             # Collect logs for multi-stage exec
#             if ext in {'.log', '.txt'} or file == 'ps.txt':
#                 try:
#                     with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
#                         all_log_lines.extend(f.readlines())
#                 except Exception:
#                     continue
#             # Standard scan
#             if ext in file_exts:
#                 all_results.extend(scan_file(fp, indicators))
#     # --- ADVANCED FUNCTION INDICATORS ---
#     for line in detect_app_masquerade(ps_lines):
#         all_results.append({
#             'filepath': 'ps.txt',
#             'line_num': None,
#             'indicator': "App_Masquerading",
#             'description': "Fake/Impostor app or .app Unicode trick detected.",
#             'pattern': 'Advanced logic',
#             'matched_text': line,
#             'severity': 'High',
#             'context': line.strip(),
#             'app_or_process': extract_app_or_process(line),
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
#         })
#     for obj in detect_stealthy_launchagents(all_plist_paths):
#         all_results.append({
#             'filepath': obj.get('path', 'N/A'),
#             'line_num': None,
#             'indicator': "Stealthy_LaunchAgent",
#             'description': obj.get('desc', ''),
#             'pattern': 'Advanced logic',
#             'matched_text': obj.get('label', 'Unknown'),
#             'severity': 'High',
#             'context': obj.get('label', 'Unknown'),
#             'app_or_process': obj.get('label', 'Unknown'),
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
#         })
#     for obj in detect_hooked_system_binary(ps_lines):
#         all_results.append({
#             'filepath': 'ps.txt',
#             'line_num': None,
#             'indicator': "Hooked_System_Binary",
#             'description': "System binary started by suspicious parent process.",
#             'pattern': 'Advanced logic',
#             'matched_text': obj['line'],
#             'severity': 'High',
#             'context': f"{obj['process']} by {obj['parent']}: {obj['line']}",
#             'app_or_process': obj['process'],
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
#         })
#     for line in detect_unknown_vpn_profile(profile_lines):
#         all_results.append({
#             'filepath': 'vpn_profile',
#             'line_num': None,
#             'indicator': "Unknown_VPN_Profile",
#             'description': "Suspicious VPN or proxy profile entry.",
#             'pattern': 'Advanced logic',
#             'matched_text': line,
#             'severity': 'Medium',
#             'context': line,
#             'app_or_process': extract_app_or_process(line),
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
#         })
#     for match in detect_multistage_download_exec(all_log_lines):
#         all_results.append({
#             'filepath': 'log_correlation',
#             'line_num': None,
#             'indicator': 'MultiStage_Download_Exec',
#             'description': 'Download, chmod, exec chain detected (likely malware installation).',
#             'pattern': 'Advanced logic',
#             'matched_text': f"{match['download']} || {match['chmod']} || {match['exec']}",
#             'severity': 'High',
#             'context': f"{match['download'].strip()} → {match['chmod'].strip()} → {match['exec'].strip()}",
#             'app_or_process': extract_app_or_process(match['download']),
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
#         })
    
#     return all_results

# # -------------------------
# # Reporting / Summarization
# # -------------------------

# def print_results(results):
#     if not results:
#         print("No indicators triggered.")
#         return
#     print("\n=== Indicator Matches ===")
#     for hit in results:
#         attr = hit.get('attribution', {})
#         print(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit.get('line_num') if hit.get('line_num') else '-'})")
#         print(f"    > Matched: {hit['matched_text']}")
#         print(f"    > App/Process: {hit.get('app_or_process', 'Unknown')}")
#         print(f"    > Context: {hit['context']}")
#         if attr:
#             print(f"    > Source: {attr.get('source','')}, Author: {attr.get('author','')}, Date: {attr.get('date_created','')}")
#         print()

# def save_report(results, output_path):
#     with open(output_path, 'w', encoding='utf-8') as f:
#         for hit in results:
#             f.write(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit.get('line_num') if hit.get('line_num') else '-' }):\n")
#             f.write(f"    > Matched: {hit['matched_text']}\n")
#             f.write(f"    > App/Process: {hit.get('app_or_process', 'Unknown')}\n")
#             f.write(f"    > Context: {hit['context']}\n")
#             attr = hit.get('attribution', {})
#             if attr:
#                 f.write(f"    > Source: {attr.get('source', '')}, Author: {attr.get('author', '')}, Date: {attr.get('date_created', '')}\n")
#             f.write("-----\n")
#     print(f"Report saved to {output_path}")

# # --------------
# # SUMMARY REPORT
# # --------------

# def generate_simple_summary(hits):
#     if not hits:
#         return "No indicators triggered in the scan."

#     indicator_counts = Counter(hit['indicator'] for hit in hits)
#     severity_counts = Counter(hit['severity'] for hit in hits)
#     file_counts = Counter(Path(hit['filepath']).name for hit in hits)
#     app_counts = Counter(hit.get('app_or_process', 'Unknown') for hit in hits)
#     summary = []
#     summary.append(f"Scan Summary:")
#     summary.append(f"Total alerts detected: {len(hits)}")
#     summary.append("Alert counts by type:")
#     for ind, count in indicator_counts.most_common():
#         summary.append(f"  - {ind}: {count} hits")
#     summary.append("\nAlert counts by severity:")
#     for sev, count in severity_counts.most_common():
#         summary.append(f"  - {sev}: {count}")
#     summary.append("\nTop 5 files with alerts:")
#     for f, count in file_counts.most_common(5):
#         summary.append(f"  - {f}: {count}")
#     summary.append("\nTop 5 attributed apps/processes:")
#     for app, count in app_counts.most_common(5):
#         summary.append(f"  - {app}: {count}")
#     summary_text = "\n".join(summary)
#     return summary_text

# # -------------
# # MAIN
# # -------------

# def main():
#     parser = argparse.ArgumentParser(description="Sysdiagnose Indicator Scanner")
#     parser.add_argument("--dir", required=True, help="Extracted logs root directory")
#     parser.add_argument("--indicators", required=True, help="Indicator JSON directory")
#     parser.add_argument("--report", help="Optional: Path to save text report")
#     parser.add_argument("--summary", help="Optional: Path to save summary report")
#     args = parser.parse_args()

#     indicators = load_indicators(args.indicators)
#     results = scan_directory_adv(args.dir, indicators)
#     print_results(results)
#     if args.report:
#         save_report(results, args.report)
#     if args.summary:
#         summary_report = generate_simple_summary(results)
#         with open(args.summary, 'w', encoding='utf-8') as f:
#             f.write(summary_report)
#         print(f"Summary report saved to {args.summary}")

# if __name__ == "__main__":
#     main()
# def parse_plain_results(filepath):
#     """Parse your results.txt plain-text into a list of dicts."""
#     with open(filepath, 'r', encoding='utf-8') as f:
#         lines = f.readlines()

#     hits = []
#     current_hit = {}

#     indicator_re = re.compile(r'\[(.*?)\] (.*?) in (.*?) \(line (\d+)\)')
#     matched_re = re.compile(r'\s*> Matched: (.*)')
#     app_re = re.compile(r'\s*> App/Process: (.*)')

#     for line in lines:
#         line = line.strip()
#         if not line:
#             if current_hit:
#                 hits.append(current_hit)
#                 current_hit = {}
#             continue

#         m_indicator = indicator_re.match(line)
#         if m_indicator:
#             current_hit['severity'] = m_indicator.group(1)
#             current_hit['indicator'] = m_indicator.group(2)
#             current_hit['filepath'] = m_indicator.group(3)
#             current_hit['line_num'] = int(m_indicator.group(4))
#             continue
#         m_matched = matched_re.match(line)
#         if m_matched:
#             current_hit['matched_text'] = m_matched.group(1)
#             continue
#         m_app = app_re.match(line)
#         if m_app:
#             current_hit['app_or_process'] = m_app.group(1)
#             continue

#     if current_hit:
#         hits.append(current_hit)

#     return hits

# def generate_simple_summary(hits):
#     """Generate a human-readable aggregated summary string."""
#     if not hits:
#         return "No indicators triggered in the scan."

#     indicator_counts = Counter(hit['indicator'] for hit in hits)
#     severity_counts = Counter(hit['severity'] for hit in hits)
#     file_counts = Counter(hit['filepath'].split('\\')[-1].split('/')[-1] for hit in hits)
#     app_counts = Counter(hit.get('app_or_process', 'Unknown') for hit in hits)

#     summary = []

#     summary.append(f"Scan Summary:")
#     summary.append(f"Total alerts detected: {len(hits)}")
#     summary.append("Alert counts by type:")
#     for ind, count in indicator_counts.most_common():
#         summary.append(f"  - {ind}: {count} hits")

#     summary.append("\nAlert counts by severity:")
#     for sev, count in severity_counts.most_common():
#         summary.append(f"  - {sev}: {count}")

#     summary.append("\nTop 5 files with alerts:")
#     for f, count in file_counts.most_common(5):
#         summary.append(f"  - {f}: {count}")

#     summary.append("\nTop 5 attributed apps/processes:")
#     for app, count in app_counts.most_common(5):
#         summary.append(f"  - {app}: {count}")

#     summary_text = "\n".join(summary)
#     return summary_text

# if __name__ == "__main__":
#     # Example usage: summarize after scan is done
#     results_file = 'results.txt'  # or pass as argument
#     hits_data = parse_plain_results(results_file)
#     summary_report = generate_simple_summary(hits_data)

#     print("\n" + "="*60)
#     print(summary_report)
#     print("="*60)

#     # Optional: Write summary to file
#     with open('summary_report.txt', 'w', encoding='utf-8') as f:
#         f.write(summary_report)
# # This script is designed to scan system logs and indicators for potential security issues.
# # It loads JSON-based indicators, scans files for patterns, and detects advanced threats like app masquerading, stealthy launch agents, and multi-stage downloads.
# # The results can be printed to the console or saved to a report file, with an optional summary report generation.
# # The script is intended for use in security analysis and incident response, particularly in macOS environments.
# # It is modular and can be extended with additional detection logic as needed.

import os
import json
import re
import argparse
import plistlib
from pathlib import Path
from collections import Counter
import concurrent.futures

# ------------------------------
# Basic Pattern/JSON Indicators
# ------------------------------
def load_indicators(indicators_dir):
    indicators = []
    for file in os.listdir(indicators_dir):
        if file.endswith('.json'):
            path = os.path.join(indicators_dir, file)
            print(f"Loading indicator: {file}")
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if not content:
                        print(f"Warning: {file} is empty, skipping.")
                        continue
                    obj = json.loads(content)
                    obj['compiled_patterns'] = [re.compile(p, re.IGNORECASE) for p in obj['patterns']]
                    indicators.append(obj)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON in file {file}: {e}")
            except Exception as e:
                print(f"Unexpected error loading file {file}: {e}")
    print(f"Loaded {len(indicators)} indicators.")
    return indicators

def extract_app_or_process(line):
    match = re.search(r'\[([A-Za-z0-9\._\-]+\.app)\]', line)
    if match:
        return match.group(1)
    match = re.search(r'Process:\s*([A-Za-z0-9\._\-]+)', line)
    if match:
        return match.group(1)
    match = re.search(r'([A-Za-z0-9\._\-]+)\.app', line)
    if match:
        return match.group(0)
    match = re.search(r'([A-Za-z0-9\._\-]+):\s', line)
    if match:
        return match.group(1)
    return "Unknown"

def scan_file(filepath, indicators):
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Could not read {filepath}: {e}")
        return results

    for idx, line in enumerate(lines):
        for indicator in indicators:
            # Defensive: skip if missing required keys
            patterns = indicator.get('patterns', [])
            compiled = indicator.get('compiled_patterns', [])
            if len(patterns) != len(compiled):
                continue
            for pat, regex in zip(patterns, compiled):
                for m in regex.finditer(line):
                    app_or_process = extract_app_or_process(line)
                    results.append({
                        'filepath': filepath,
                        'line_num': idx + 1,
                        'indicator': indicator.get('name', 'Unknown'),
                        'description': indicator.get('description', 'No description supplied.'),
                        'pattern': pat,
                        'matched_text': m.group(0),
                        'severity': indicator.get('severity', 'Unknown'),
                        'context': line.strip(),
                        'app_or_process': app_or_process,
                        'attribution': indicator.get('attribution', {})
                    })
    return results

# ----------------------------------------
# Advanced "Crazy" Python Indicator Logic
# ----------------------------------------

def detect_app_masquerade(ps_lines):
    findings = []
    for line in ps_lines:
        if re.search(r"\b\w+\.app\.app\b", line) or re.search(r"[^\x00-\x7F]", line):
            findings.append(line.strip())
        m = re.search(r'/Applications/(.+?\.app)', line)
        if m and (not m.group(1).startswith("com.apple") and " " in m.group(1)):
            findings.append(line.strip())
    return findings

def detect_stealthy_launchagents(plist_paths):
    suspicious = []
    for path in plist_paths:
        try:
            with open(path, 'rb') as f:
                data = plistlib.load(f)
            if data.get("KeepAlive") == True and not str(data.get('Label', '')).startswith("com.apple"):
                suspicious.append({"path": path, "label": data.get("Label"), "desc": "User-writable, persistent, non-Apple LaunchAgent"})
        except Exception:
            pass
    return suspicious

def detect_hooked_system_binary(ps_lines):
    suspicious = []
    for line in ps_lines:
        parts = line.split()
        if len(parts) >= 4:
            proc_name = parts[0]
            parent = parts[-1]
            if proc_name in ["login", "bash", "sh", "launchd"] and parent not in ["launchd", "init"]:
                suspicious.append({"process": proc_name, "parent": parent, "line": line.strip()})
    return suspicious

def detect_unknown_vpn_profile(profile_lines):
    suspicious = []
    for line in profile_lines:
        if re.search(r'VPNType\s*:\s*(?!IPSec|IKEv2|L2TP)\w+', line):
            suspicious.append(line.strip())
        if re.search(r'proxy\s+[A-Za-z0-9]+', line, re.IGNORECASE) and not re.search(r'Apple|Nord|Express|TunnelBear', line):
            suspicious.append(line.strip())
        if "RemoteManagement" in line:
            suspicious.append(line.strip())
    return suspicious

def detect_multistage_download_exec(log_lines):
    matches = []
    events = []
    for idx, line in enumerate(log_lines):
        if re.search(r"\bcurl\b|\bwget\b", line):
            events.append(("download", idx, line))
        if re.search(r"\bchmod\b.*\+x", line):
            events.append(("chmod", idx, line))
        if re.search(r"\./[A-Za-z0-9\-_]+\b", line):
            events.append(("exec", idx, line))
    for i in range(len(events) - 2):
        if (events[i][0] == "download" and
            events[i+1][0] == "chmod" and
            events[i+2][0] == "exec" and
            events[i+2][1] - events[i][1] < 10):
            matches.append({"download": events[i][2], "chmod": events[i+1][2], "exec": events[i+2][2]})
    return matches

# ----------------------
# Multithreaded Directory Walker & Scanner
# ----------------------
def scan_directory_threaded(root_dir, indicators, file_exts=None, max_workers=8):
    if file_exts is None:
        file_exts = {'.log', '.txt', '.plist', '.json', '.xml', '.csv','.sysdiagnose', '.trace'}
    files_to_scan = []
    ps_lines = []
    all_plist_paths = []
    profile_lines = []
    all_log_lines = []

    for root, dirs, files in os.walk(root_dir):
        for file in files:
            ext = Path(file).suffix.lower()
            fp = os.path.join(root, file)
            # Collect process list (ps.txt)
            if file == 'ps.txt':
                try:
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                        ps_lines.extend(f.readlines())
                except Exception:
                    continue
            # Collect all plists for LaunchAgents/Daemons
            if 'launchagent' in file.lower() or 'launchdaemon' in file.lower() or file.endswith('.plist'):
                all_plist_paths.append(fp)
            # Collect VPN/profile files
            if 'vpn' in file.lower() or 'profile' in file.lower() or file.endswith('.plist'):
                try:
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                        profile_lines.extend(f.readlines())
                except Exception:
                    continue
            # Collect logs for multi-stage exec
            if ext in {'.log', '.txt'} or file == 'ps.txt':
                try:
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                        all_log_lines.extend(f.readlines())
                except Exception:
                    continue
            # Add files for standard scanning
            if ext in file_exts:
                files_to_scan.append(fp)

    all_results = []
    # Multi-threaded scan_file for all matched files
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_file, fp, indicators) for fp in files_to_scan]
        for future in concurrent.futures.as_completed(futures):
            all_results.extend(future.result())

    # Add advanced indicators results
    for line in detect_app_masquerade(ps_lines):
        all_results.append({
            'filepath': 'ps.txt',
            'line_num': None,
            'indicator': "App_Masquerading",
            'description': "Fake/Impostor app or .app Unicode trick detected.",
            'pattern': 'Advanced logic',
            'matched_text': line,
            'severity': 'High',
            'context': line.strip(),
            'app_or_process': extract_app_or_process(line),
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
        })
    for obj in detect_stealthy_launchagents(all_plist_paths):
        all_results.append({
            'filepath': obj.get('path', 'N/A'),
            'line_num': None,
            'indicator': "Stealthy_LaunchAgent",
            'description': obj.get('desc', ''),
            'pattern': 'Advanced logic',
            'matched_text': obj.get('label', 'Unknown'),
            'severity': 'High',
            'context': obj.get('label', 'Unknown'),
            'app_or_process': obj.get('label', 'Unknown'),
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
        })
    for obj in detect_hooked_system_binary(ps_lines):
        all_results.append({
            'filepath': 'ps.txt',
            'line_num': None,
            'indicator': "Hooked_System_Binary",
            'description': "System binary started by suspicious parent process.",
            'pattern': 'Advanced logic',
            'matched_text': obj['line'],
            'severity': 'High',
            'context': f"{obj['process']} by {obj['parent']}: {obj['line']}",
            'app_or_process': obj['process'],
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
        })
    for line in detect_unknown_vpn_profile(profile_lines):
        all_results.append({
            'filepath': 'vpn_profile',
            'line_num': None,
            'indicator': "Unknown_VPN_Profile",
            'description': "Suspicious VPN or proxy profile entry.",
            'pattern': 'Advanced logic',
            'matched_text': line,
            'severity': 'Medium',
            'context': line,
            'app_or_process': extract_app_or_process(line),
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
        })
    for match in detect_multistage_download_exec(all_log_lines):
        all_results.append({
            'filepath': 'log_correlation',
            'line_num': None,
            'indicator': 'MultiStage_Download_Exec',
            'description': 'Download, chmod, exec chain detected (likely malware installation).',
            'pattern': 'Advanced logic',
            'matched_text': f"{match['download']} || {match['chmod']} || {match['exec']}",
            'severity': 'High',
            'context': f"{match['download'].strip()} → {match['chmod'].strip()} → {match['exec'].strip()}",
            'app_or_process': extract_app_or_process(match['download']),
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'}
        })
    
    return all_results


# -------------------------
# Reporting / Summarization
# -------------------------

def print_results(results):
    if not results:
        print("No indicators triggered.")
        return
    print("\n=== Indicator Matches ===")
    for hit in results:
        attr = hit.get('attribution', {})
        print(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit.get('line_num') if hit.get('line_num') else '-'})")
        print(f"    > Matched: {hit['matched_text']}")
        print(f"    > App/Process: {hit.get('app_or_process', 'Unknown')}")
        print(f"    > Context: {hit['context']}")
        if attr:
            print(f"    > Source: {attr.get('source','')}, Author: {attr.get('author','')}, Date: {attr.get('date_created','')}")
        print()

def save_report(results, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        for hit in results:
            f.write(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit.get('line_num') if hit.get('line_num') else '-'}):\n")
            f.write(f"    > Matched: {hit['matched_text']}\n")
            f.write(f"    > App/Process: {hit.get('app_or_process', 'Unknown')}\n")
            f.write(f"    > Context: {hit['context']}\n")
            attr = hit.get('attribution', {})
            if attr:
                f.write(f"    > Source: {attr.get('source', '')}, Author: {attr.get('author', '')}, Date: {attr.get('date_created', '')}\n")
            f.write("-----\n")
    print(f"Report saved to {output_path}")

# --------------
# SUMMARY REPORT
# --------------

def generate_simple_summary(hits):
    if not hits:
        return "No indicators triggered in the scan."

    indicator_counts = Counter(hit['indicator'] for hit in hits)
    severity_counts = Counter(hit['severity'] for hit in hits)
    file_counts = Counter(Path(hit['filepath']).name for hit in hits)
    app_counts = Counter(hit.get('app_or_process', 'Unknown') for hit in hits)
    summary = []
    summary.append(f"Scan Summary:")
    summary.append(f"Total alerts detected: {len(hits)}")
    summary.append("Alert counts by type:")
    for ind, count in indicator_counts.most_common():
        summary.append(f"  - {ind}: {count} hits")
    summary.append("\nAlert counts by severity:")
    for sev, count in severity_counts.most_common():
        summary.append(f"  - {sev}: {count}")
    summary.append("\nTop 5 files with alerts:")
    for f, count in file_counts.most_common(5):
        summary.append(f"  - {f}: {count}")
    summary.append("\nTop 5 attributed apps/processes:")
    for app, count in app_counts.most_common(5):
        summary.append(f"  - {app}: {count}")
    summary_text = "\n".join(summary)
    return summary_text

# -------------
# MAIN
# -------------

def main():
    parser = argparse.ArgumentParser(description="Sysdiagnose Indicator Scanner (Threaded)")
    parser.add_argument("--dir", required=True, help="Extracted logs root directory")
    parser.add_argument("--indicators", required=True, help="Indicator JSON directory")
    parser.add_argument("--report", help="Optional: Path to save text report")
    parser.add_argument("--summary", help="Optional: Path to save summary report")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads (default=8)")
    args = parser.parse_args()

    indicators = load_indicators(args.indicators)
    results = scan_directory_threaded(args.dir, indicators, max_workers=args.threads)
    print_results(results)
    if args.report:
        save_report(results, args.report)
    if args.summary:
        summary_report = generate_simple_summary(results)
        with open(args.summary, 'w', encoding='utf-8') as f:
            f.write(summary_report)
        print(f"Summary report saved to {args.summary}")

if __name__ == "__main__":
    main()


# Optional: Legacy plain-text parsing & summary functions here if you want to parse results.txt manually (not used in threaded scan):
def parse_plain_results(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    hits = []
    current_hit = {}

    indicator_re = re.compile(r'\[(.*?)\] (.*?) in (.*?) \(line (\d+)\)')
    matched_re = re.compile(r'\s*> Matched: (.*)')
    app_re = re.compile(r'\s*> App/Process: (.*)')

    for line in lines:
        line = line.strip()
        if not line:
            if current_hit:
                hits.append(current_hit)
                current_hit = {}
            continue

        m_indicator = indicator_re.match(line)
        if m_indicator:
            current_hit['severity'] = m_indicator.group(1)
            current_hit['indicator'] = m_indicator.group(2)
            current_hit['filepath'] = m_indicator.group(3)
            current_hit['line_num'] = int(m_indicator.group(4))
            continue
        m_matched = matched_re.match(line)
        if m_matched:
            current_hit['matched_text'] = m_matched.group(1)
            continue
        m_app = app_re.match(line)
        if m_app:
            current_hit['app_or_process'] = m_app.group(1)
            continue

    if current_hit:
        hits.append(current_hit)
    return hits

def generate_simple_summary(hits):
    if not hits:
        return "No indicators triggered in the scan."

    indicator_counts = Counter(hit['indicator'] for hit in hits)
    severity_counts = Counter(hit['severity'] for hit in hits)
    file_counts = Counter(hit['filepath'].split('\\')[-1].split('/')[-1] for hit in hits)
    app_counts = Counter(hit.get('app_or_process', 'Unknown') for hit in hits)
    summary = []
    summary.append(f"Scan Summary:")
    summary.append(f"Total alerts detected: {len(hits)}")
    summary.append("Alert counts by type:")
    for ind, count in indicator_counts.most_common():
        summary.append(f"  - {ind}: {count} hits")
    summary.append("\nAlert counts by severity:")
    for sev, count in severity_counts.most_common():
        summary.append(f"  - {sev}: {count}")
    summary.append("\nTop 5 files with alerts:")
    for f, count in file_counts.most_common(5):
        summary.append(f"  - {f}: {count}")
    summary.append("\nTop 5 attributed apps/processes:")
    for app, count in app_counts.most_common(5):
        summary.append(f"  - {app}: {count}")
    return "\n".join(summary)
# # This script is designed to scan system logs and indicators for potential security issues.
# # It loads JSON-based indicators, scans files for patterns, and detects advanced threats like app masquerading, stealthy launch agents, and multi-stage downloads.
# # The results can be printed to the console or saved to a report file, with an optional summary report generation.
# # The script is intended for use in security analysis and incident response, particularly in macOS environments.
# # It is modular and can be extended with additional detection logic as needed.
# # This code is designed to scan system logs and indicators for potential security issues.
