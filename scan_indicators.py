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

# import os
# import json
# import re
# import argparse
# import plistlib
# from pathlib import Path
# from collections import Counter
# import concurrent.futures
# from tqdm import tqdm
# import time
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
#             # Defensive: skip if missing required keys
#             patterns = indicator.get('patterns', [])
#             compiled = indicator.get('compiled_patterns', [])
#             if len(patterns) != len(compiled):
#                 continue
#             for pat, regex in zip(patterns, compiled):
#                 for m in regex.finditer(line):
#                     app_or_process = extract_app_or_process(line)
#                     results.append({
#                         'filepath': filepath,
#                         'line_num': idx + 1,
#                         'indicator': indicator.get('name', 'Unknown'),
#                         'description': indicator.get('description', 'No description supplied.'),
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
# # Multithreaded Directory Walker & Scanner
# # ----------------------
# def scan_directory_threaded(root_dir, indicators, file_exts=None, max_workers=8):
#     if file_exts is None:
#         file_exts = {'.log', '.txt', '.plist', '.json', '.xml', '.csv','.sysdiagnose', '.trace'}
#     files_to_scan = []
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
#             # Add files for standard scanning
#             if ext in file_exts:
#                 files_to_scan.append(fp)
    
#     all_results = []
#     # Multi-threaded scan_file for all matched files
#     with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
#         futures = [executor.submit(scan_file, fp, indicators) for fp in files_to_scan]
#         for future in tqdm(concurrent.futures.as_completed(futures), 
#                        total=len(futures), desc="Scanning files"):
#             all_results.extend(future.result())

#     # Add advanced indicators results
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
# def calculate_risk_score(results):
#     """Calculate overall device risk score based on findings"""
#     risk_score = 0
#     for hit in results:
#         severity_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
#         risk_score += severity_weights.get(hit['severity'], 1)
    
#     if risk_score >= 50: return "CRITICAL RISK"
#     elif risk_score >= 25: return "HIGH RISK"
#     elif risk_score >= 10: return "MODERATE RISK"
#     else: return "LOW RISK"
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
#             f.write(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit.get('line_num') if hit.get('line_num') else '-'}):\n")
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
#     parser = argparse.ArgumentParser(description="Sysdiagnose Indicator Scanner (Threaded)")
#     parser.add_argument("--dir", required=True, help="Extracted logs root directory")
#     parser.add_argument("--indicators", required=True, help="Indicator JSON directory")
#     parser.add_argument("--report", help="Optional: Path to save text report")
#     parser.add_argument("--summary", help="Optional: Path to save summary report")
#     parser.add_argument("--threads", type=int, default=8, help="Number of worker threads (default=8)")
#     args = parser.parse_args()

#     indicators = load_indicators(args.indicators)
#     results = scan_directory_threaded(args.dir, indicators, max_workers=args.threads)
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


# # Optional: Legacy plain-text parsing & summary functions here if you want to parse results.txt manually (not used in threaded scan):
# def parse_plain_results(filepath):
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
#     return "\n".join(summary)
# # # This script is designed to scan system logs and indicators for potential security issues.
# # # It loads JSON-based indicators, scans files for patterns, and detects advanced threats like app masquerading, stealthy launch agents, and multi-stage downloads.
# # # The results can be printed to the console or saved to a report file, with an optional summary report generation.
# # # The script is intended for use in security analysis and incident response, particularly in macOS environments.
# # # It is modular and can be extended with additional detection logic as needed.
# # # This code is designed to scan system logs and indicators for potential security issues.
import os
import json
import re
import argparse
import plistlib
from pathlib import Path
from collections import Counter
import concurrent.futures
from tqdm import tqdm
import time
import csv
import yaml
from datetime import datetime

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
                        'attribution': indicator.get('attribution', {}),
                        'timestamp': datetime.now().isoformat()
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
        for future in tqdm(concurrent.futures.as_completed(futures), 
                       total=len(futures), desc="Scanning files"):
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
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
            'timestamp': datetime.now().isoformat()
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
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
            'timestamp': datetime.now().isoformat()
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
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
            'timestamp': datetime.now().isoformat()
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
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
            'timestamp': datetime.now().isoformat()
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
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
            'timestamp': datetime.now().isoformat()
        })
    
    return all_results

# -------------------------
# Configuration Loading
# -------------------------
def load_config(config_path):
    """Load configuration from YAML file"""
    default_config = {
        'scanning': {
            'max_threads': 8,
            'file_extensions': ['.log', '.txt', '.plist', '.json', '.xml', '.csv', '.sysdiagnose', '.trace'],
            'timeout_seconds': 300
        },
        'reporting': {
            'include_context': True,
            'max_context_length': 200,
            'export_formats': ['txt', 'json', 'csv']
        },
        'thresholds': {
            'high_risk_score': 25,
            'critical_risk_score': 50
        }
    }
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f)
                # Merge with defaults
                for section, values in user_config.items():
                    if section in default_config:
                        default_config[section].update(values)
                    else:
                        default_config[section] = values
        except Exception as e:
            print(f"Warning: Could not load config file {config_path}: {e}")
            print("Using default configuration.")
    
    return default_config

# -------------------------
# Export Functions
# -------------------------
def export_json(results, filepath):
    """Export results to JSON format"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"JSON report exported to {filepath}")
    except Exception as e:
        print(f"Error exporting JSON: {e}")

def export_csv(results, filepath):
    """Export results to CSV format"""
    if not results:
        print("No results to export to CSV")
        return
    
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            # Flatten attribution for CSV
            fieldnames = ['filepath', 'line_num', 'indicator', 'description', 'pattern', 
                         'matched_text', 'severity', 'context', 'app_or_process', 'timestamp',
                         'attribution_source', 'attribution_author', 'attribution_date']
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Flatten the result
                flat_result = result.copy()
                attribution = flat_result.pop('attribution', {})
                flat_result['attribution_source'] = attribution.get('source', '')
                flat_result['attribution_author'] = attribution.get('author', '')
                flat_result['attribution_date'] = attribution.get('date_created', '')
                writer.writerow(flat_result)
        print(f"CSV report exported to {filepath}")
    except Exception as e:
        print(f"Error exporting CSV: {e}")

def export_html(results, filepath):
    """Export results to HTML format"""
    try:
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>iOS AntiSpyware Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f4f4f4; padding: 10px; margin-bottom: 20px; }}
        .result {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; }}
        .high {{ border-left: 5px solid #ff4444; }}
        .medium {{ border-left: 5px solid #ffaa00; }}
        .low {{ border-left: 5px solid #44ff44; }}
        .critical {{ border-left: 5px solid #aa0000; background-color: #ffe6e6; }}
        .indicator {{ font-weight: bold; color: #333; }}
        .context {{ background-color: #f9f9f9; padding: 5px; margin: 5px 0; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>iOS AntiSpyware Scan Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total findings: {len(results)}</p>
    </div>
"""
        
        for result in results:
            severity_class = result['severity'].lower()
            html_content += f"""
    <div class="result {severity_class}">
        <div class="indicator">[{result['severity']}] {result['indicator']}</div>
        <p><strong>File:</strong> {Path(result['filepath']).name} (Line: {result.get('line_num', 'N/A')})</p>
        <p><strong>Description:</strong> {result['description']}</p>
        <p><strong>Matched:</strong> {result['matched_text']}</p>
        <p><strong>App/Process:</strong> {result.get('app_or_process', 'Unknown')}</p>
        <div class="context"><strong>Context:</strong> {result['context']}</div>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report exported to {filepath}")
    except Exception as e:
        print(f"Error exporting HTML: {e}")

# -------------------------
# Risk Assessment
# -------------------------
def calculate_risk_score(results):
    """Calculate overall device risk score based on findings"""
    risk_score = 0
    for hit in results:
        severity_weights = {"Critical": 20, "High": 0.005, "Medium": 0.001, "Low": 0.0005, "Unknown": 0.0005}
        risk_score += severity_weights.get(hit['severity'], 1)
    
    if risk_score >= 50 : return "CRITICAL RISK", risk_score
    elif risk_score >= 40: return "HIGH RISK", risk_score
    elif risk_score >= 20: return "MODERATE RISK", risk_score
    else: return "LOW RISK", risk_score

def generate_risk_assessment(results):
    """Generate detailed risk assessment"""
    risk_level, risk_score = calculate_risk_score(results)
    
    severity_counts = Counter(hit['severity'] for hit in results)
    indicator_counts = Counter(hit['indicator'] for hit in results)
    
    assessment = []
    assessment.append("=== RISK ASSESSMENT ===")
    assessment.append(f"Overall Risk Level: {risk_level} (Score: {risk_score})")
    assessment.append(f"Total Findings: {len(results)}")
    assessment.append("")
    
    assessment.append("Severity Breakdown:")
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(severity, 0)
        assessment.append(f"  {severity}: {count}")
    assessment.append("")
    
    assessment.append("Top Threat Indicators:")
    for indicator, count in indicator_counts.most_common(10):
        assessment.append(f"  {indicator}: {count} occurrences")
    
    assessment.append("")
    assessment.append("Recommendations:")
    if risk_score >= 50:
        assessment.append("  🚨 IMMEDIATE ACTION REQUIRED")
        assessment.append("  - Device shows signs of advanced persistent threats")
        assessment.append("  - Conduct full forensic analysis")
        assessment.append("  - Consider device isolation")
    elif risk_score >= 25:
        assessment.append("  ⚠️  HIGH PRIORITY INVESTIGATION")
        assessment.append("  - Multiple suspicious indicators detected")
        assessment.append("  - Review all findings carefully")
        assessment.append("  - Implement additional monitoring")
    elif risk_score >= 10:
        assessment.append("  ℹ️  MODERATE CONCERN")
        assessment.append("  - Some suspicious activity detected")
        assessment.append("  - Monitor for additional indicators")
    else:
        assessment.append("  ✅ LOW RISK")
        assessment.append("  - No critical threats detected")
        assessment.append("  - Continue routine monitoring")
    
    return "\n".join(assessment)

# -------------------------
# Reporting / Summarization
# -------------------------
def print_results(results, quiet=False):
    if quiet:
        return
    
    if not results:
        print("No indicators triggered.")
        return
    
    # Print risk assessment first
    print("\n" + generate_risk_assessment(results))
    
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
        # Write risk assessment
        f.write(generate_risk_assessment(results) + "\n\n")
        
        # Write detailed results
        f.write("=== DETAILED FINDINGS ===\n\n")
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
    
    risk_level, risk_score = calculate_risk_score(hits)
    
    summary = []
    summary.append(f"=== iOS ANTISPYWARE SCAN SUMMARY ===")
    summary.append(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary.append(f"Risk Level: {risk_level} (Score: {risk_score})")
    summary.append(f"Total alerts detected: {len(hits)}")
    summary.append("")
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
    parser = argparse.ArgumentParser(
        description="iOS AntiSpyware Detection Tool v2.0 - Advanced Sysdiagnose Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan_indicators.py --dir /path/to/sysdiagnose --indicators indicators/
  python scan_indicators.py --dir logs/ --indicators indicators/ --export-json results.json --threads 4
  python scan_indicators.py --dir data/ --indicators indicators/ --config config.yaml --quiet
        """
    )
    
    parser.add_argument("--dir", required=True, help="Extracted logs root directory")
    parser.add_argument("--indicators", required=True, help="Indicator JSON directory")
    parser.add_argument("--report", help="Path to save detailed text report")
    parser.add_argument("--summary", help="Path to save summary report")
    parser.add_argument("--export-json", help="Export results as JSON")
    parser.add_argument("--export-csv", help="Export results as CSV")
    parser.add_argument("--export-html", help="Export results as HTML")
    parser.add_argument("--config", help="Path to configuration YAML file")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads (default=8)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress console output")
    parser.add_argument("--version", action="version", version="iOS AntiSpyware v2.0")
    
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)
    
    # Override threads from config if not specified
    if args.threads == 8 and 'scanning' in config:
        args.threads = config['scanning'].get('max_threads', 8)

    if not args.quiet:
        print("=== iOS AntiSpyware Detection Tool v2.0 ===")
        print(f"Scanning directory: {args.dir}")
        print(f"Using {args.threads} threads")
        print()

    start_time = time.time()
    
    indicators = load_indicators(args.indicators)
    results = scan_directory_threaded(args.dir, indicators, max_workers=args.threads)
    
    scan_time = time.time() - start_time
    
    if not args.quiet:
        print(f"\nScan completed in {scan_time:.2f} seconds")
    
    # Print results to console
    print_results(results, args.quiet)
    
    # Save reports
    if args.report:
        save_report(results, args.report)
    
    if args.summary:
        summary_report = generate_simple_summary(results)
        with open(args.summary, 'w', encoding='utf-8') as f:
            f.write(summary_report)
        if not args.quiet:
            print(f"Summary report saved to {args.summary}")
    
    # Export in different formats
    if args.export_json:
        export_json(results, args.export_json)
    
    if args.export_csv:
        export_csv(results, args.export_csv)
    
    if args.export_html:
        export_html(results, args.export_html)
    
    # Print final stats
    if not args.quiet:
        risk_level, risk_score = calculate_risk_score(results)
        print(f"\n🎯 Final Assessment: {risk_level} ({len(results)} findings, Risk Score: {risk_score})")

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

# This script is designed to scan system logs and indicators for potential security issues.
# It loads JSON-based indicators, scans files for patterns, and detects advanced threats like app masquerading, stealthy launch agents, and multi-stage downloads.
# The results can be printed to the console or saved to a report file, with an optional summary report generation.
# The script is intended for use in security analysis and incident response, particularly in iOS environments.
# It is modular and can be extended with additional detection logic as needed.
# This code is designed to scan system logs and indicators for potential security issues.
