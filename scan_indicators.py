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

## Ace One till 16-08-25
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
# import csv
# import yaml
# from datetime import datetime

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
#                         'attribution': indicator.get('attribution', {}),
#                         'timestamp': datetime.now().isoformat()
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
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
#             'timestamp': datetime.now().isoformat()
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
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
#             'timestamp': datetime.now().isoformat()
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
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
#             'timestamp': datetime.now().isoformat()
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
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
#             'timestamp': datetime.now().isoformat()
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
#             'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
#             'timestamp': datetime.now().isoformat()
#         })
    
#     return all_results

# # -------------------------
# # Configuration Loading
# # -------------------------
# def load_config(config_path):
#     """Load configuration from YAML file"""
#     default_config = {
#         'scanning': {
#             'max_threads': 8,
#             'file_extensions': ['.log', '.txt', '.plist', '.json', '.xml', '.csv', '.sysdiagnose', '.trace'],
#             'timeout_seconds': 300
#         },
#         'reporting': {
#             'include_context': True,
#             'max_context_length': 200,
#             'export_formats': ['txt', 'json', 'csv']
#         },
#         'thresholds': {
#             'high_risk_score': 25,
#             'critical_risk_score': 50
#         }
#     }
    
#     if config_path and os.path.exists(config_path):
#         try:
#             with open(config_path, 'r', encoding='utf-8') as f:
#                 user_config = yaml.safe_load(f)
#                 # Merge with defaults
#                 for section, values in user_config.items():
#                     if section in default_config:
#                         default_config[section].update(values)
#                     else:
#                         default_config[section] = values
#         except Exception as e:
#             print(f"Warning: Could not load config file {config_path}: {e}")
#             print("Using default configuration.")
    
#     return default_config

# # -------------------------
# # Export Functions
# # -------------------------
# def export_json(results, filepath):
#     """Export results to JSON format"""
#     try:
#         with open(filepath, 'w', encoding='utf-8') as f:
#             json.dump(results, f, indent=2, ensure_ascii=False)
#         print(f"JSON report exported to {filepath}")
#     except Exception as e:
#         print(f"Error exporting JSON: {e}")

# def export_csv(results, filepath):
#     """Export results to CSV format"""
#     if not results:
#         print("No results to export to CSV")
#         return
    
#     try:
#         with open(filepath, 'w', newline='', encoding='utf-8') as f:
#             # Flatten attribution for CSV
#             fieldnames = ['filepath', 'line_num', 'indicator', 'description', 'pattern', 
#                          'matched_text', 'severity', 'context', 'app_or_process', 'timestamp',
#                          'attribution_source', 'attribution_author', 'attribution_date']
            
#             writer = csv.DictWriter(f, fieldnames=fieldnames)
#             writer.writeheader()
            
#             for result in results:
#                 # Flatten the result
#                 flat_result = result.copy()
#                 attribution = flat_result.pop('attribution', {})
#                 flat_result['attribution_source'] = attribution.get('source', '')
#                 flat_result['attribution_author'] = attribution.get('author', '')
#                 flat_result['attribution_date'] = attribution.get('date_created', '')
#                 writer.writerow(flat_result)
#         print(f"CSV report exported to {filepath}")
#     except Exception as e:
#         print(f"Error exporting CSV: {e}")

# def export_html(results, filepath):
#     """Export results to HTML format"""
#     try:
#         html_content = f"""
# <!DOCTYPE html>
# <html>
# <head>
#     <title>iOS AntiSpyware Scan Report</title>
#     <style>
#         body {{ font-family: Arial, sans-serif; margin: 20px; }}
#         .header {{ background-color: #f4f4f4; padding: 10px; margin-bottom: 20px; }}
#         .result {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; }}
#         .high {{ border-left: 5px solid #ff4444; }}
#         .medium {{ border-left: 5px solid #ffaa00; }}
#         .low {{ border-left: 5px solid #44ff44; }}
#         .critical {{ border-left: 5px solid #aa0000; background-color: #ffe6e6; }}
#         .indicator {{ font-weight: bold; color: #333; }}
#         .context {{ background-color: #f9f9f9; padding: 5px; margin: 5px 0; font-family: monospace; }}
#     </style>
# </head>
# <body>
#     <div class="header">
#         <h1>iOS AntiSpyware Scan Report</h1>
#         <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
#         <p>Total findings: {len(results)}</p>
#     </div>
# """
        
#         for result in results:
#             severity_class = result['severity'].lower()
#             html_content += f"""
#     <div class="result {severity_class}">
#         <div class="indicator">[{result['severity']}] {result['indicator']}</div>
#         <p><strong>File:</strong> {Path(result['filepath']).name} (Line: {result.get('line_num', 'N/A')})</p>
#         <p><strong>Description:</strong> {result['description']}</p>
#         <p><strong>Matched:</strong> {result['matched_text']}</p>
#         <p><strong>App/Process:</strong> {result.get('app_or_process', 'Unknown')}</p>
#         <div class="context"><strong>Context:</strong> {result['context']}</div>
#     </div>
# """
        
#         html_content += """
# </body>
# </html>
# """
        
#         with open(filepath, 'w', encoding='utf-8') as f:
#             f.write(html_content)
#         print(f"HTML report exported to {filepath}")
#     except Exception as e:
#         print(f"Error exporting HTML: {e}")

# # -------------------------
# # Risk Assessment
# # -------------------------
# def calculate_risk_score(results):
#     """Calculate overall device risk score based on findings"""
#     risk_score = 0
#     for hit in results:
#         severity_weights = {"Critical": 20, "High": 0.005, "Medium": 0.001, "Low": 0.0005, "Unknown": 0.0005}
#         risk_score += severity_weights.get(hit['severity'], 1)
    
#     if risk_score >= 50 : return "CRITICAL RISK", risk_score
#     elif risk_score >= 40: return "HIGH RISK", risk_score
#     elif risk_score >= 20: return "MODERATE RISK", risk_score
#     else: return "LOW RISK", risk_score

# def generate_risk_assessment(results):
#     """Generate detailed risk assessment"""
#     risk_level, risk_score = calculate_risk_score(results)
    
#     severity_counts = Counter(hit['severity'] for hit in results)
#     indicator_counts = Counter(hit['indicator'] for hit in results)
    
#     assessment = []
#     assessment.append("=== RISK ASSESSMENT ===")
#     assessment.append(f"Overall Risk Level: {risk_level} (Score: {risk_score})")
#     assessment.append(f"Total Findings: {len(results)}")
#     assessment.append("")
    
#     assessment.append("Severity Breakdown:")
#     for severity in ["Critical", "High", "Medium", "Low"]:
#         count = severity_counts.get(severity, 0)
#         assessment.append(f"  {severity}: {count}")
#     assessment.append("")
    
#     assessment.append("Top Threat Indicators:")
#     for indicator, count in indicator_counts.most_common(10):
#         assessment.append(f"  {indicator}: {count} occurrences")
    
#     assessment.append("")
#     assessment.append("Recommendations:")
#     if risk_score >= 50:
#         assessment.append("  🚨 IMMEDIATE ACTION REQUIRED")
#         assessment.append("  - Device shows signs of advanced persistent threats")
#         assessment.append("  - Conduct full forensic analysis")
#         assessment.append("  - Consider device isolation")
#     elif risk_score >= 25:
#         assessment.append("  ⚠️  HIGH PRIORITY INVESTIGATION")
#         assessment.append("  - Multiple suspicious indicators detected")
#         assessment.append("  - Review all findings carefully")
#         assessment.append("  - Implement additional monitoring")
#     elif risk_score >= 10:
#         assessment.append("  ℹ️  MODERATE CONCERN")
#         assessment.append("  - Some suspicious activity detected")
#         assessment.append("  - Monitor for additional indicators")
#     else:
#         assessment.append("  ✅ LOW RISK")
#         assessment.append("  - No critical threats detected")
#         assessment.append("  - Continue routine monitoring")
    
#     return "\n".join(assessment)

# # -------------------------
# # Reporting / Summarization
# # -------------------------
# def print_results(results, quiet=False):
#     if quiet:
#         return
    
#     if not results:
#         print("No indicators triggered.")
#         return
    
#     # Print risk assessment first
#     print("\n" + generate_risk_assessment(results))
    
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
#         # Write risk assessment
#         f.write(generate_risk_assessment(results) + "\n\n")
        
#         # Write detailed results
#         f.write("=== DETAILED FINDINGS ===\n\n")
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
    
#     risk_level, risk_score = calculate_risk_score(hits)
    
#     summary = []
#     summary.append(f"=== iOS ANTISPYWARE SCAN SUMMARY ===")
#     summary.append(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
#     summary.append(f"Risk Level: {risk_level} (Score: {risk_score})")
#     summary.append(f"Total alerts detected: {len(hits)}")
#     summary.append("")
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
#     parser = argparse.ArgumentParser(
#         description="iOS AntiSpyware Detection Tool v2.0 - Advanced Sysdiagnose Scanner",
#         formatter_class=argparse.RawDescriptionHelpFormatter,
#         epilog="""
# Examples:
#   python scan_indicators.py --dir /path/to/sysdiagnose --indicators indicators/
#   python scan_indicators.py --dir logs/ --indicators indicators/ --export-json results.json --threads 4
#   python scan_indicators.py --dir data/ --indicators indicators/ --config config.yaml --quiet
#         """
#     )
    
#     parser.add_argument("--dir", required=True, help="Extracted logs root directory")
#     parser.add_argument("--indicators", required=True, help="Indicator JSON directory")
#     parser.add_argument("--report", help="Path to save detailed text report")
#     parser.add_argument("--summary", help="Path to save summary report")
#     parser.add_argument("--export-json", help="Export results as JSON")
#     parser.add_argument("--export-csv", help="Export results as CSV")
#     parser.add_argument("--export-html", help="Export results as HTML")
#     parser.add_argument("--config", help="Path to configuration YAML file")
#     parser.add_argument("--threads", type=int, default=8, help="Number of worker threads (default=8)")
#     parser.add_argument("--quiet", "-q", action="store_true", help="Suppress console output")
#     parser.add_argument("--version", action="version", version="iOS AntiSpyware v2.0")
    
#     args = parser.parse_args()

#     # Load configuration
#     config = load_config(args.config)
    
#     # Override threads from config if not specified
#     if args.threads == 8 and 'scanning' in config:
#         args.threads = config['scanning'].get('max_threads', 8)

#     if not args.quiet:
#         print("=== iOS AntiSpyware Detection Tool v2.0 ===")
#         print(f"Scanning directory: {args.dir}")
#         print(f"Using {args.threads} threads")
#         print()

#     start_time = time.time()
    
#     indicators = load_indicators(args.indicators)
#     results = scan_directory_threaded(args.dir, indicators, max_workers=args.threads)
    
#     scan_time = time.time() - start_time
    
#     if not args.quiet:
#         print(f"\nScan completed in {scan_time:.2f} seconds")
    
#     # Print results to console
#     print_results(results, args.quiet)
    
#     # Save reports
#     if args.report:
#         save_report(results, args.report)
    
#     if args.summary:
#         summary_report = generate_simple_summary(results)
#         with open(args.summary, 'w', encoding='utf-8') as f:
#             f.write(summary_report)
#         if not args.quiet:
#             print(f"Summary report saved to {args.summary}")
    
#     # Export in different formats
#     if args.export_json:
#         export_json(results, args.export_json)
    
#     if args.export_csv:
#         export_csv(results, args.export_csv)
    
#     if args.export_html:
#         export_html(results, args.export_html)
    
#     # Print final stats
#     if not args.quiet:
#         risk_level, risk_score = calculate_risk_score(results)
#         print(f"\n🎯 Final Assessment: {risk_level} ({len(results)} findings, Risk Score: {risk_score})")

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

# # This script is designed to scan system logs and indicators for potential security issues.
# # It loads JSON-based indicators, scans files for patterns, and detects advanced threats like app masquerading, stealthy launch agents, and multi-stage downloads.
# # The results can be printed to the console or saved to a report file, with an optional summary report generation.
# # The script is intended for use in security analysis and incident response, particularly in iOS environments.
# # It is modular and can be extended with additional detection logic as needed.
# # This code is designed to scan system logs and indicators for potential security issues.
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
import math
import requests
from fpdf import FPDF

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
    filename = os.path.basename(filepath).lower()
    system_files = [
        'ioacpiplane', 'iodevicetree', 'iofirewire', 'ioport', 'iopower', 
        'ioservice', 'ioregistry', 'iokit', 'iousb', 'iopci', 'iohid',
        'hardware', 'device', 'system_profiler'
    ]
    system_settings = [
        'usersettings', 'effectiveusersettings', 'publiceffectiveusersettings',
        'systemconfiguration', 'preferences', 'defaults'
    ]

    if any(sys_file in filename for sys_file in system_files):
        return [] 
    if any(setting_file in filename for setting_file in system_settings):
        return []
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
                        'timestamp': datetime.now().isoformat(),
                        'match_type': indicator.get('match_type', 'pattern_match'),
                        'enrichments': indicator.get('enrichments', []),
                        'remediation': indicator.get('remediation', 'Review and investigate finding'),
                        'confidence': indicator.get('confidence', 'Medium')
                    })
    return results

# ----------------------------------------
# Advanced "Crazy" Python Indicator Logic
# ----------------------------------------

def detect_app_masquerade(ps_lines):
    findings = []
    
    for line in ps_lines:
        # Look for actual doubled .app extensions
        if re.search(r"\b\w+\.app\.app\b", line):
            findings.append(line.strip())
            continue  # Avoid duplicate entries
        
        # Look for suspicious Unicode characters ONLY in app names
        app_match = re.search(r'/Applications/([^/]+\.app)', line)
        if app_match:
            app_name = app_match.group(1)
            # Check for suspicious Unicode ONLY in app names
            if re.search(r"[\u200B-\u200D\uFEFF]", app_name):
                findings.append(line.strip())
                continue
        
        # Look for typosquatting of Apple apps ONLY
        suspicious_names = [
            r"\bsafarii?\d*\.app\b",   # Safari variations
            r"\bmessag[ez]\w*\.app\b", # Messages variations (messagz, messagez, etc.)
            r"\bphoto\w*\d+\.app\b",   # Photos with numbers (photo1, photo2, etc.)
            r"\bfacetim[ez]\w*\.app\b" # FaceTime variations
        ]
        
        for pattern in suspicious_names:
            if re.search(pattern, line, re.IGNORECASE):
                # Exclude legitimate Apple apps and known false positives
                if not re.search(r"com\.apple\.", line):
                    # Additional filtering for known legitimate apps
                    legit_variations = ['facetime.app', 'messages.app', 'photos.app']
                    if not any(legit in line.lower() for legit in legit_variations):
                        findings.append(line.strip())
                break
    
    # Remove duplicates and return
    return list(set(findings))



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
            events[i+1] == "chmod" and
            events[i+2] == "exec" and
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
    skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.mp4', '.mov', '.zip', '.gz', '.dmg'}
    for root, dirs, files in os.walk(root_dir):
        for file in files:

            ext = Path(file).suffix.lower()
            fp = os.path.join(root, file)
            if ext in skip_extensions:
                continue
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
    print(f"✅ Loaded {len(indicators)} indicators successfully")
    print(f"🔍 Found {len(files_to_scan)} files to scan")
    print("🚀 Beginning threaded scan...")
    # Multi-threaded scan_file for all matched files
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_file, fp, indicators) for fp in files_to_scan]
        completed = 0
        for future in tqdm(concurrent.futures.as_completed(futures), 
                   total=len(futures), desc="Scanning files"):
           completed += 1
           
           all_results.extend(future.result())

    # Add advanced indicators results (FIXED VERSION)
    masquerade_findings = detect_app_masquerade(ps_lines)
    for line in masquerade_findings:
    # Only add if it's actually suspicious (additional filtering)
        if not any(legit in line.lower() for legit in ['time.app', 'filter.app', 'system', 'apple']):
         all_results.append({
            'filepath': 'ps.txt',
            'line_num': None,
            'indicator': "App_Masquerading",
            'description': "Suspicious app masquerading detected after filtering.",
            'pattern': 'Advanced logic',
            'matched_text': line,
            'severity': 'Medium',  # Reduced from High
            'context': line.strip(),
            'app_or_process': extract_app_or_process(line),
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
            'timestamp': datetime.now().isoformat(),
            'match_type': 'behavioral_analysis',
            'enrichments': ['process_signature_verification', 'path_analysis'],
            'remediation': 'Investigate app legitimacy, check app store source, verify developer signature',
            'confidence': 'Medium'  # Reduced from High
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
            'timestamp': datetime.now().isoformat(),
            'match_type': 'persistence_analysis',
            'enrichments': ['plist_analysis', 'launch_agent_verification'],
            'remediation': 'Remove malicious LaunchAgent, check for additional persistence mechanisms, audit system startup items',
            'confidence': 'High'
        })
    
    # Continue with other advanced indicators...
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
            'timestamp': datetime.now().isoformat(),
            'match_type': 'process_tree_analysis',
            'enrichments': ['parent_process_verification', 'binary_integrity_check'],
            'remediation': 'Investigate parent process, verify system binary integrity, check for process injection',
            'confidence': 'Medium'
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
            'timestamp': datetime.now().isoformat(),
            'match_type': 'configuration_analysis',
            'enrichments': ['profile_signature_verification', 'vpn_provider_lookup'],
            'remediation': 'Remove suspicious VPN profile, audit network configurations, check for unauthorized remote management',
            'confidence': 'Medium'
        })
    
    for match in detect_multistage_download_exec(all_log_lines):
        all_results.append({
            'filepath': 'log_correlation',
            'line_num': None,
            'indicator': 'MultiStage_Download_Exec',
            'description': 'Download, chmod, exec chain detected (likely malware installation).',
            'pattern': 'Advanced logic',
            'matched_text': f"{match['download']} || {match['chmod']} || {match['exec']}",
            'severity': 'Critical',
            'context': f"{match['download'].strip()} → {match['chmod'].strip()} → {match['exec'].strip()}",
            'app_or_process': extract_app_or_process(match['download']),
            'attribution': {'source': 'Advanced Logic', 'author': 'Toolkit', 'date_created': '2024-07-01'},
            'timestamp': datetime.now().isoformat(),
            'match_type': 'behavioral_correlation',
            'enrichments': ['file_hash_analysis', 'download_source_verification', 'execution_context_analysis'],
            'remediation': 'CRITICAL: Isolate device, identify and remove downloaded files, change all passwords, conduct full system scan',
            'confidence': 'High'
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
            'low_risk_score': 5,
            'moderate_risk_score': 15,
            'high_risk_score': 30,
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
            # Enhanced fieldnames with new fields
            fieldnames = ['filepath', 'line_num', 'indicator', 'description', 'pattern', 
                         'matched_text', 'severity', 'context', 'app_or_process', 'timestamp',
                         'match_type', 'confidence', 'remediation',
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
                # Handle enrichments as comma-separated string
                flat_result['enrichments'] = ', '.join(flat_result.get('enrichments', []))
                writer.writerow(flat_result)
        print(f"CSV report exported to {filepath}")
    except Exception as e:
        print(f"Error exporting CSV: {e}")

def export_html(results, filepath):
    """Export results to HTML format with enhanced styling"""
    try:
        risk_level, risk_score = calculate_risk_score(results)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>iOS AntiSpyware Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 20px; margin-bottom: 20px; border-radius: 10px; }}
        .risk-summary {{ background-color: white; padding: 15px; margin-bottom: 20px; 
                        border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .result {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; 
                  background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
        .critical {{ border-left: 5px solid #dc3545; background-color: #fff5f5; }}
        .high {{ border-left: 5px solid #fd7e14; background-color: #fff8f0; }}
        .medium {{ border-left: 5px solid #ffc107; background-color: #fffdf0; }}
        .low {{ border-left: 5px solid #28a745; background-color: #f0fff4; }}
        .indicator {{ font-weight: bold; color: #333; font-size: 1.1em; margin-bottom: 10px; }}
        .context {{ background-color: #f8f9fa; padding: 10px; margin: 10px 0; 
                   font-family: 'Consolas', monospace; border-radius: 4px; }}
        .metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                    gap: 10px; margin: 10px 0; }}
        .metadata-item {{ background-color: #f8f9fa; padding: 8px; border-radius: 4px; }}
        .remediation {{ background-color: #e7f3ff; padding: 10px; border-left: 4px solid #0066cc; 
                       margin: 10px 0; border-radius: 0 4px 4px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ iOS AntiSpyware Scan Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total findings: {len(results)} | Risk Level: <strong>{risk_level}</strong> (Score: {risk_score:.2f})</p>
    </div>
    
    <div class="risk-summary">
        <h2>📊 Risk Assessment Summary</h2>
        {generate_risk_assessment(results).replace(chr(10), '<br>')}
    </div>
"""
        
        for result in results:
            severity_class = result['severity'].lower()
            enrichments = ', '.join(result.get('enrichments', []))
            
            html_content += f"""
    <div class="result {severity_class}">
        <div class="indicator">🚨 [{result['severity']}] {result['indicator']}</div>
        
        <div class="metadata">
            <div class="metadata-item"><strong>File:</strong> {Path(result['filepath']).name}</div>
            <div class="metadata-item"><strong>Line:</strong> {result.get('line_num', 'N/A')}</div>
            <div class="metadata-item"><strong>Match Type:</strong> {result.get('match_type', 'N/A')}</div>
            <div class="metadata-item"><strong>Confidence:</strong> {result.get('confidence', 'N/A')}</div>
            <div class="metadata-item"><strong>App/Process:</strong> {result.get('app_or_process', 'Unknown')}</div>
            <div class="metadata-item"><strong>Timestamp:</strong> {result.get('timestamp', 'N/A')}</div>
        </div>
        
        <p><strong>📝 Description:</strong> {result['description']}</p>
        <p><strong>🎯 Matched:</strong> <code>{result['matched_text']}</code></p>
        
        <div class="context">
            <strong>📋 Context:</strong><br>
            {result['context']}
        </div>
        
        {f'<p><strong>🔍 Enrichments:</strong> {enrichments}</p>' if enrichments else ''}
        
        <div class="remediation">
            <strong>⚡ Remediation Steps:</strong><br>
            {result.get('remediation', 'Review and investigate finding')}
        </div>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Enhanced HTML report exported to {filepath}")
    except Exception as e:
        print(f"Error exporting HTML: {e}")

# -------------------------
# Advanced Risk Assessment with Multiple Factors
# -------------------------
def calculate_risk_score(results):
    """Advanced risk scoring algorithm considering multiple factors"""
    if not results:
        return "NO RISK", 0.0
    
    # Base severity weights
    severity_weights = {
        "Critical": 15.0,
        "High": 6.0,
        "Medium": 2.0,
        "Low": 0.5,
        "Unknown": 0.1
    }
    
    # Confidence multipliers
    confidence_multipliers = {
        "High": 1.0,
        "Medium": 0.8,
        "Low": 0.6,
        "Unknown": 0.5
    }
    
    # Special indicator type weights (higher risk indicators)
    critical_indicators = {
        "Zero_Click_Exploit_Detection": 50.0,
        "Commercial_Spyware_Signatures": 40.0,
        "Nation_State_APT_Indicators": 45.0,
        "MultiStage_Download_Exec": 35.0,
        "Privileged_Access_Abuse": 30.0,
        "Advanced_Data_Exfiltration": 25.0
    }
    
    total_score = 0.0
    indicator_diversity = set()
    file_scope = set()
    temporal_clustering = {}
    
    for hit in results:
        # Base score calculation
        base_score = severity_weights.get(hit['severity'], 1.0)
        confidence_mult = confidence_multipliers.get(hit.get('confidence', 'Medium'), 0.8)
        
        # Special indicator bonus
        indicator_name = hit['indicator']
        if indicator_name in critical_indicators:
            base_score = max(base_score, critical_indicators[indicator_name])
        
        # Apply confidence multiplier
        weighted_score = base_score * confidence_mult
        
        # Diversity bonus (more diverse indicators = higher risk)
        indicator_diversity.add(indicator_name)
        
        # File scope tracking
        file_scope.add(hit['filepath'])
        
        # Temporal clustering (multiple indicators in short time)
        timestamp = hit.get('timestamp', '')
        if timestamp:
            hour_key = timestamp[:13]  # Group by hour
            temporal_clustering[hour_key] = temporal_clustering.get(hour_key, 0) + 1
        
        total_score += weighted_score
    
    # Apply multipliers based on attack sophistication
    diversity_multiplier = 1.0 + (len(indicator_diversity) * 0.1)  # 10% bonus per unique indicator type
    scope_multiplier = 1.0 + (len(file_scope) * 0.05)  # 5% bonus per affected file
    
    # Temporal clustering bonus (multiple indicators in same time window)
    max_temporal_cluster = max(temporal_clustering.values()) if temporal_clustering else 1
    temporal_multiplier = 1.0 + (max_temporal_cluster - 1) * 0.15  # 15% bonus per additional indicator in same hour
    
    # Final score calculation
    final_score = total_score * diversity_multiplier * scope_multiplier * temporal_multiplier
    
    # Apply logarithmic scaling to prevent extreme scores
    if final_score > 100:
        final_score = 100 + math.log10(final_score - 100 + 1) * 20
    
    # Determine risk level with more nuanced thresholds
    if final_score >= 80:
        return "CRITICAL RISK", final_score
    elif final_score >= 50:
        return "HIGH RISK", final_score
    elif final_score >= 25:
        return "MODERATE RISK", final_score
    elif final_score >= 10:
        return "ELEVATED RISK", final_score
    elif final_score >= 5:
        return "LOW RISK", final_score
    else:
        return "MINIMAL RISK", final_score

def generate_comprehensive_remediation_plan(results):
    """Generate comprehensive remediation plan based on findings"""
    if not results:
        return "No remediation required - no threats detected."
    
    risk_level, risk_score = calculate_risk_score(results)
    severity_counts = Counter(hit['severity'] for hit in results)
    indicator_types = Counter(hit['indicator'] for hit in results)
    
    remediation_plan = []
    remediation_plan.append("🛡️ COMPREHENSIVE REMEDIATION PLAN")
    remediation_plan.append("=" * 50)
    remediation_plan.append(f"Risk Level: {risk_level} (Score: {risk_score:.2f})")
    remediation_plan.append("")
    
    # Immediate actions based on risk level
    if risk_score >= 80:
        remediation_plan.extend([
            "🚨 IMMEDIATE EMERGENCY ACTIONS:",
            "1. DISCONNECT device from all networks immediately",
            "2. DO NOT enter any passwords or sensitive information",
            "3. Contact cybersecurity team/law enforcement if targeted attack suspected",
            "4. Preserve device for forensic analysis",
            "5. Notify all contacts about potential compromise",
            "6. Change ALL passwords from a different, clean device",
            "7. Enable 2FA on all critical accounts",
            "8. Consider complete device replacement",
            ""
        ])
    elif risk_score >= 50:
        remediation_plan.extend([
            "⚠️ HIGH PRIORITY ACTIONS (Next 24 hours):",
            "1. Isolate device from corporate/sensitive networks",
            "2. Run comprehensive antivirus/anti-malware scan",
            "3. Change passwords for critical accounts",
            "4. Review and revoke suspicious app permissions",
            "5. Check for unauthorized profiles/certificates",
            "6. Monitor accounts for suspicious activity",
            "7. Consider professional security consultation",
            ""
        ])
    elif risk_score >= 25:
        remediation_plan.extend([
            "📋 MODERATE PRIORITY ACTIONS (Next week):",
            "1. Update iOS to latest version",
            "2. Review and audit installed applications",
            "3. Check privacy settings and permissions",
            "4. Remove suspicious profiles/configurations",
            "5. Enable Screen Time restrictions if needed",
            "6. Monitor data usage patterns",
            ""
        ])
    else:
        remediation_plan.extend([
            "✅ STANDARD SECURITY MEASURES:",
            "1. Keep iOS updated to latest version",
            "2. Regular security awareness training",
            "3. Periodic security audits",
            "4. Monitor for new threat indicators",
            ""
        ])
    
    # Specific remediation based on indicator types
    critical_indicators_found = []
    for indicator, count in indicator_types.most_common():
        if any(critical in indicator for critical in ['Zero_Click', 'Commercial_Spyware', 'Nation_State', 'Pegasus']):
            critical_indicators_found.append(f"  - {indicator}: {count} occurrences")
    
    if critical_indicators_found:
        remediation_plan.extend([
            "🎯 SPECIFIC THREAT REMEDIATION:",
            *critical_indicators_found,
            ""
        ])
    
    # Recovery and prevention
    remediation_plan.extend([
        "🔄 RECOVERY STEPS:",
        "1. Backup important data (after security verification)",
        "2. Factory reset device if compromise confirmed",
        "3. Restore from clean, pre-compromise backup",
        "4. Reinstall applications from trusted sources only",
        "5. Reconfigure security settings",
        "",
        "🛡️ PREVENTION MEASURES:",
        "1. Enable automatic iOS updates",
        "2. Only install apps from App Store",
        "3. Avoid clicking suspicious links/attachments",
        "4. Regular security awareness training",
        "5. Use enterprise MDM if in corporate environment",
        "6. Regular security audits and monitoring",
        "",
        "📞 GET HELP:",
        "- Apple Support: https://support.apple.com/",
        "- Local law enforcement (if criminal activity suspected)",
        "- Cybersecurity professionals for advanced threats",
        "- IT security team (if corporate device)"
    ])
    
    return "\n".join(remediation_plan)

def generate_risk_assessment(results):
    """Generate detailed risk assessment with enhanced analysis"""
    risk_level, risk_score = calculate_risk_score(results)
    
    severity_counts = Counter(hit['severity'] for hit in results)
    indicator_counts = Counter(hit['indicator'] for hit in results)
    confidence_counts = Counter(hit.get('confidence', 'Unknown') for hit in results)
    
    assessment = []
    assessment.append("=== ADVANCED RISK ASSESSMENT ===")
    assessment.append(f"Overall Risk Level: {risk_level} (Score: {risk_score:.2f})")
    assessment.append(f"Total Findings: {len(results)}")
    assessment.append(f"Unique Indicators: {len(set(hit['indicator'] for hit in results))}")
    assessment.append(f"Affected Files: {len(set(hit['filepath'] for hit in results))}")
    assessment.append("")
    
    assessment.append("Severity Distribution:")
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(severity, 0)
        percentage = (count / len(results) * 100) if results else 0
        assessment.append(f"  {severity}: {count} ({percentage:.1f}%)")
    assessment.append("")
    
    assessment.append("Confidence Levels:")
    for confidence in ["High", "Medium", "Low"]:
        count = confidence_counts.get(confidence, 0)
        percentage = (count / len(results) * 100) if results else 0
        assessment.append(f"  {confidence}: {count} ({percentage:.1f}%)")
    assessment.append("")
    
    assessment.append("Top Threat Indicators:")
    for indicator, count in indicator_counts.most_common(10):
        assessment.append(f"  {indicator}: {count} occurrences")
    
    assessment.append("")
    assessment.append(generate_comprehensive_remediation_plan(results))
    
    return "\n".join(assessment)

# -------------------------
# Enhanced Reporting / Summarization
# -------------------------
def print_results(results, quiet=False):
    if quiet:
        return
    
    if not results:
        print("✅ No indicators triggered - Device appears clean.")
        return
    
    # Print risk assessment first
    print("\n" + generate_risk_assessment(results))
    
    print("\n=== DETAILED INDICATOR MATCHES ===")
    for hit in results:
        attr = hit.get('attribution', {})
        print(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit.get('line_num') if hit.get('line_num') else '-'})")
        print(f"    > Matched: {hit['matched_text']}")
        print(f"    > App/Process: {hit.get('app_or_process', 'Unknown')}")
        print(f"    > Context: {hit['context']}")
        print(f"    > Match Type: {hit.get('match_type', 'N/A')} | Confidence: {hit.get('confidence', 'N/A')}")
        if hit.get('enrichments'):
            print(f"    > Enrichments: {', '.join(hit['enrichments'])}")
        if attr:
            print(f"    > Source: {attr.get('source','')}, Author: {attr.get('author','')}, Date: {attr.get('date_created','')}")
        print(f"    > Remediation: {hit.get('remediation', 'Review finding')}")
        print()

def save_report(results, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        # Write enhanced risk assessment
        f.write(generate_risk_assessment(results) + "\n\n")
        
        # Write detailed results
        f.write("=== DETAILED FINDINGS ===\n\n")
        for hit in results:
            f.write(f"[{hit['severity']}] {hit['indicator']} in {Path(hit['filepath']).name} (line {hit.get('line_num') if hit.get('line_num') else '-'}):\n")
            f.write(f"    > Matched: {hit['matched_text']}\n")
            f.write(f"    > App/Process: {hit.get('app_or_process', 'Unknown')}\n")
            f.write(f"    > Context: {hit['context']}\n")
            f.write(f"    > Match Type: {hit.get('match_type', 'N/A')} | Confidence: {hit.get('confidence', 'N/A')}\n")
            if hit.get('enrichments'):
                f.write(f"    > Enrichments: {', '.join(hit['enrichments'])}\n")
            attr = hit.get('attribution', {})
            if attr:
                f.write(f"    > Source: {attr.get('source', '')}, Author: {attr.get('author', '')}, Date: {attr.get('date_created', '')}\n")
            f.write(f"    > Remediation: {hit.get('remediation', 'Review finding')}\n")
            f.write("-----\n")
    print(f"Enhanced report saved to {output_path}")

def generate_simple_summary(hits):
    if not hits:
        return "✅ No indicators triggered in the scan - Device appears clean."

    indicator_counts = Counter(hit['indicator'] for hit in hits)
    severity_counts = Counter(hit['severity'] for hit in hits)
    file_counts = Counter(Path(hit['filepath']).name for hit in hits)
    app_counts = Counter(hit.get('app_or_process', 'Unknown') for hit in hits)
    
    risk_level, risk_score = calculate_risk_score(hits)
    
    summary = []
    summary.append(f"=== iOS ANTISPYWARE SCAN SUMMARY ===")
    summary.append(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary.append(f"Risk Level: {risk_level} (Score: {risk_score:.2f})")
    summary.append(f"Total alerts detected: {len(hits)}")
    summary.append(f"Unique indicators: {len(set(hit['indicator'] for hit in hits))}")
    summary.append(f"Files affected: {len(set(hit['filepath'] for hit in hits))}")
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
    
    # Add quick remediation summary
    summary.append(f"\n🛡️ QUICK ACTION REQUIRED:")
    if risk_score >= 80:
        summary.append("CRITICAL: Disconnect device, contact security team immediately")
    elif risk_score >= 50:
        summary.append("HIGH: Isolate device, run full security scan, change passwords")
    elif risk_score >= 25:
        summary.append("MODERATE: Update iOS, audit apps, review security settings")
    else:
        summary.append("LOW: Monitor and maintain standard security practices")
    
    summary_text = "\n".join(summary)
    return summary_text


# =====================================
# AI ENRICHMENT & PDF REPORTING
# =====================================

class AIEnhancer:
    def __init__(self, gemini_key=None, deepseek_key=None):
        self.gemini_key = gemini_key
        self.deepseek_key = deepseek_key
        print(f"🔑 API Keys loaded - Gemini: {'✅' if gemini_key else '❌'} | DeepSeek: {'✅' if deepseek_key else '❌'}")
    
    def supervise_and_enhance(self, findings):
        """AI supervises and enhances all findings"""
        if not findings:
            print("⚠️ No findings to enhance")
            return findings
        
        print(f"🤖 AI analyzing {len(findings)} findings...")
        enhanced_findings = []
        successful_enhancements = 0
        
        for i, finding in enumerate(findings, 1):
            print(f"   📍 Processing finding {i}/{len(findings)}: {finding['indicator']}")
            
            # Try AI enhancement
            ai_analysis = self._get_ai_analysis(finding)
            if ai_analysis:
                finding['ai_analysis'] = ai_analysis['analysis']
                finding['ai_confidence'] = ai_analysis['confidence']
                finding['ai_threat_level'] = ai_analysis['threat_level']
                finding['ai_attribution'] = ai_analysis.get('attribution', 'AI Analysis')
                finding['enhanced'] = True
                successful_enhancements += 1
                print(f"   ✅ Enhanced successfully")
            else:
                finding['enhanced'] = False
                print(f"   ❌ Enhancement failed")
            
            enhanced_findings.append(finding)
            
            # Rate limiting to be nice to APIs
            if i < len(findings):  # Don't sleep after last item
                time.sleep(2)
        
        print(f"🎯 AI Enhancement Results: {successful_enhancements}/{len(findings)} findings enhanced")
        return enhanced_findings
    
    def _get_ai_analysis(self, finding):
        """Get AI analysis for a single finding"""
        
        # Check if we have any API keys
        if not self.gemini_key and not self.deepseek_key:
            print("   ⚠️ No API keys provided - skipping AI analysis")
            return None
        
        # Try Gemini first
        if self.gemini_key:
            try:
                result = self._query_gemini(finding)
                if result:
                    print(f"   🟢 Gemini analysis successful")
                    return result
            except Exception as e:
                print(f"   🔴 Gemini error: {str(e)[:100]}...")
        
        # Fallback to DeepSeek
        if self.deepseek_key:
            try:
                result = self._query_deepseek(finding)
                if result:
                    print(f"   🟢 DeepSeek analysis successful")
                    return result
            except Exception as e:
                print(f"   🔴 DeepSeek error: {str(e)[:100]}...")
        
        return None
    
    def _query_gemini(self, finding):
        """Query Google Gemini API with robust error handling"""
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
        
        # Create focused prompt based on your findings format
        prompt = f"""
Analyze this iOS security finding:

INDICATOR: {finding['indicator']}
SEVERITY: {finding['severity']}
EVIDENCE: {finding['matched_text']}
CONTEXT: {finding['context']}
FILE: {finding.get('filepath', 'Unknown')}

Provide a brief security analysis covering:
1. What this threat indicates
2. Potential threat actor or attack type
3. Recommended immediate action

Keep your response under 150 words, but make sure it is a COMPLETE answer
with all three requested sections. Do not stop mid-sentence.
        """
        
        headers = {
            "Content-Type": "application/json",
            
        }
        
        # FIXED: Use exact payload format from your curl
        payload = {
                "contents": [
                 {
                     "parts": [
                         {"text": prompt}
            ]
        }
    ],
    "generationConfig": {
        "maxOutputTokens": 512,    # default is ~256, increase for longer answers
        "temperature": 0.2,        # lower = more focused/deterministic
        "topP": 0.9,               # nucleus sampling
        "topK": 40                 # limits candidate pool
    }
}


        
        try:
            print(f"   📡 Calling Gemini API...")
            response = requests.post(
                f"{url}?key={self.gemini_key}",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            print(f"   📊 Status: {response.status_code}")
            
            if response.status_code != 200:
                print(f"   ❌ API Error: {response.text[:200]}")
                return None
            
            # Parse response safely
            try:
                result = response.json()
                
                # Debug: Show response structure
                print(f"   🔍 Response keys: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}")
                
                # Handle Gemini response format
                if isinstance(result, dict) and 'candidates' in result:
                    candidates = result['candidates']
                    if candidates:
                        candidate = candidates[0]
                        if 'content' in candidate:
                            content = candidate.get('content', {})
                            parts = content.get("parts", [])

                            if parts and 'text' in parts[0]:
                                analysis_text = parts[0]['text']
                                return {
                                        "source": "Gemini",
                                        "analysis": analysis_text,
                                        "confidence": 85,
                                        "threat_level": "AI-Analyzed",
                                        "attribution": "Gemini AI Analysis"
                                    }
                
                print(f"   ❌ Unexpected response format: {str(result)[:200]}...")
                return None
                
            except json.JSONDecodeError as e:
                print(f"   ❌ JSON decode error: {e}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Request error: {e}")
            return None
    
    def _query_deepseek(self, finding):
        """Query DeepSeek API via OpenRouter with robust error handling"""
        url = "https://openrouter.ai/api/v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.deepseek_key}",
            "Content-Type": "application/json"
        }
        
        # Create focused prompt
        prompt = f"""
Analyze this iOS security finding:

Type: {finding['indicator']}
Evidence: {finding['matched_text']}
Severity: {finding['severity']}

Provide brief analysis of:
1. Threat classification
2. Attack method
3. Recommended action
4. Comment if such a finding is logical in user's case

Be specific and actionable in 100 words or less.
        """
        
        payload = {
            "model": "deepseek/deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000
        }
        
        try:
            print(f"   📡 Calling DeepSeek API...")
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            
            print(f"   📊 Status: {response.status_code}")
            
            if response.status_code != 200:
                print(f"   ❌ API Error: {response.text[:200]}")
                return None
            
            # Check for empty response
            if not response.text or response.text.strip() == "":
                print(f"   ❌ Empty response from DeepSeek")
                return None
            
            # Parse response safely
            try:
                result = response.json()
                
                print(f"   🔍 Response keys: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}")
                
                # Handle DeepSeek/OpenRouter response format
                if isinstance(result, dict) and 'choices' in result:
                    choices = result['choices']
                    if len(choices) > 0:
                        choice = choices[0]
                        if 'message' in choice and 'content' in choice['message']:
                            analysis_text = choice['message']['content']
                            return {
                                "source": "DeepSeek",
                                "analysis": analysis_text,
                                "confidence": 80,
                                "threat_level": "AI-Analyzed",
                                "attribution": "DeepSeek AI Analysis"
                            }
                
                print(f"   ❌ Unexpected response format: {str(result)[:200]}...")
                return None
                
            except json.JSONDecodeError as e:
                print(f"   ❌ JSON decode error: {e}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Request error: {e}")
            return None

class ProfessionalPDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
    
    def header(self):
        self.set_font('Arial', 'B', 20)
        self.set_text_color(30, 60, 140)
        self.cell(0, 15, 'DeepCytes iOS AntiSpyware Security Report', 0, 1, 'C')
        
        self.set_font('Arial', '', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
    
    def add_executive_summary(self, findings):
        self.set_font('Arial', 'B', 16)
        self.set_text_color(200, 50, 50)
        self.cell(0, 10, 'EXECUTIVE SUMMARY', 0, 1, 'L')
        self.ln(5)
        
        # Calculate metrics
        critical_count = len([f for f in findings if f.get('severity') == 'Critical'])
        high_count = len([f for f in findings if f.get('severity') == 'High'])
        ai_enhanced = len([f for f in findings if f.get('enhanced')])
        
        # Determine risk level
        if critical_count > 0:
            risk_level = "CRITICAL RISK"
            risk_color = (200, 50, 50)
        elif high_count > 0:
            risk_level = "HIGH RISK"
            risk_color = (200, 100, 50)
        elif len(findings) > 0:
            risk_level = "MODERATE RISK"
            risk_color = (200, 150, 50)
        else:
            risk_level = "LOW RISK"
            risk_color = (50, 150, 50)
        
        self.set_font('Arial', 'B', 14)
        self.set_text_color(*risk_color)
        self.cell(0, 10, f'Risk Assessment: {risk_level}', 0, 1, 'L')
        
        self.set_font('Arial', '', 11)
        self.set_text_color(0, 0, 0)
        
        summary_text = f"""
Total Threats Detected: {len(findings)}
Critical Severity: {critical_count}
High Severity: {high_count}
AI-Enhanced Analysis: {ai_enhanced} findings
Files Affected: {len(set(f.get('filepath', '') for f in findings))}
        """
        
        self.multi_cell(0, 6, summary_text.strip())
        self.ln(10)
    
    def add_detailed_findings(self, findings):
        self.set_font('Arial', 'B', 16)
        self.set_text_color(30, 60, 140)
        self.cell(0, 10, 'DETAILED SECURITY FINDINGS', 0, 1, 'L')
        self.ln(5)
        
        for i, finding in enumerate(findings[:15], 1):  # Limit to first 15 for PDF space
            # Finding header
            self.set_font('Arial', 'B', 12)
            self.set_text_color(200, 50, 50)
            self.cell(0, 8, f'Finding #{i}: {finding["indicator"]}', 0, 1, 'L')
            
            # Basic details
            self.set_font('Arial', '', 10)
            self.set_text_color(0, 0, 0)
            
            details = f"""
File: {finding.get('filepath', 'Unknown').split('/')[-1]}
Severity: {finding.get('severity', 'Unknown')}
Evidence: {finding.get('matched_text', 'N/A')}
Context: {finding.get('context', 'N/A')[:100]}...
            """
            
            self.multi_cell(0, 5, details.strip())
            
            # AI Analysis if available
            if finding.get('enhanced') and finding.get('ai_analysis'):
                self.ln(3)
                self.set_font('Arial', 'B', 10)
                self.set_text_color(0, 100, 0)
                self.cell(0, 6, f'AI THREAT ANALYSIS ({finding.get("ai_attribution", "AI")}):', 0, 1, 'L')
                
                self.set_font('Arial', '', 9)
                self.set_text_color(50, 50, 50)
                ai_text = finding['ai_analysis'][:400] + "..." if len(finding['ai_analysis']) > 400 else finding['ai_analysis']
                self.multi_cell(0, 4, ai_text)
            
            # Remediation
            self.ln(3)
            self.set_font('Arial', 'B', 10)
            self.set_text_color(150, 50, 50)
            self.cell(0, 6, 'RECOMMENDED ACTION:', 0, 1, 'L')
            
            self.set_font('Arial', '', 9)
            self.set_text_color(0, 0, 0)
            remediation = finding.get('remediation', 'Review and investigate this finding')[:200]
            self.multi_cell(0, 4, remediation)
            
            self.ln(8)

def generate_enhanced_pdf_report(findings, filename):
    """Generate professional PDF report with AI analysis"""
    print(f"📄 Generating enhanced PDF report...")
    
    try:
        pdf = ProfessionalPDFReport()
        pdf.add_page()
        
        pdf.add_executive_summary(findings)
        pdf.add_detailed_findings(findings)
        
        pdf.output(filename)
        print(f"✅ Enhanced PDF report saved: {filename}")
        
    except Exception as e:
        print(f"❌ PDF generation error: {e}")

# -------------
# ENHANCED MAIN
# -------------

def main():
    parser = argparse.ArgumentParser(
        description="iOS AntiSpyware Detection Tool v2.1 - Enhanced with AI Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan_indicators.py --dir /path/to/sysdiagnose --indicators indicators/
  python scan_indicators.py --dir logs/ --indicators indicators/ --gemini-key YOUR_KEY --pdf-report report.pdf
  python scan_indicators.py --dir data/ --indicators indicators/ --deepseek-key YOUR_KEY --export-html report.html
        """
    )
    
    # Existing arguments
    parser.add_argument("--dir", required=True, help="Extracted logs root directory")
    parser.add_argument("--indicators", required=True, help="Indicator JSON directory")
    parser.add_argument("--report", help="Path to save detailed text report")
    parser.add_argument("--summary", help="Path to save summary report")
    parser.add_argument("--export-json", help="Export results as JSON")
    parser.add_argument("--export-csv", help="Export results as CSV")
    parser.add_argument("--export-html", help="Export results as HTML")
    parser.add_argument("--config", help="Path to configuration YAML file")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress console output")
    
    # NEW: AI Enhancement arguments
    parser.add_argument("--gemini-key", help="Google Gemini API key for AI analysis")
    parser.add_argument("--deepseek-key", help="DeepSeek API key for AI analysis (via OpenRouter)")
    parser.add_argument("--pdf-report", help="Path to save enhanced PDF report with AI analysis")
    parser.add_argument("--skip-ai", action="store_true", help="Skip AI analysis and generate basic PDF only")
    
    args = parser.parse_args()

    # Load configuration (your existing code)
    config = load_config(args.config)
    
    if not args.quiet:
        print("🛡️ === iOS AntiSpyware Detection Tool v2.1 ===")
        print("Enhanced with AI-Powered Threat Intelligence")
        print(f"Scanning directory: {args.dir}")
        print(f"Using {args.threads} threads")
        if args.gemini_key or args.deepseek_key:
            print("🤖 AI Enhancement: ENABLED")
        else:
            print("⚪ AI Enhancement: DISABLED (no API keys provided)")
        print()

    start_time = time.time()
    
    # Run your existing scan
    indicators = load_indicators(args.indicators)
    results = scan_directory_threaded(args.dir, indicators, max_workers=args.threads)
    
    scan_time = time.time() - start_time
    
    if not args.quiet:
        print(f"\n⏱️ Initial scan completed in {scan_time:.2f} seconds")
        print(f"🎯 Found {len(results)} potential threats")
    
    # NEW: AI Enhancement Phase
    if not args.skip_ai and (args.gemini_key or args.deepseek_key):
        enhancer = AIEnhancer(args.gemini_key, args.deepseek_key)
        results = enhancer.supervise_and_enhance(results)
    elif not args.skip_ai:
        print("⚠️ AI Enhancement skipped - no API keys provided")
        print("   Use --gemini-key or --deepseek-key to enable AI analysis")
    
    # Print results to console (your existing code)
    print_results(results, args.quiet)
    
    # Save reports (your existing code)
    if args.report:
        save_report(results, args.report)
    
    if args.summary:
        summary_report = generate_simple_summary(results)
        with open(args.summary, 'w', encoding='utf-8') as f:
            f.write(summary_report)
        if not args.quiet:
            print(f"Summary report saved to {args.summary}")
    
    # NEW: Enhanced PDF Report
    if args.pdf_report:
        generate_enhanced_pdf_report(results, args.pdf_report)
    
    # Export in different formats (your existing code)
    if args.export_json:
        export_json(results, args.export_json)
    
    if args.export_csv:
        export_csv(results, args.export_csv)
    
    if args.export_html:
        export_html(results, args.export_html)
    
    # Print final stats
    if not args.quiet:
        risk_level, risk_score = calculate_risk_score(results)
        unique_indicators = len(set(hit['indicator'] for hit in results)) if results else 0
        ai_enhanced = len([r for r in results if r.get('enhanced')])
        total_time = time.time() - start_time
        
        print(f"\n🎯 Final Assessment: {risk_level}")
        print(f"   📊 Risk Score: {risk_score:.2f}/100")
        print(f"   🔍 Findings: {len(results)} total, {unique_indicators} unique indicators")
        print(f"   🤖 AI Enhanced: {ai_enhanced} findings")
        print(f"   ⏱️ Total Time: {total_time:.1f} seconds")
        
        if risk_score >= 50:
            print(f"   🚨 ATTENTION: High risk detected - Review remediation plan immediately!")


if __name__ == "__main__":
    main()

# This enhanced script provides world-class spyware detection with:
# - Advanced multi-factor risk scoring algorithm
# - Comprehensive remediation planning based on threat level
# - Enhanced metadata (match_type, enrichments, confidence)
# - Professional reporting with actionable intelligence
# - Sophisticated risk assessment considering indicator diversity, file scope, and temporal clustering
