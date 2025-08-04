import re
import json

def parse_results_file(input_path):
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    hits = []
    current_hit = {}
    context_lines = []

    # Regexes to extract important fields
    indicator_re = re.compile(r'\[(.*?)\] (.*?) in (.*?) \(line (\d+)\)')
    matched_re = re.compile(r'\s*> Matched: (.*)')
    app_re = re.compile(r'\s*> App/Process: (.*)')
    context_re = re.compile(r'\s*> Context: (.*)')
    attribution_source_re = re.compile(r'\s*> Source: (.*)')
    attribution_author_re = re.compile(r'\s*> Author: (.*)')
    attribution_date_re = re.compile(r'\s*> Date: (.*)')

    for line in lines:
        line = line.strip()
        if not line:
            # Empty line means hit delimiter; save current if exists
            if current_hit:
                hits.append(current_hit)
                current_hit = {}
            continue

        # Parse main indicator line
        m_indicator = indicator_re.match(line)
        if m_indicator:
            current_hit['severity'] = m_indicator.group(1)
            current_hit['indicator'] = m_indicator.group(2)
            current_hit['filepath'] = m_indicator.group(3)
            current_hit['line_num'] = int(m_indicator.group(4))
            continue

        # Parse matched text line
        m_matched = matched_re.match(line)
        if m_matched:
            current_hit['matched_text'] = m_matched.group(1)
            continue

        # Parse app/process attribution
        m_app = app_re.match(line)
        if m_app:
            current_hit['app_or_process'] = m_app.group(1)
            continue

        # Parse context line
        m_context = context_re.match(line)
        if m_context:
            current_hit['context'] = m_context.group(1)
            continue

        # Parse attribution metadata
        m_source = attribution_source_re.match(line)
        if m_source:
            current_hit.setdefault('attribution', {})['source'] = m_source.group(1)
            continue
        m_author = attribution_author_re.match(line)
        if m_author:
            current_hit.setdefault('attribution', {})['author'] = m_author.group(1)
            continue
        m_date = attribution_date_re.match(line)
        if m_date:
            current_hit.setdefault('attribution', {})['date_created'] = m_date.group(1)
            continue

    # Catch last hit if file does not end with empty line
    if current_hit:
        hits.append(current_hit)

    return hits

def save_as_json(data, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python parse_results.py <input_plaintext_results.txt> <output.json>")
        exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    parsed_hits = parse_results_file(input_file)
    print(f"Parsed {len(parsed_hits)} indicator hits.")

    save_as_json(parsed_hits, output_file)
    print(f"Saved structured results to {output_file}")
