To run
python scan_indicators.py --dir "Path of sysdiagnose files" --indicators indicators/ --report results.txt --summary summary_report.txt --threads 6
TO Export i n varaious forms
# Export to JSON, CSV, and HTML
python scan_indicators.py --dir data/ --indicators indicators/ --export-json results.json --export-csv results.csv --export-html results.html

python scan_indicators.py --help
# Shows version, examples, and full help

python scan_indicators.py --version
# Shows: iOS AntiSpyware v2.0

python scan_indicators.py --quiet --export-json results.json
# Silent mode for automation
