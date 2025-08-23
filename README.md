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

summary_report.txt made by 
python scan_indicators.py --dir "E:\DC AntiSpyware\sysdiagnose_2025.03.26_10-34-36+0530_iPhone-OS_iPhone_22D82" --indicators indicators/ --report results.txt --summary summary_report.txt --export-json results.json --threads 16   


Full enhanced workflow
python scan_indicators.py \
  --dir "test_malicious/" \
  --indicators "indicators/" \
  --gemini-key "AIzaSyD-your-key-here" \
  --pdf-report "security_report.pdf" \
  --export-html "report.html" \
  --summary "summary.txt"