import os
import time
import re
from pathlib import Path

def test_regex_performance():
    # Test the problematic patterns
    slow_pattern = re.compile(r"(?i)(?:wget|curl)\\s+\\S*(?:\\.sh|\\.py|\\.exe)\\s")
    fast_pattern = re.compile(r"wget.*\.sh")
    
    # Sample text (simulate log line)
    test_text = "user executed wget http://example.com/malware.sh in background" * 1000
    
    # Test slow pattern
    start = time.time()
    for _ in range(100):
        slow_pattern.search(test_text)
    slow_time = time.time() - start
    
    # Test fast pattern  
    start = time.time()
    for _ in range(100):
        fast_pattern.search(test_text)
    fast_time = time.time() - start
    
    print(f"Slow pattern: {slow_time:.4f}s")
    print(f"Fast pattern: {fast_time:.4f}s") 
    print(f"Speedup: {slow_time/fast_time:.1f}x faster")

test_regex_performance()
