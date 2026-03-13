This tool leverages BPF to dynamically attach to MySQL's mysql_execute_command function. By monitoring this function in real-time, it can capture:

- The query text
- The execution time of the query (in msec)
- Whether the query was truncated
- Date/time

The program is version-aware, meaning it uses offsets specific to each supported MySQL version (5.7, 8.0, 8.4) to access internal MySQL structures. 

Requirements

    Python Version: Python 3.6 or higher
    BPF Library: (bcc) via yum/dnf/apt. 

Python Libraries

    argparse
    subprocess
    textwrap
    datetime
    typing (for type hints)
    bcc (for BPF support)

Getting Started

Clone the Repository:

    git clone https://github.com/your-username/mysql-bpf-query-monitor.git
    cd mysql-bpf-query-monitor

Run the script:

    python3 mysql_query_monitor.py --path /path/to/mysqld --duration-threshold 10 --log /path/to/output.log

Output 

    Detected MySQL version 8.0 (Using offsets (510, 518))
    Monitoring MySQL queries... Press Ctrl+C to stop.
    2024-11-08 14:43:39.299 | Execution Time: 1.22 ms | Length: 92 | Truncated: No | Query: select * from users where id=1;
    2024-11-08 14:43:41.915 | Execution Time: 4.76 ms | Length: 156 | Truncated: Yes | Query: select * from ...

Known Limitations

- Offset Compatibility: This tool supports specific MySQL versions (5.7, 8.0, 8.4) and may require updating offsets for other versions. 
- Debugging Symbols: If offsets change across MySQL updates, new offsets will need to be calculated. (See below) 
- Kernel Compatibility: Ensure the kernel version supports BPF and that BPF is configured correctly. All of my testing was performed on AlmaLinux 8+ with MySQL 8.0+
  
Updating Offsets

A quick guide on updating the offsets:


Requirements: 
- MySQL debugging symbols
- GDB

Steps 
- Generate a coredump of a running MySQL process, eg:
  
      gcore -o /tmp/mysql_core %d

- Load up the coredump into gdb, eg:

      gdb /usr/sbin/mysqld /tmp/mysql_core

- Get the offsets

      (gdb) python print("Detected offsets:")
      Detected offsets:
      (gdb) python print("m_query_string.str offset (decimal):", int(gdb.parse_and_eval("&((THD*)0)->m_query_string.str")))
      m_query_string.str offset (decimal): 1296
      (gdb) python print("m_query_string.length offset (decimal):", int(gdb.parse_and_eval("&((THD*)0)->m_query_string.length")))
      m_query_string.length offset (decimal): 1304

- The numeric values (decimal) can now be added to the code.


Credits: 

This code is based off of https://github.com/shuhaowu/mysqld-bpf/blob/master/mysql/trace/mysql_query_tracer.py with signifigant modifications.

    
