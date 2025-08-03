import json
import re
import argparse
from collections import OrderedDict

def parse_cmp_log_file(filepath):
    results = []
    seen = set()

    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # 只匹配包含 cmpbytes 的日志
        match = re.match(
            r"\[my-taint-log\] type=(\w+), bytes=\[([^\]]+)\], cmpbytes=\[([^\]]+)\], label=\d+",
            line
        )
        if match:
            type_str = match.group(1)
            byte_strs = [b.strip() for b in match.group(2).split(',')]
            cmpbyte_strs = [b.strip() for b in match.group(3).split(',')]

            tainted_input_bytes = []
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if next_line.startswith("byte: "):
                    val = next_line[len("byte: "):].strip()
                    tainted_input_bytes.append(val)
                    i += 1
                else:
                    break

            tainted_input_bytes.sort(key=lambda x: int(x, 16))

            record = OrderedDict()
            record["type"] = type_str
            record["bytes"] = byte_strs
            record["cmpbytes"] = cmpbyte_strs
            record["tainted_input_bytes"] = tainted_input_bytes

            key = (
                type_str,
                tuple(byte_strs),
                tuple(cmpbyte_strs),
                tuple(tainted_input_bytes)
            )

            if key not in seen:
                results.append(record)
                seen.add(key)
            continue
        i += 1

    results.sort(key=lambda r: [int(b, 16) for b in r["tainted_input_bytes"]])
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse only DFSan logs with cmpbytes.")
    parser.add_argument("input_file", help="Path to the log input file")
    parser.add_argument("output_file", help="Path to save the parsed JSON output")
    args = parser.parse_args()

    parsed_data = parse_cmp_log_file(args.input_file)

    with open(args.output_file, 'w') as out:
        json.dump(parsed_data, out, indent=2, separators=(', ', ': '), ensure_ascii=False)
    
    print(f"[CMP ONLY] 去重 + 排序后共输出 {len(parsed_data)} 个记录单元")
