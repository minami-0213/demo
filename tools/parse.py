import json
import re
import argparse

def parse_log_file(filepath):
    results = []
    seen = set()

    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # 匹配开头行
        if line.startswith("[my-taint-log]"):
            match = re.match(r"\[my-taint-log\] type=(\w+), bytes=\[([^\]]+)\], label=\d+", line)
            if match:
                type_str = match.group(1)
                byte_strs = match.group(2).split(',')
                byte_strs = [b.strip() for b in byte_strs]

                # 收集 byte: 行
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

                # 排序污点字节
                tainted_input_bytes.sort(key=lambda x: int(x, 16))

                # 创建 dict 单元
                record = {
                    "type": type_str,
                    "bytes": byte_strs,
                    "tainted_input_bytes": tainted_input_bytes
                }

                # 构造 hash key 去重
                key = (
                    type_str,
                    tuple(byte_strs),
                    tuple(tainted_input_bytes)
                )

                if key not in seen:
                    results.append(record)
                    seen.add(key)
                continue
        i += 1

    # 根据 tainted_input_bytes 的值排序
    results.sort(key=lambda r: [int(b, 16) for b in r["tainted_input_bytes"]])
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse DFSan taint log and output JSON.")
    parser.add_argument("input_file", help="Path to the log input file")
    parser.add_argument("output_file", help="Path to save the parsed JSON output")

    args = parser.parse_args()

    parsed_data = parse_log_file(args.input_file)

    # 美观输出，数组紧凑展示
    with open(args.output_file, 'w') as out:
        json.dump(parsed_data, out, indent=2, separators=(', ', ': '), ensure_ascii=False)
    
    print(f"去重 + 排序后共输出 {len(parsed_data)} 个记录单元")
    print(f"结果已保存到 {args.output_file}")