import argparse

def extract_il2cpp_enum(input_path, output_path):
    with open(input_path, "r") as f:
        text = f.read()
    
    text_il2cpp_internal = text[:text.index("#if !IS_DECOMPILER\nnamespace app {")]
    
    text_enum = text[text.index("enum Protocol__Enum {"):]
    text_enum = text_enum[:text_enum.index("};")+2]
    
    with open(output_path, "w") as f:
        f.write(text_il2cpp_internal + text_enum)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract il2cpp.h from il2cpp-types.h")
    parser.add_argument("input", help="Path to input il2cpp-types.h")
    parser.add_argument("output", help="Path to output il2cpp.h")
    args = parser.parse_args()
    
    extract_il2cpp_enum(args.input, args.output)