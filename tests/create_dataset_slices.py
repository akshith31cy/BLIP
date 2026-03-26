import os

# Path to your common password file
SOURCE_FILE = os.path.join("data", "common-passwords.txt")

# Output sizes you want
sizes = [1000, 5000, 10000, 50000, 100000]

def create_slices():
    # Read all passwords
    with open(SOURCE_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    print(f"Loaded {len(lines)} passwords from source file.\n")

    # Create slice files
    for s in sizes:
        output_path = os.path.join("data", f"sample_{s}.txt")
        with open(output_path, "w", encoding="utf-8") as out:
            out.write("\n".join(lines[:s]))
        print(f"Created {output_path} with first {s} passwords.")

if __name__ == "__main__":
    create_slices()
