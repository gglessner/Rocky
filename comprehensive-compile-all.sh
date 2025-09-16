#!/bin/bash
# Comprehensive Exploit Compilation Script - All Exploits
# Author: Garland Glessner <gglessner@gmail.com>
# License: GNU General Public License v3.0 (GPL-3.0)
# WARNING: Only use on systems you own or have explicit permission to test

set -e

EXPLOIT_REPO_DIR="Linux-Privilege-Escalation-Exploits"
WORKING_EXPLOITS_DIR="working-exploits"
RESULTS_DIR="compilation-results"
COMPILED_COUNT=0
FAILED_COUNT=0

mkdir -p $RESULTS_DIR
mkdir -p $WORKING_EXPLOITS_DIR

echo "=== Comprehensive Exploit Compilation Framework ==="
echo "Target System: Rocky Linux 8.6 (Red Hat 8.10 Compatible)"
echo "Kernel: $(uname -r)"
echo "glibc: $(ldd --version | head -n 1)"
echo "=========================================================="

# Function to try compilation with various flags
try_compile() {
    local source_file="$1"
    local output_name="$2"
    local dir_name="$3"
    local additional_flags="$4"
    
    echo "  Attempting to compile: $source_file"
    
    # Try basic compilation first
    if gcc -o "$output_name" "$source_file" $additional_flags 2>/dev/null; then
        echo "    ✓ Basic compilation successful"
        return 0
    fi
    
    # Try with common libraries
    local libs=("-lpthread" "-lcrypt" "-lm" "-ldl" "-lrt" "-lutil")
    for lib in "${libs[@]}"; do
        if gcc -o "$output_name" "$source_file" $lib $additional_flags 2>/dev/null; then
            echo "    ✓ Compilation successful with $lib"
            return 0
        fi
    done
    
    # Try with multiple libraries
    if gcc -o "$output_name" "$source_file" -lpthread -lcrypt -lm $additional_flags 2>/dev/null; then
        echo "    ✓ Compilation successful with multiple libs"
        return 0
    fi
    
    # Try with static linking
    if gcc -static -o "$output_name" "$source_file" $additional_flags 2>/dev/null; then
        echo "    ✓ Static compilation successful"
        return 0
    fi
    
    echo "    ✗ All compilation attempts failed"
    return 1
}

# Function to copy compiled exploit
copy_exploit() {
    local source_dir="$1"
    local target_name="$2"
    local binary_name="$3"
    
    if [ -f "$binary_name" ]; then
        echo "    Copying $source_dir to working exploits..."
        cp -r "$source_dir" "$WORKING_EXPLOITS_DIR/$target_name"
        chmod +x "$WORKING_EXPLOITS_DIR/$target_name/$binary_name"
        echo "    ✓ Successfully copied $target_name"
        ((COMPILED_COUNT++))
        echo "$source_dir: COMPILED" >> "$RESULTS_DIR/successful_compilations.txt"
        return 0
    fi
    return 1
}

echo ""
echo "=== Phase 1: Compiling Original 10 Exploits ==="

# Original exploits from the Dockerfile
echo "Compiling CVE-2021-4034 (PwnKit)..."
cd $EXPLOIT_REPO_DIR/2021/CVE-2021-4034
cp -r . /home/rocky/working-exploits/CVE-2021-4034
cd /home/rocky/working-exploits/CVE-2021-4034
gcc -o cve-2021-4034-poc cve-2021-4034-poc.c
echo "  ✓ CVE-2021-4034 compiled"

echo "Compiling CVE-2021-3493..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2021/CVE-2021-3493
cp -r . /home/rocky/working-exploits/CVE-2021-3493
cd /home/rocky/working-exploits/CVE-2021-3493
gcc -o exploit exploit.c
echo "  ✓ CVE-2021-3493 compiled"

echo "Compiling CVE-2021-22555 exp-1..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2021/CVE-2021-22555/exp-1
cp -r . /home/rocky/working-exploits/CVE-2021-22555-exp1
cd /home/rocky/working-exploits/CVE-2021-22555-exp1
gcc -o exploit exploit.c
echo "  ✓ CVE-2021-22555-exp1 compiled"

echo "Compiling CVE-2019-13272..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2019/CVE-2019-13272
cp -r . /home/rocky/working-exploits/CVE-2019-13272
cd /home/rocky/working-exploits/CVE-2019-13272
gcc -o CVE-2019-13272 CVE-2019-13272.c
echo "  ✓ CVE-2019-13272 compiled"

echo "Compiling CVE-2017-7308..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2017/CVE-2017-7308
cp -r . /home/rocky/working-exploits/CVE-2017-7308
cd /home/rocky/working-exploits/CVE-2017-7308
gcc -o poc poc.c
echo "  ✓ CVE-2017-7308 compiled"

echo "Compiling CVE-2017-6074..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2017/CVE-2017-6074
cp -r . /home/rocky/working-exploits/CVE-2017-6074
cd /home/rocky/working-exploits/CVE-2017-6074
gcc -o poc poc.c
echo "  ✓ CVE-2017-6074 compiled"

echo "Compiling CVE-2017-5123..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2017/CVE-2017-5123
cp -r . /home/rocky/working-exploits/CVE-2017-5123
cd /home/rocky/working-exploits/CVE-2017-5123
gcc -o 43029 43029.c
echo "  ✓ CVE-2017-5123 compiled"

echo "Compiling CVE-2017-8890..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2017/CVE-2017-8890
cp -r . /home/rocky/working-exploits/CVE-2017-8890
cd /home/rocky/working-exploits/CVE-2017-8890
gcc -o exp-ret2usr exp-ret2usr.c -lpthread
gcc -o exp-smep exp-smep.c -lpthread
echo "  ✓ CVE-2017-8890 compiled (2 binaries)"

echo "Compiling CVE-2016-5195 exp-1 (Dirty COW)..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2016/CVE-2016-5195/exp-1
cp -r . /home/rocky/working-exploits/CVE-2016-5195-exp1
cd /home/rocky/working-exploits/CVE-2016-5195-exp1
gcc -o dirtycow dirty.c -lpthread -lcrypt
echo "  ✓ CVE-2016-5195-exp1 compiled"

echo "Compiling CVE-2016-5195 exp-2 (Dirty COW alt)..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2016/CVE-2016-5195/exp-2
cp -r . /home/rocky/working-exploits/CVE-2016-5195-exp2
cd /home/rocky/working-exploits/CVE-2016-5195-exp2
gcc -o 40611 40611.c -lpthread
echo "  ✓ CVE-2016-5195-exp2 compiled"

echo ""
echo "=== Phase 2: Compiling Additional Exploits ==="

# Additional exploits discovered
echo "Compiling CVE-2021-3156 (Sudo heap buffer overflow)..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2021/CVE-2021-3156
make clean 2>/dev/null || true
if make 2>/dev/null; then
    cp -r . /home/rocky/working-exploits/CVE-2021-3156
    echo "  ✓ CVE-2021-3156 compiled"
else
    echo "  ✗ CVE-2021-3156 compilation failed"
fi

echo "Compiling CVE-2021-42008 (6pack driver vulnerability)..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2021/CVE-2021-42008
make clean 2>/dev/null || true
if make 2>/dev/null; then
    cp -r . /home/rocky/working-exploits/CVE-2021-42008
    echo "  ✓ CVE-2021-42008 compiled"
else
    echo "  ✗ CVE-2021-42008 compilation failed"
fi

echo "Compiling CVE-2022-2588 (File credential vulnerability)..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2022/CVE-2022-2588
make clean 2>/dev/null || true
if make 2>/dev/null; then
    cp -r . /home/rocky/working-exploits/CVE-2022-2588
    echo "  ✓ CVE-2022-2588 compiled"
else
    echo "  ✗ CVE-2022-2588 compilation failed"
fi

echo "Compiling CVE-2017-1000367 (Sudo pty vulnerability)..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2017/CVE-2017-1000367
if gcc -o sudopwn sudopwn.c -lutil 2>/dev/null; then
    cp -r . /home/rocky/working-exploits/CVE-2017-1000367
    echo "  ✓ CVE-2017-1000367 compiled"
else
    echo "  ✗ CVE-2017-1000367 compilation failed"
fi

echo "Compiling CVE-2017-16995 (Kernel vulnerability)..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2017/CVE-2017-16995
if gcc -o upstream44 upstream44.c 2>/dev/null; then
    cp -r . /home/rocky/working-exploits/CVE-2017-16995
    echo "  ✓ CVE-2017-16995 compiled"
else
    echo "  ✗ CVE-2017-16995 compilation failed"
fi

echo "Compiling CVE-2019-15666 (UFFD vulnerability)..."
cd /home/rocky/$EXPLOIT_REPO_DIR/2019/CVE-2019-15666
if gcc -o exp exp.c -lpthread -lrt 2>/dev/null; then
    cp -r . /home/rocky/working-exploits/CVE-2019-15666
    echo "  ✓ CVE-2019-15666 compiled"
else
    echo "  ✗ CVE-2019-15666 compilation failed"
fi

echo ""
echo "=== Phase 3: Compiling Makefile-based Exploits ==="

# Find and compile additional makefiles
find $EXPLOIT_REPO_DIR -name "Makefile" -o -name "makefile" | while read makefile; do
    dir=$(dirname "$makefile")
    dir_name=$(basename "$dir")
    parent_dir=$(basename $(dirname "$dir"))
    full_name="${parent_dir}-${dir_name}"
    
    # Skip if already compiled
    if [ -d "$WORKING_EXPLOITS_DIR/$full_name" ] || [ -d "$WORKING_EXPLOITS_DIR/CVE-${dir_name}" ]; then
        continue
    fi
    
    echo "Processing makefile: $dir"
    cd "$dir"
    
    if make clean 2>/dev/null; then
        echo "  Cleaned previous builds"
    fi
    
    if make 2>/dev/null; then
        echo "  ✓ Make successful"
        
        # Find the compiled binary
        binary=$(find . -type f -executable -not -name "*.c" -not -name "*.h" -not -name "Makefile" -not -name "README*" | head -1)
        if [ -n "$binary" ]; then
            binary_name=$(basename "$binary")
            echo "  Found binary: $binary_name"
            cp -r "$dir" "$WORKING_EXPLOITS_DIR/$full_name"
            chmod +x "$WORKING_EXPLOITS_DIR/$full_name/$binary_name"
            echo "  ✓ Successfully copied $full_name"
            ((COMPILED_COUNT++))
        else
            echo "  No executable binary found after make"
        fi
    else
        echo "  ✗ Make failed"
        ((FAILED_COUNT++))
    fi
    
    cd - > /dev/null
done

echo ""
echo "=== Phase 4: Compiling Individual C Files ==="

# Find all C files and try to compile them individually
find $EXPLOIT_REPO_DIR -name "*.c" | while read c_file; do
    dir=$(dirname "$c_file")
    file_name=$(basename "$c_file" .c)
    dir_name=$(basename "$dir")
    parent_dir=$(basename $(dirname "$dir"))
    full_name="${parent_dir}-${dir_name}-${file_name}"
    
    # Skip if already compiled
    if [ -d "$WORKING_EXPLOITS_DIR" ] && find "$WORKING_EXPLOITS_DIR" -name "*${dir_name}*" -type d | grep -q .; then
        continue
    fi
    
    echo "Processing: $c_file"
    cd "$dir"
    
    # Determine additional flags based on file content
    additional_flags=""
    if grep -q "pthread" "$c_file"; then
        additional_flags="-lpthread"
    fi
    if grep -q "crypt\|crypt_r" "$c_file"; then
        additional_flags="$additional_flags -lcrypt"
    fi
    if grep -q "math\.h\|sin\|cos\|sqrt" "$c_file"; then
        additional_flags="$additional_flags -lm"
    fi
    if grep -q "openpty\|login_tty" "$c_file"; then
        additional_flags="$additional_flags -lutil"
    fi
    if grep -q "sem_\|shm_" "$c_file"; then
        additional_flags="$additional_flags -lrt"
    fi
    
    if try_compile "$c_file" "$file_name" "$full_name" "$additional_flags"; then
        cp -r "$dir" "$WORKING_EXPLOITS_DIR/$full_name"
        chmod +x "$WORKING_EXPLOITS_DIR/$full_name/$file_name"
        echo "  ✓ Successfully copied $full_name"
        ((COMPILED_COUNT++))
    else
        echo "  ✗ Compilation failed for $c_file"
        ((FAILED_COUNT++))
    fi
    
    cd - > /dev/null
done

echo ""
echo "=== Compilation Summary ==="
echo "Successfully compiled: $COMPILED_COUNT"
echo "Failed: $FAILED_COUNT"
echo "Results saved to: $RESULTS_DIR/"

echo ""
echo "=== Working Exploits Directory Contents ==="
if [ -d "$WORKING_EXPLOITS_DIR" ]; then
    ls -la "$WORKING_EXPLOITS_DIR"
    echo ""
    echo "Total exploits in working directory: $(find $WORKING_EXPLOITS_DIR -type f -executable | wc -l)"
fi

echo ""
echo "IMPORTANT REMINDERS:"
echo "1. Only run exploits on systems you own"
echo "2. Use isolated test environments"
echo "3. Never test on production systems"
echo "4. Ensure proper authorization for penetration testing"
