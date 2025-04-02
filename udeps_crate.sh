#!/bin/bash

CRATE_DIR="$1"
CRATE_TOML="$CRATE_DIR/Cargo.toml"
TMP_FILE=".unused_crate_deps"

if [[ -z "$CRATE_DIR" || ! -f "$CRATE_TOML" ]]; then
    echo "❌ Please provide a valid crate path with a Cargo.toml (e.g. ./check_unused_crate_deps.sh path/to/my-crate)"
    exit 1
fi

echo "📦 Analyzing crate: $CRATE_DIR"
echo "🔍 Parsing dependencies from $CRATE_TOML..."
echo "" > "$TMP_FILE"

# Collect deps from [dependencies] and [dev-dependencies]
deps=()
in_section=false
while IFS= read -r line; do
    if [[ "$line" =~ ^\[.*\] ]]; then
        in_section=false
        [[ "$line" == "[dependencies]" ]] || [[ "$line" == "[dev-dependencies]" ]] && in_section=true
        continue
    fi

    if $in_section; then
        # Strip comments, handle whitespace
        clean_line=$(echo "$line" | sed 's/#.*//' | xargs)
        [[ -z "$clean_line" ]] && continue
        dep_name=$(echo "$clean_line" | cut -d '=' -f 1 | xargs)
        deps+=("$dep_name")
    fi
done < "$CRATE_TOML"

if [[ ${#deps[@]} -eq 0 ]]; then
    echo "⚠️  No dependencies found in [dependencies] or [dev-dependencies]."
    exit 0
fi

echo "🔎 Found ${#deps[@]} dependencies to check:"
printf '   - %s\n' "${deps[@]}"
echo

# Check for usage in code files
for dep in "${deps[@]}"; do
    echo "🔍 Checking usage of '$dep'..."
    
    # Extract the base crate name (strip any workspace or version specifiers)
    base_dep=$(echo "$dep" | cut -d '.' -f 1)
    
    # Search the crate's source files for word match using the base dependency name
    if find "$CRATE_DIR" -type f -name "*.rs" | xargs grep -w "$base_dep" >/dev/null 2>&1; then
        echo "✅ Used"
    else
        echo "❌ Unused: $base_dep"
        echo "$base_dep" >> "$TMP_FILE"
    fi
done

# Final report
if [[ -s "$TMP_FILE" ]]; then
    echo ""
    echo "💡 The following dependencies appear unused in $CRATE_DIR:"
    cat "$TMP_FILE"
    echo ""
    echo "✂️ Consider removing them from $CRATE_TOML"
else
    echo ""
    echo "✅ All dependencies appear to be used!"
fi

rm "$TMP_FILE"
