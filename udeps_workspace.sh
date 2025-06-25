#!/bin/bash

# Checks for dependencies in the cargo workspace that are 
# not listed in any crate's Cargo.toml

WORKSPACE_TOML="Cargo.toml"
TMP_FILE=".unused_deps_found"

# Check Cargo.toml exists
if [[ ! -f "$WORKSPACE_TOML" ]]; then
    echo "❌ Error: $WORKSPACE_TOML not found in the current directory: $(pwd)"
    echo "👉 Please run this script from the root of your Cargo workspace."
    exit 1
fi

# Check if [workspace.dependencies] section exists
if ! grep -q '^\[workspace.dependencies\]' "$WORKSPACE_TOML"; then
    echo "ℹ️  No [workspace.dependencies] section found in $WORKSPACE_TOML."
    echo "✅ Nothing to check. Exiting."
    exit 0
fi

echo "🔍 Scanning [workspace.dependencies] in $WORKSPACE_TOML..."

# Extract lines after the section until the next section, clean comments and whitespace
deps=()
in_section=false
while IFS= read -r line; do
    if [[ "$line" =~ ^\[.*\] ]]; then
        if $in_section; then break; fi
        if [[ "$line" == "[workspace.dependencies]" ]]; then in_section=true; fi
        continue
    fi

    if $in_section; then
        # Strip comments
        clean_line=$(echo "$line" | sed 's/#.*//' | xargs)
        # Skip empty lines
        [[ -z "$clean_line" ]] && continue
        # Extract the key before '='
        dep_name=$(echo "$clean_line" | cut -d '=' -f 1 | xargs)
        deps+=("$dep_name")
    fi
done < "$WORKSPACE_TOML"

# Check if any deps were found
if [[ ${#deps[@]} -eq 0 ]]; then
    echo "⚠️  [workspace.dependencies] section is present but contains no dependencies."
    exit 0
fi

echo "📦 Found ${#deps[@]} declared workspace dependencies:"
printf '   - %s\n' "${deps[@]}"
echo

# Search for each dep
for dep in "${deps[@]}"; do
    echo "🔎 Checking usage of '$dep'..."
    found=false

    # Find all Cargo.toml files EXCEPT the root workspace one
    cargo_tomls=$(find . -name "Cargo.toml" ! -path "./$WORKSPACE_TOML")

    # Search each for the dependency name
    for toml in $cargo_tomls; do
        if grep -q -w "$dep" "$toml"; then
            found=true
            break
        fi
    done

    # Search in all Cargo.toml files (excluding the workspace one)
    if grep -rq "$dep" . --include "Cargo.toml" --exclude "$WORKSPACE_TOML"; then
        found=true
    fi

    if ! $found; then
        echo "❌ Unused: $dep"
        echo "$dep" >> "$TMP_FILE"
    else
        echo "✅ Used"
    fi
done

# Summary
if [[ -s "$TMP_FILE" ]]; then
    echo ""
    echo "💡 The following workspace dependencies appear unused:"
    cat "$TMP_FILE"
    echo ""
    echo "✂️ You can now manually remove them from [workspace.dependencies] in $WORKSPACE_TOML."
    rm "$TMP_FILE"
else
    echo ""
    echo "✅ No unused workspace dependencies found!"
fi
