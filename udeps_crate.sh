#!/bin/bash
CRATE_DIR="$1"
CRATE_TOML="$CRATE_DIR/Cargo.toml"
TMP_FILE=".unused_crate_deps"
VERBOSE="${2:-false}"  # Add verbose option as second parameter

if [[ -z "$CRATE_DIR" || ! -f "$CRATE_TOML" ]]; then
  echo "❌ Please provide a valid crate path with a Cargo.toml (e.g. ./check_unused_crate_deps.sh path/to/my-crate)"
  exit 1
fi

echo "📦 Analyzing crate: $CRATE_DIR"
echo "🔍 Parsing dependencies from $CRATE_TOML..."
echo "" > "$TMP_FILE"

# Collect deps from [dependencies] and [dev-dependencies]
deps=()
section=""
while IFS= read -r line; do
  # Check for section headers
  if [[ "$line" =~ ^\[(.*?)\] ]]; then
    section="${BASH_REMATCH[1]}"
    continue
  fi
  
  # Only process dependencies and dev-dependencies sections
  if [[ "$section" == "dependencies" || "$section" == "dev-dependencies" ]]; then
    # Strip comments, handle whitespace
    clean_line=$(echo "$line" | sed 's/#.*//' | xargs)
    [[ -z "$clean_line" ]] && continue
    
    # Extract dependency name
    if [[ "$clean_line" =~ ^([a-zA-Z0-9_-]+) ]]; then
      dep_name="${BASH_REMATCH[1]}"
      deps+=("$dep_name")
    fi
  fi
done < "$CRATE_TOML"

if [[ ${#deps[@]} -eq 0 ]]; then
  echo "⚠️ No dependencies found in [dependencies] or [dev-dependencies]."
  exit 0
fi

echo "🔎 Found ${#deps[@]} dependencies to check:"
printf ' - %s\n' "${deps[@]}"
echo

# Check for usage in code files
for dep in "${deps[@]}"; do
  echo "🔍 Checking usage of '$dep'..."
  
  # Convert hyphens to both underscore and hyphen for pattern matching
  dep_underscore=$(echo "$dep" | tr '-' '_')
  dep_hyphen=$(echo "$dep" | tr '_' '-')
  
  # Common patterns for dependency usage
  patterns=(
    "^[[:space:]]*use[[:space:]]+$dep\b"          # Direct use statement: use tokio
    "^[[:space:]]*use[[:space:]]+$dep_underscore\b" # With underscores: use kbs_types
    "^[[:space:]]*use[[:space:]]+$dep_hyphen\b"     # With hyphens: use kbs-types
    "^[[:space:]]*use[[:space:]]+.*::$dep\b"      # Qualified use: use crate::tokio
    "^[[:space:]]*use[[:space:]]+$dep::"           # Module use: use tokio::runtime
    "^[[:space:]]*use[[:space:]]+$dep_underscore::" # Module with underscores: use kbs_types::
    "^[[:space:]]*use[[:space:]]+$dep_hyphen::"     # Module with hyphens: use kbs-types::
    "\b$dep::"                                   # Qualified path: tokio::runtime
    "\b$dep_underscore::"                        # Path with underscores: kbs_types::
    "\b$dep_hyphen::"                            # Path with hyphens: kbs-types::
    "for[[:space:]]+$dep::"                      # Type annotation: for aes_gcm::Type
    "for[[:space:]]+$dep_underscore::"           # Type with underscores
    "for[[:space:]]+$dep_hyphen::"               # Type with hyphens
    "[[:space:]]$dep::"                          # Space then dependency: impl X for aes_gcm::Y
    "[[:space:]]$dep_underscore::"               # With underscores 
    "[[:space:]]$dep_hyphen::"                   # With hyphens
    "<[[:space:]]*$dep::"                        # Generic usage: Option<aes_gcm::Type>
    "<[[:space:]]*$dep_underscore::"             # With underscores
    "<[[:space:]]*$dep_hyphen::"                 # With hyphens
    "#\[.*$dep"                                 # Attribute: #[tokio::main]
    "#\[.*$dep_underscore"                      # Attribute with underscores: #[pin_project]
    "#\[.*$dep_hyphen"                          # Attribute with hyphens: #[pin-project]
    "extern[[:space:]]+crate[[:space:]]+$dep\b"    # extern crate statement
    "extern[[:space:]]+crate[[:space:]]+$dep_underscore\b" # With underscores
    "extern[[:space:]]+crate[[:space:]]+$dep_hyphen\b"     # With hyphens
    ".*[[:space:]]as[[:space:]]+$dep"                 # Import aliasing: use x as kbs_types
    ".*[[:space:]]as[[:space:]]+$dep_underscore"      # With underscores
    ".*[[:space:]]as[[:space:]]+$dep_hyphen"          # With hyphens
  )
  
  found=false
  for pattern in "${patterns[@]}"; do
    if $VERBOSE; then
      echo "  Searching for pattern: $pattern"
    fi
    
    if find "$CRATE_DIR" -type f \( -name "*.rs" -o -name "build.rs" -o -name "*.toml" \) -print0 | xargs -0 grep -E "$pattern" > /tmp/matches_$dep 2>/dev/null; then
      found=true
      if $VERBOSE; then
        echo "  Found matches:"
        cat /tmp/matches_$dep
      fi
      break
    fi
  done
  
  # If not found using strict patterns, try a broader approach for special cases
  if ! $found; then
    # Replace hyphens with regex that matches both hyphen and underscore
    dep_pattern=$(echo "$dep" | sed 's/-/[-_]/g')
    broader_patterns=(
      "use[[:space:]]+.*$dep_pattern\b"
      "use[[:space:]]+.*$dep_pattern::"
    )
    
    for pattern in "${broader_patterns[@]}"; do
      if $VERBOSE; then
        echo "  Trying broader search pattern: $pattern"
      fi
      
      if find "$CRATE_DIR" -type f \( -name "*.rs" -o -name "build.rs" \) -print0 | xargs -0 grep -E "$pattern" > /tmp/matches_$dep 2>/dev/null; then
        found=true
        if $VERBOSE; then
          echo "  Found matches with broader pattern:"
          cat /tmp/matches_$dep
        fi
        break
      fi
    done
  fi
  
  rm -f /tmp/matches_$dep
  
  if $found; then
    echo "✅ Used"
  else
    echo "❌ Unused: $dep"
    echo "$dep" >> "$TMP_FILE"
  fi
done

# Final report
if [[ -s "$TMP_FILE" ]]; then
  echo ""
  echo "💡 The following dependencies appear unused in $CRATE_DIR:"
  cat "$TMP_FILE"
  echo ""
  echo "✂️ Consider removing them from $CRATE_TOML"
  echo "Note: Run with verbose mode for detailed matching: $0 $CRATE_DIR true"
else
  echo ""
  echo "✅ All dependencies appear to be used!"
fi

rm "$TMP_FILE"