#!/bin/zsh
set -u

if [[ -z "${1:-}" ]]; then
    echo "Error: No file path specified."
    echo "Usage: $0 /path/to/file"
    exit 1
fi

TARGET="${1%/}"

if [[ ! -e "$TARGET" ]]; then
    echo "Error: File or directory not found: $TARGET"
    exit 1
fi

echo "=================================================="
echo "Analyzing: $(basename -- "$TARGET")"
echo "=================================================="

_BASENAME="$(basename -- "$TARGET")"
if [[ "$_BASENAME" == *.* ]]; then
    EXTENSION="${(L)${_BASENAME##*.}}"
else
    EXTENSION=""
fi

echo "--------------------------------------------------"
echo "Checksums (Hashes):"
if [[ -f "$TARGET" ]]; then
    # Compute MD5
    MD5_VAL=$(md5 -q -- "$TARGET")
    echo "   [MD5]    $MD5_VAL"

    # Compute SHA-256
    SHA256_VAL=$(shasum -a 256 -- "$TARGET" | awk '{print $1}')
    echo "   [SHA256] $SHA256_VAL"
else
    echo "   (skipped: target is a bundle directory)"
fi
echo "--------------------------------------------------"


typeset -A CODESIGN_INFO
typeset -A SPCTL_INFO

parse_codesign() {
    local check_path="$1"
    local simple_data=$(codesign -dv --verbose=4 -- "$check_path" 2>&1)
    
    CODESIGN_INFO[Executable]=$(echo "$simple_data" | grep "^Executable=" | cut -d'=' -f2-)
    CODESIGN_INFO[Identifier]=$(echo "$simple_data" | grep "^Identifier=" | cut -d'=' -f2-)
    CODESIGN_INFO[Format]=$(echo "$simple_data" | grep "^Format=" | cut -d'=' -f2-)
    CODESIGN_INFO[TeamIdentifier]=$(echo "$simple_data" | grep "^TeamIdentifier=" | cut -d'=' -f2-)
    CODESIGN_INFO[NotarizationTicket]=$(echo "$simple_data" | grep "^Notarization Ticket=" | cut -d'=' -f2-)
    
    CODESIGN_INFO[Authority]=$(echo "$simple_data" | grep "^Authority=" | head -n 1 | cut -d'=' -f2-)

    echo "   [codesign] Deep verify (recursive check of all binaries)..."
    local deep_data
    deep_data=$(codesign --verify --deep --strict --verbose=4 -- "$check_path" 2>&1)
    local deep_data_exit_code=$?

    if [ $deep_data_exit_code -eq 0 ]; then
        CODESIGN_INFO[DeepStatus]="OK (Integrity confirmed)"
        CODESIGN_INFO[DeepError]=""
    else
        CODESIGN_INFO[DeepStatus]="ERROR (Tampered or unsigned)"
        CODESIGN_INFO[DeepError]=$(echo "$deep_data" | head -n 1)
    fi
}

parse_spctl_app() {
    local check_path="$1"
    local raw_spctl=$(spctl -a -vv -- "$check_path" 2>&1)

    SPCTL_INFO[Gatekeeper]=$(echo "$raw_spctl" | head -n 1)
    SPCTL_INFO[Source]=$(echo "$raw_spctl" | grep "source=" | cut -d'=' -f2-)
    SPCTL_INFO[Origin]=$(echo "$raw_spctl" | grep "origin=" | cut -d'=' -f2-)
}

parse_spctl_dmg() {
    local check_path="$1"
    local raw_spctl
    raw_spctl=$(spctl -a -vv -- "$check_path" 2>&1)

    SPCTL_INFO[Gatekeeper]=$(echo "$raw_spctl" | head -n 1)
    SPCTL_INFO[Source]=$(echo "$raw_spctl" | grep "source=" | cut -d'=' -f2-)
    SPCTL_INFO[Origin]=$(echo "$raw_spctl" | grep "origin=" | cut -d'=' -f2-)
}

print_report() {
    echo "\nCODESIGN DATA:"
    echo "----------------------------------------------------------------------"
    printf "%-20s | %s\n" "PARAMETER" "VALUE"
    echo "----------------------------------------------------------------------"
    printf "%-20s | %s\n" "Executable" "${CODESIGN_INFO[Executable]}"
    printf "%-20s | %s\n" "Identifier" "${CODESIGN_INFO[Identifier]}"
    printf "%-20s | %s\n" "Format" "${CODESIGN_INFO[Format]}"
    printf "%-20s | %s\n" "TeamIdentifier" "${CODESIGN_INFO[TeamIdentifier]}"
    printf "%-20s | %s\n" "Authority" "${CODESIGN_INFO[Authority]}"
    printf "%-20s | %s\n" "NotarizationTicket" "${CODESIGN_INFO[NotarizationTicket]}"
    if [[ -z "${CODESIGN_INFO[DeepError]}" ]]; then
        printf "%-20s | %s\n" "Deep Verify" "${CODESIGN_INFO[DeepStatus]}"
    else
        printf "%-20s | %s\n" "Deep Verify" "${CODESIGN_INFO[DeepStatus]}"
        printf "%-20s | %s\n" "Deep Error" "${CODESIGN_INFO[DeepError]}"
    fi
    echo "----------------------------------------------------------------------"

    # ===================================================================

    echo "\n\nSPCTL DATA:"
    echo "----------------------------------------------------------------------"
    printf "%-20s | %s\n" "PARAMETER" "VALUE"
    echo "----------------------------------------------------------------------"
    printf "%-20s | %s\n" "Gatekeeper" "${SPCTL_INFO[Gatekeeper]}"
    printf "%-20s | %s\n" "Source" "${SPCTL_INFO[Source]}"
    printf "%-20s | %s\n" "Origin" "${SPCTL_INFO[Origin]}"
    echo "----------------------------------------------------------------------"

    # ===================================================================

    echo "\n\nCOMPARISON:"
    echo "----------------------------------------------------------------------"

    local team="${CODESIGN_INFO[TeamIdentifier]}"
    local origin="${SPCTL_INFO[Origin]}"
    local auth="${CODESIGN_INFO[Authority]}"

    if [[ -n "$team" && -n "$origin" && "$origin" == *"($team)"* ]]; then
        echo "Status: Source verified: TeamID ($team) matches Gatekeeper origin."
    else
        echo "Status: Mismatch! Authority: [$auth] | Origin: [$origin]"
    fi
    echo "----------------------------------------------------------------------"

    # ===================================================================

    if [[ "${SPCTL_INFO[Gatekeeper]}" == *"accepted"* ]]; then
        echo "\nFINAL STATUS: OK (System will allow launch)"
    elif echo "${SPCTL_INFO[Gatekeeper]}" | grep -q "the code is valid but does not seem to be an app"; then
        # DMG is not an .app bundle — spctl returns "rejected" with this message.
        # This is expected: the signature is valid, the file type is just not an app.
        # Authoritative source: codesign --verify --deep.
        if [[ "${CODESIGN_INFO[DeepStatus]}" == *"ERROR"* ]]; then
            echo "\nFINAL STATUS: FAIL (Signature is tampered)"
        else
            echo "\nFINAL STATUS: OK (Signature valid; disk image is not an .app — this is normal)"
        fi
    else
        echo "\nFINAL STATUS: FAIL (System will block launch)"
    fi
}


case "$EXTENSION" in
    app)
        echo "Type: macOS Application (.app)"

        echo "Analyzing signature (may take a few seconds)..."
        parse_codesign "$TARGET"
        echo "Checking Gatekeeper..."
        parse_spctl_app "$TARGET"
        print_report
        ;;

    pkg)
        echo "Type: Installer Package (.pkg)"
        
        echo "\nChecking pkgutil certificate..."
        pkg_sig=$(pkgutil --check-signature -- "$TARGET")
        if echo "$pkg_sig" | grep -qE "Status: signed by a certificate trusted by (Mac OS X|macOS)"; then
             echo "Package is signed by a trusted certificate."
             echo "\n--- Certificate chain ---"
             echo "$pkg_sig" | grep -A 3 "1. "
        else
             echo "PACKAGE IS NOT SIGNED or certificate is not trusted!"
             echo "$pkg_sig"
        fi
        ;;

    dmg)
        echo "Type: Disk Image (.dmg)"

        echo "Analyzing signature (may take a few seconds)..."
        parse_codesign "$TARGET"
        echo "Checking Gatekeeper..."
        parse_spctl_dmg "$TARGET"
        print_report

        echo "=================================================="

        is_dmg_ok=true
        local gk="${SPCTL_INFO[Gatekeeper]}"
        if [[ "$gk" != *"accepted"* ]]; then
            # "does not seem to be an app" is the expected response for a DMG (not an .app bundle).
            # The signature is still valid; authoritative source is codesign --verify.
            if echo "$gk" | grep -q "does not seem to be an app"; then
                if [[ "${CODESIGN_INFO[DeepStatus]}" == *"ERROR"* ]]; then
                    is_dmg_ok=false
                fi
            else
                is_dmg_ok=false
            fi
        fi
        if [[ "${CODESIGN_INFO[DeepStatus]}" == *"ERROR"* ]]; then
            is_dmg_ok=false
        fi

        if [[ "$is_dmg_ok" == true ]]; then
            echo "Disk image is correctly signed. Mounting skipped."
        else
            echo "WARNING: Disk image is unsigned or has errors."
            
            if read -q "?Mount the image and check the .app inside? (y/n): "; then
                echo ""
                echo ""
                echo "Safely mounting disk image..."
                
                local hdiutil_err
                hdiutil_err=$(mktemp)
                mount_path=$(hdiutil attach -readonly -nobrowse -mountrandom /tmp "$TARGET" 2>"$hdiutil_err" | tail -1 | awk -F'\t' '{print $NF}')

                if [[ -n "$mount_path" ]]; then
                    rm -f "$hdiutil_err"
                    trap "echo 'Unmounting disk image (cleanup)...'; hdiutil detach ${(q)mount_path} -quiet 2>/dev/null" EXIT INT TERM

                    app_path=""
                    while IFS= read -r _found; do
                        app_path="$_found"
                        break
                    done < <(find "$mount_path" -maxdepth 1 -name "*.app")

                    if [[ -n "$app_path" ]]; then
                        echo "Found application: $(basename "$app_path")"
                        echo "Analyzing signature (may take up to 30 sec for large apps)..."
                        parse_codesign "$app_path"
                        echo "Checking Gatekeeper..."
                        parse_spctl_app "$app_path"
                        print_report
                    else
                        echo "Warning: No .app files found at the root of the image."
                    fi

                    echo ""
                    echo "Unmounting disk image..."
                    if ! hdiutil detach "$mount_path" -quiet; then
                        echo "Warning: Failed to unmount image: $mount_path"
                    fi
                    trap - EXIT INT TERM
                else
                    echo "Error: Failed to safely mount the disk image."
                    if [[ -s "$hdiutil_err" ]]; then
                        echo "Reason: $(cat "$hdiutil_err")"
                    fi
                    rm -f "$hdiutil_err"
                fi
            else
                echo ""
                echo "Content check cancelled by user."
            fi
        fi
        ;;

    *)
        echo "Unknown or unsupported file type: .$EXTENSION"
        echo "This script supports .app, .pkg and .dmg only"
        ;;
esac

echo "\n=================================================="
echo "Analysis complete."