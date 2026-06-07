#!/system/bin/sh

# CleveresTricky Generic ID Attestation Provisioning Script
# This attempts to provision ID attestation directly to the TEE
# (e.g., Qualcomm QSEECom or Mediatek TEE) to fix CSR Exception (code 20)
# without requiring a full software keybox override.

MODDIR=${0%/*}
CONFIG_DIR="/data/adb/cleverestricky"
SPOOF_VARS="$CONFIG_DIR/spoof_build_vars"

if [ ! -f "$CONFIG_DIR/id_attest_provision" ]; then
    exit 0
fi


log_info() {
    echo "cleverestricky-provision: $1" > /dev/kmsg
}

get_val() {
    local prop_name=$1
    local fallback_prop=$2
    local val=""

    if [ -f "$SPOOF_VARS" ]; then
        val=$(grep "^ATTESTATION_ID_${prop_name}=" "$SPOOF_VARS" | cut -d'=' -f2)
        if [ -z "$val" ]; then
            val=$(grep "^${prop_name}=" "$SPOOF_VARS" | cut -d'=' -f2)
        fi
    fi

    if [ -z "$val" ] && [ -n "$fallback_prop" ]; then
        val=$(getprop "$fallback_prop")
    fi

    echo "$val"
}

BRAND=$(get_val "BRAND" "ro.product.brand")
DEVICE=$(get_val "DEVICE" "ro.product.device")
PRODUCT=$(get_val "PRODUCT" "ro.product.name")
SERIAL=$(get_val "SERIAL" "ro.serialno")
[ -z "$SERIAL" ] && SERIAL=$(getprop "ro.boot.serialno")
MANUFACTURER=$(get_val "MANUFACTURER" "ro.product.manufacturer")
MODEL=$(get_val "MODEL" "ro.product.model")

IMEI=$(get_val "IMEI" "persist.radio.imei")
[ -z "$IMEI" ] && IMEI=$(getprop "vendor.ril.imei")
[ -z "$IMEI" ] && IMEI=$(getprop "ro.ril.oem.imei")
IMEI2=$(get_val "IMEI2" "persist.radio.imei2")
[ -z "$IMEI2" ] && IMEI2=$(getprop "vendor.ril.imei2")
MEID=$(get_val "MEID" "vendor.ril.meid")
[ -z "$MEID" ] && MEID=$(getprop "persist.radio.meid")
MEID2=$(get_val "MEID2" "vendor.ril.meid2")
[ -z "$MEID2" ] && MEID2=$(getprop "persist.radio.meid2")

# We determine platform
if [ -c "/dev/qseecom" ] || [ -c "/dev/smd" ]; then
    log_info "Detected Qualcomm environment."
    PROVISION_BIN="$CONFIG_DIR/provision_device_ids"
    if [ ! -x "$PROVISION_BIN" ]; then
        PROVISION_BIN="$MODDIR/provision_device_ids"
    fi

    if [ -x "$PROVISION_BIN" ]; then
        log_info "Executing Qualcomm provisioning tool..."
        set -- "$PROVISION_BIN" -b "$BRAND" -d "$DEVICE" -p "$PRODUCT" -s "$SERIAL" -m "$MANUFACTURER" -M "$MODEL"
        [ -n "$IMEI" ] && set -- "$@" -i "$IMEI"
        [ -n "$IMEI2" ] && set -- "$@" -I "$IMEI2"
        [ -n "$MEID" ] && set -- "$@" -e "$MEID"
        [ -n "$MEID2" ] && set -- "$@" -E "$MEID2"
        "$@" > /dev/null 2>&1
    else
        log_info "Qualcomm provisioning binary not found, skipping."
    fi
elif [ -c "/dev/tee0" ] || getprop ro.board.platform | grep -iq "mt"; then
    log_info "Detected MediaTek environment."
    PROVISION_BIN="$CONFIG_DIR/provision_device_ids_mtk"
    if [ ! -x "$PROVISION_BIN" ]; then
        PROVISION_BIN="$MODDIR/provision_device_ids_mtk"
    fi
    if [ -x "$PROVISION_BIN" ]; then
        log_info "Executing MTK provisioning tool..."
        "$PROVISION_BIN" -b "$BRAND" -d "$DEVICE" -p "$PRODUCT" -s "$SERIAL" -m "$MANUFACTURER" -M "$MODEL" > /dev/null 2>&1
    else
        log_info "MTK provisioning binary not found, skipping."
    fi
else
    log_info "Unknown or unsupported hardware TEE environment."
fi
