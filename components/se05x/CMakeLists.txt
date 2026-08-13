set(SE05X_NXP_DIR "${CMAKE_CURRENT_LIST_DIR}/nxp/plug-and-trust")

if(NOT EXISTS "${SE05X_NXP_DIR}/sss/inc/fsl_sss_ftr.h.in")
    message(FATAL_ERROR
        "NXP Plug & Trust middleware is missing. Run: "
        "git submodule update --init --recursive")
endif()

# Generate NXP's feature header outside the vendor submodule. This initial
# compatibility build targets an SE051C2 (IoT applet 7.2), a plain/default
# session, and no host-side crypto. Authenticated sessions are intentionally a
# later integration step.
set(SSS_HAVE_APPLET_SE05X_C 1)
set(SSS_HAVE_SE05X_VER_07_02 1)
set(SSS_HAVE_HOSTCRYPTO_NONE 1)
set(SSS_HAVE_MBEDTLS_ALT_NONE 1)
set(SSS_HAVE_SCP_NONE 1)
set(SSS_HAVE_FIPS_NONE 1)
set(SSS_HAVE_SBL_NONE 1)
set(SSS_HAVE_SE05X_AUTH_NONE 1)
set(SSS_HAVE_SE_RESET_LOGIC_1 1)

set(SSSFTR_SE05X_AES 1)
set(SSSFTR_SE05X_ECC 1)
set(SSSFTR_SE05X_RSA 1)
set(SSSFTR_SE05X_KEY_SET 1)
set(SSSFTR_SE05X_KEY_GET 1)
set(SSSFTR_SE05X_AuthECKey 1)
set(SSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ 1)
set(SSS_HAVE_ECC 1)
set(SSS_HAVE_RSA 1)
set(SSS_HAVE_EC_ED 1)
set(SSS_HAVE_EC_MONT 1)
set(SSS_HAVE_MIFARE_DESFIRE 1)
set(SSS_HAVE_PBKDF2 1)
set(SSS_HAVE_TLS_HANDSHAKE 1)
set(SSS_HAVE_IMPORT 1)

set(SE05X_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include")
file(MAKE_DIRECTORY "${SE05X_GENERATED_INCLUDE_DIR}")
configure_file(
    "${SE05X_NXP_DIR}/sss/inc/fsl_sss_ftr.h.in"
    "${SE05X_GENERATED_INCLUDE_DIR}/fsl_sss_ftr.h"
)

set(SE05X_SOURCES
    "port/i2c_espidf.c"
    "port/sm_timer_espidf.c"
    "se05x_esp.c"
    "${SE05X_NXP_DIR}/sss/src/fsl_sss_apis.c"
    "${SE05X_NXP_DIR}/sss/src/fsl_sss_util_asn1_der.c"
    "${SE05X_NXP_DIR}/sss/src/fsl_sss_util_rsa_sign_utils.c"
    "${SE05X_NXP_DIR}/sss/src/se05x/fsl_sss_se05x_apis.c"
    "${SE05X_NXP_DIR}/sss/src/se05x/fsl_sss_se05x_mw.c"
    "${SE05X_NXP_DIR}/sss/src/se05x/fsl_sss_se05x_policy.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/infra/global_platf.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/infra/sm_apdu.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/infra/sm_connect.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/infra/sm_errors.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/infra/sm_printf.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/log/nxLog.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/smCom/smCom.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/smCom/smComT1oI2C.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEsePal_i2c.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEseProto7816_3.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEse_Api.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/se05x/src/se05x_ECC_curves.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/se05x/src/se05x_mw.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/se05x/src/se05x_tlv.c"
    "${SE05X_NXP_DIR}/hostlib/hostLib/se05x_03_xx_xx/se05x_APDU.c"
)

idf_component_register(
    SRCS ${SE05X_SOURCES}
    INCLUDE_DIRS
        "include"
        "port/include"
        "${SE05X_GENERATED_INCLUDE_DIR}"
        "${SE05X_NXP_DIR}/sss/inc"
        "${SE05X_NXP_DIR}/sss/port/default"
        "${SE05X_NXP_DIR}/sss/ex/inc"
        "${SE05X_NXP_DIR}/hostlib/hostLib/inc"
        "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/infra"
        "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/log"
        "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/smCom"
        "${SE05X_NXP_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C"
        "${SE05X_NXP_DIR}/hostlib/hostLib/platform/inc"
        "${SE05X_NXP_DIR}/hostlib/hostLib/se05x_03_xx_xx"
    REQUIRES
        esp_driver_i2c
        esp_timer
        freertos
        log
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC
    SSS_USE_FTR_FILE
    USE_RTOS=1
    AX_EMBEDDED=1
)

# These select the physical transport implementation inside the NXP sources;
# consumers of se05x_esp.h do not need them in their compile environment.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    SMCOM_T1oI2C
    T1oI2C
    T1oI2C_UM11225
    T1OI2C_RETRY_ON_I2C_FAILED
)
