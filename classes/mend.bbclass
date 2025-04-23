MEND_LOG_LEVEL ?= "debug"

HOSTTOOLS += "java"

python () {
    if not d.getVar("WS_USERKEY"):
        bb.error("WS_USERKEY must be set in local.conf or image recipe.")
        raise Exception("WS_USERKEY not set")

    if not d.getVar("WS_APIKEY"):
        bb.error("WS_APIKEY must be set in local.conf or image recipe.")
        raise Exception("WS_APIKEY not set")

    if not d.getVar("WS_PRODUCTNAME"):
        bb.error("WS_PRODUCTNAME must be set in local.conf or image recipe.")
        raise Exception("WS_PRODUCTNAME not set")

    if not d.getVar("WS_PRODUCTTOKEN"):
        bb.error("WS_PRODUCTTOKEN must be set in local.conf or image recipe.")
        raise Exception("WS_PRODUCTTOKEN not set")
}

do_mend_check() {
    unified_agent_cmd="java -jar /builder/wss-unified-agent.jar -logLevel \"${MEND_LOG_LEVEL}\" -userKey \"${WS_USERKEY}\" -apiKey \"${WS_APIKEY}\" -c /builder/amarula.wss.config -d \"${S}\" -product \"${WS_PRODUCTNAME}\" -productToken \"${WS_PRODUCTTOKEN}\" -project \"${BPN}\""

    echo "Executing Mend Unified Agent command: ${unified_agent_cmd}"

    eval "${unified_agent_cmd}"

    echo "Mend Unified Agent scan completed."
}

addtask mend_check after do_patch before do_build
do_mend_check[nostamp] = "1"
do_rootfs[recrdeptask] += "do_mend_check"
