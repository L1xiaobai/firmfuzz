#!/bin/bash
USER=${USER:-root}

set -e
set -u

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

if check_number $1; then
    echo "Usage: makeImage.sh <image ID> [<architecture>]"
    exit 1
fi

if check_root; then
    echo "Error: This script requires root privileges!"
    exit 1
fi

IID=${1}
ARCH=${2}
FIRMAE_LLM=${FIRMAE_LLM:-false}
LLM_PROVIDER=${LLM_PROVIDER:-mock}
LLM_MODEL=${LLM_MODEL:-gpt-4o-mini}
LLM_BASE_URL=${LLM_BASE_URL:-https://api.openai.com/v1}
LLM_TIMEOUT=${LLM_TIMEOUT:-60}
LLM_TEMPERATURE=${LLM_TEMPERATURE:-0.1}
LLM_MAX_OUTPUT_TOKENS=${LLM_MAX_OUTPUT_TOKENS:-1600}
LLM_CONF_THRESHOLD=${LLM_CONF_THRESHOLD:-0.6}
LLM_VALIDATE_STRICT=${LLM_VALIDATE_STRICT:-false}

echo "----Running----"
WORK_DIR=`get_scratch ${IID}`
IMAGE=`get_fs ${IID}`
IMAGE_DIR=`get_fs_mount ${IID}`

echo "----Copying Filesystem Tarball----"
mkdir -p "${WORK_DIR}"
chmod a+rwx "${WORK_DIR}"
chown -R "${USER}" "${WORK_DIR}"
chgrp -R "${USER}" "${WORK_DIR}"

if [ ! -e "${WORK_DIR}/${IID}.tar.gz" ]; then
    if [ ! -e "${TARBALL_DIR}/${IID}.tar.gz" ]; then
        echo "Error: Cannot find tarball of root filesystem for ${IID}!"
        exit 1
    else
        cp "${TARBALL_DIR}/${IID}.tar.gz" "${WORK_DIR}/${IID}.tar.gz"
    fi
fi

echo "----Creating QEMU Image----"
qemu-img create -f raw "${IMAGE}" 1G
chmod a+rw "${IMAGE}"

echo "----Creating Partition Table----"
echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk "${IMAGE}"

echo "----Mounting QEMU Image----"
echo "[*] add_partition image=${IMAGE}"
DEVICE=`add_partition ${IMAGE}`
echo "[*] add_partition device=${DEVICE}"

echo "----Creating Filesystem----"
sync
mkfs.ext2 "${DEVICE}"

echo "----Making QEMU Image Mountpoint----"
if [ ! -e "${IMAGE_DIR}" ]; then
    mkdir "${IMAGE_DIR}"
    chown "${USER}" "${IMAGE_DIR}"
fi

echo "----Mounting QEMU Image Partition----"
sync
mount "${DEVICE}" "${IMAGE_DIR}"

echo "----Extracting Filesystem Tarball----"
tar -xf "${WORK_DIR}/$IID.tar.gz" -C "${IMAGE_DIR}"
rm "${WORK_DIR}/${IID}.tar.gz"

echo "----Creating FIRMADYNE Directories----"
mkdir "${IMAGE_DIR}/firmadyne/"
mkdir "${IMAGE_DIR}/firmadyne/libnvram/"
mkdir "${IMAGE_DIR}/firmadyne/libnvram.override/"

cp $(which busybox) "${IMAGE_DIR}"
cp $(which bash-static) "${IMAGE_DIR}"
echo "----Finding Init (chroot)----"
if [ -e "${WORK_DIR}/kernelInit" ]; then
  cp "${WORK_DIR}/kernelInit" "${IMAGE_DIR}"
fi
cp "${SCRIPT_DIR}/inferFile.sh" "${IMAGE_DIR}"
FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} chroot "${IMAGE_DIR}" /bash-static /inferFile.sh
rm "${IMAGE_DIR}/bash-static"
rm "${IMAGE_DIR}/inferFile.sh"
if [ -e "${IMAGE_DIR}/kernelInit" ]; then
  rm "${IMAGE_DIR}/kernelInit"
fi

# Keep original init list in both image and host workdir:
# - image copy is needed for llm_entry.sh fallback
# - workdir copy is used by makeNetwork.py
cp ${IMAGE_DIR}/firmadyne/init ${WORK_DIR}/init
if [ -e ${IMAGE_DIR}/firmadyne/service ]; then
  cp ${IMAGE_DIR}/firmadyne/service ${WORK_DIR}
fi

if (${FIRMAE_LLM}); then
  echo "----LLM Pipeline: collect -> infer -> validate -> render----"
  FACTS_JSON=${WORK_DIR}/facts.json
  LLM_INFER_JSON=${WORK_DIR}/llm_infer.json
  LLM_VALIDATE_JSON=${WORK_DIR}/llm_validate.json
  LLM_RENDER_META_JSON=${WORK_DIR}/llm_render_meta.json
  LLM_ENABLED=false

  set +e
  python3 "${SCRIPT_DIR}/collectFacts.py" \
    --iid "${IID}" \
    --rootfs "${IMAGE_DIR}" \
    --work-dir "${FIRMAE_DIR}" \
    --output "${FACTS_JSON}" --pretty
  RC_COLLECT=$?

  if [ ${RC_COLLECT} -eq 0 ]; then
    python3 "${SCRIPT_DIR}/llm_infer.py" \
      --facts "${FACTS_JSON}" \
      --output "${LLM_INFER_JSON}" \
      --provider "${LLM_PROVIDER}" \
      --model "${LLM_MODEL}" \
      --base-url "${LLM_BASE_URL}" \
      --timeout "${LLM_TIMEOUT}" \
      --temperature "${LLM_TEMPERATURE}" \
      --max-output-tokens "${LLM_MAX_OUTPUT_TOKENS}" \
      --confidence-threshold "${LLM_CONF_THRESHOLD}" \
      --pretty
    RC_INFER=$?
  else
    RC_INFER=1
  fi

  if [ ${RC_INFER} -eq 0 ]; then
    VALIDATE_ARGS="--llm-infer ${LLM_INFER_JSON} --output ${LLM_VALIDATE_JSON} --min-confidence ${LLM_CONF_THRESHOLD} --pretty"
    if (${LLM_VALIDATE_STRICT}); then
      VALIDATE_ARGS="${VALIDATE_ARGS} --strict"
    fi
    python3 "${SCRIPT_DIR}/validate_llm_plan.py" ${VALIDATE_ARGS}
    RC_VALIDATE=$?
  else
    RC_VALIDATE=1
  fi

  if [ ${RC_VALIDATE} -eq 0 ]; then
    python3 "${SCRIPT_DIR}/render_init_from_llm.py" \
      --llm-infer "${LLM_INFER_JSON}" \
      --rootfs "${IMAGE_DIR}" \
      --orig-init "/firmadyne/init" \
      --llm-init "/firmadyne/llm_init.sh" \
      --wrapper "/firmadyne/llm_entry.sh" \
      --meta-out "${LLM_RENDER_META_JSON}"
    RC_RENDER=$?
  else
    RC_RENDER=1
  fi
  set -e

  if [ ${RC_RENDER} -eq 0 ]; then
    echo "[+] LLM pipeline enabled: prepend /firmadyne/llm_entry.sh to init candidates"
    if [ -e "${WORK_DIR}/init" ]; then
      cp "${WORK_DIR}/init" "${WORK_DIR}/init.orig"
      {
        echo "/firmadyne/llm_entry.sh"
        cat "${WORK_DIR}/init.orig"
      } > "${WORK_DIR}/init"
      rm -f "${WORK_DIR}/init.orig"
    fi
    LLM_ENABLED=true
  else
    echo "[-] LLM pipeline failed or rejected, fallback to original FirmAE init flow"
    LLM_ENABLED=false
  fi
fi

echo "----Patching Filesystem (chroot)----"
cp "${SCRIPT_DIR}/fixImage.sh" "${IMAGE_DIR}"
FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} chroot "${IMAGE_DIR}" /busybox ash /fixImage.sh
rm "${IMAGE_DIR}/fixImage.sh"
rm "${IMAGE_DIR}/busybox"

echo "----Setting up FIRMADYNE----"
for BINARY_NAME in "${BINARIES[@]}"
do
    BINARY_PATH=`get_binary ${BINARY_NAME} ${ARCH}`
    cp "${BINARY_PATH}" "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
    chmod a+x "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
done
mknod -m 666 "${IMAGE_DIR}/firmadyne/ttyS1" c 4 65

cp "${SCRIPT_DIR}/preInit.sh" "${IMAGE_DIR}/firmadyne/preInit.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/preInit.sh"

cp "${SCRIPT_DIR}/network.sh" "${IMAGE_DIR}/firmadyne/network.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/network.sh"

cp "${SCRIPT_DIR}/run_service.sh" "${IMAGE_DIR}/firmadyne/run_service.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/run_service.sh"

cp "${SCRIPT_DIR}/injectionChecker.sh" "${IMAGE_DIR}/bin/a"
chmod a+x "${IMAGE_DIR}/bin/a"

touch "${IMAGE_DIR}/firmadyne/debug.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/debug.sh"

if (! ${FIRMAE_ETC}); then
  sed -i 's/sleep 60/sleep 15/g' "${IMAGE_DIR}/firmadyne/network.sh"
  sed -i 's/sleep 120/sleep 30/g' "${IMAGE_DIR}/firmadyne/run_service.sh"
  sed -i 's@/firmadyne/sh@/bin/sh@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
  sed -i 's@BUSYBOX=/firmadyne/busybox@BUSYBOX=@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
fi

echo "----Unmounting QEMU Image----"
sync
umount "${IMAGE_DIR}"

# Run fsck on the current partition device when valid.
# On some hosts, re-attaching loop partitions can return a stale/non-ext device
# (e.g. "Bad magic number in super-block"), which should not abort image build.
if [ -b "${DEVICE}" ]; then
  FS_TYPE=$(blkid -o value -s TYPE "${DEVICE}" 2>/dev/null || true)
  if [ -z "${FS_TYPE}" ]; then
    if (file -s "${DEVICE}" 2>/dev/null | grep -qi "ext[234] filesystem"); then
      FS_TYPE="ext2"
    fi
  fi
  if [ "${FS_TYPE}" = "ext2" ] || [ "${FS_TYPE}" = "ext3" ] || [ "${FS_TYPE}" = "ext4" ]; then
    e2fsck -y "${DEVICE}" || true
  else
    echo "[!] Skip e2fsck: unknown filesystem type on ${DEVICE} (${FS_TYPE})"
  fi
else
  echo "[!] Skip e2fsck: partition device not found (${DEVICE})"
fi

sync
sleep 1
LOOP_BASE=$(echo "${DEVICE}" | sed -E 's/p?[0-9]+$//')
del_partition "${LOOP_BASE}"
