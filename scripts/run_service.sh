#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox
BINARY=`${BUSYBOX} cat /firmadyne/service`
BINARY_NAME=`${BUSYBOX} cat /firmadyne/service_name 2>/dev/null`
if [ -z "${BINARY_NAME}" ]; then
  BINARY_NAME=`${BUSYBOX} basename ${BINARY}`
fi

SERVICE_ARGS=""
SERVICE_ENV=""
if [ -e /firmadyne/service_args ]; then
  SERVICE_ARGS=`${BUSYBOX} cat /firmadyne/service_args`
fi
if [ -e /firmadyne/service_env ]; then
  SERVICE_ENV=`${BUSYBOX} cat /firmadyne/service_env`
fi

start_service() {
  if [ -n "${SERVICE_ENV}" ]; then
    /firmadyne/sh -c "${SERVICE_ENV} ${BINARY} ${SERVICE_ARGS}" &
  else
    /firmadyne/sh -c "${BINARY} ${SERVICE_ARGS}" &
  fi
}

if (${FIRMAE_ETC}); then
  echo "[LLM] run_service.sh start: binary=${BINARY} name=${BINARY_NAME} args='${SERVICE_ARGS}' env='${SERVICE_ENV}'"
  ${BUSYBOX} sleep 120
  start_service

  while (true); do
      ${BUSYBOX} sleep 10
      if ( ! (${BUSYBOX} ps | ${BUSYBOX} grep -v grep | ${BUSYBOX} grep -sqi ${BINARY_NAME}) ); then
          start_service
      fi
  done
fi
