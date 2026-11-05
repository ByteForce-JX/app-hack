#!/system/bin/sh
# Diagnóstico del cheat "Liberdade / FreeADOM KERNEL" en Android root
# Uso:  su -c "sh diagnostico-liberdade.sh"
# No modifica nada: solo lee y muestra información.

echo "==================== 1. KERNEL / BUILD ===================="
uname -a
cat /proc/version 2>/dev/null
getprop ro.build.version.release
getprop ro.build.version.sdk
getprop ro.build.fingerprint

echo
echo "==================== 2. ¿EXISTE /dev/ESP? ===================="
echo "-- el driver real del cheat es /dev/ESP --"
ls -l /dev/ESP 2>&1
echo "-- cualquier device suspecto en /dev --"
ls -l /dev 2>/dev/null | grep -iE "esp|free|adom|kg|game|mem"

echo
echo "==================== 3. MODULOS CARGADOS EN EL KERNEL ===================="
echo "--总线 modulos--"
wc -l < /proc/modules 2>/dev/null
grep -iE "esp|free|adom|kg|overlay" /proc/modules 2>/dev/null || echo "(ningun modulo con esos nombres)"

echo
echo "==================== 4. MODULOS INSTALADOS (KSU/Magisk) ===================="
ls -la /data/adb/modules 2>/dev/null || echo "(sin /data/adb/modules)"
ls -la /data/adb/ksu/modules 2>/dev/null || echo "(sin /data/adb/ksu/modules)"
ls -la /data/adb/ap/modules 2>/dev/null || echo "(sin /data/adb/ap/modules)"

echo
echo "==================== 5. ROOT ===================="
id
command -v su
su -v 2>&1 | head -3

echo
echo "==================== 6. SELINUX ===================="
getenforce 2>/dev/null

echo
echo "==================== 7. dmesg: CARGA DE MODULOS ===================="
dmesg 2>/dev/null | grep -iE "invalid module|version magic|unknown symbol|freeadom|tainting" | tail -20

echo
echo "==================== 8. dmesg: DENEGACIONES SELINUX ===================="
dmesg 2>/dev/null | grep -i "avc: denied" | tail -20

echo
echo "==================== 9. PROCESOS DEL CHEAT ===================="
ps -A 2>/dev/null | grep -iE "zig_liberdade|freeadom|liberdade"

echo
echo "==================== 10. LOG ACTUAL ===================="
tail -20 /data/local/tmp/overlay.log 2>/dev/null

echo
echo "==================== 11. JUEGO ===================="
echo "-- PID de Free Fire TH --"
pidof com.dts.freefireth 2>/dev/null
echo "-- libil2cpp cargada en el juego? --"
PID=$(pidof com.dts.freefireth 2>/dev/null)
if [ -n "$PID" ]; then
  grep -i il2cpp /proc/$PID/maps 2>/dev/null | head -3
else
  echo "(juego no esta corriendo: abre el juego y repite)"
fi

echo
echo "==================== FIN ===================="
