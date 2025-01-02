#!/bin/bash

echo "
    ____     ______  ______        
   / __ \   / ____/ /_  __/   _____
  / /_/ /  / __/     / /     / ___/
 / ____/  / /___    / /     (__  ) 
/_/      /_____/   /_/     /____/  

Description: This script is a basic automation of initial map exploration with Proxmark3 - it performs tasks such as reading map information, checking keys, performing attacks (e.g. darkside, nested, hardnested) and map emulation. All logs are saved in a specified directory and archived for easy further analysis.
Author: @sigdevel
Version: 1.0
Created: 01-01-2025
Last Modified: 01-01-2025
License: MIT License
Repo: https://github.com/sigdevel/PETs
";sleep 3;

PROXMARK3_CLI="./pm3"
USER_DIR="/home/${USER}"
LOG_DIR="/home/${USER}/logdir"
TIMESTAMP=$(date +"%d%m%Y_%H%M%S")
ARCHIVE_NAME="/home/$USER/hf-mf-logs-${TIMESTAMP}.tar.gz"
LOG_FILE="${LOG_DIR}/output.log"

if [ -d "$LOG_DIR" ]; then
    echo "Директория $LOG_DIR существует. Очищаем содержимое..." | tee -a "$LOG_FILE"
    rm -rf "${LOG_DIR}"/* | tee -a "$LOG_FILE"
else
    echo "Директория $LOG_DIR не существует. Создаём..." | tee -a "$LOG_FILE"
    mkdir -p "$LOG_DIR" | tee -a "$LOG_FILE"
fi

#ф-ция выполнения команды и вывода результата
run_command() {
    echo "Выполнение команды: $1" | tee -a "$LOG_FILE"
    $PROXMARK3_CLI -c "$1" 2>&1 | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
}

#ф-ция извлечения значения из вывода команды
extract_value() {
    echo "$1" | grep -oP "$2:\s*\K[0-9A-Fa-f ]+"
}

#получение инфо по карте
echo "Получение информации о карте..." | tee -a "$LOG_FILE"
INFO=$($PROXMARK3_CLI -c "hf mf info" 2>&1 | tee -a "$LOG_FILE")

#извлечение UID+ATQA+SAK
UID=$(extract_value "$INFO" "UID")
ATQA=$(extract_value "$INFO" "ATQA")
SAK=$(extract_value "$INFO" "SAK")

#проверка извлечения данных
if [[ -z "$UID" || -z "$ATQA" || -z "$SAK" ]]; then
    echo "Ошибка: не удалось извлечь UID, ATQA или SAK - проверьте контакт с картой" | tee -a "$LOG_FILE"
    exit 1
fi

echo "UID: $UID" | tee -a "$LOG_FILE"
echo "ATQA: $ATQA" | tee -a "$LOG_FILE"
echo "SAK: $SAK" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

mf_chk() {
    echo "1. Проверка ключей доступа (chk)..." | tee -a "$LOG_FILE"
    run_command "hf mf chk"
}

mf_fchk() {
    echo "2. Проверка ключей (fchk)..." | tee -a "$LOG_FILE"
    run_command "hf mf fchk"
}

mf_info() {
    echo "3. Получение инфо по карте (info)..." | tee -a "$LOG_FILE"
    run_command "hf mf info"
}

mf_isen() {
    echo "4. Получение инфо по статически-зашифрованных нонсах (isen)..." | tee -a "$LOG_FILE"
    run_command "hf mf isen"
}

mf_darkside() {
    echo "5. Попытка выполнение атаки darkside..." | tee -a "$LOG_FILE"
    run_command "hf mf darkside"
}

mf_nested() {
    echo "6. Попытка выполнение атаки nested..." | tee -a "$LOG_FILE"
    NESTED_OUTPUT=$($PROXMARK3_CLI -c "hf mf nested 0 A FFFFFFFFFFFF 1" 2>&1 | tee -a "$LOG_FILE")

    # Извлечение данных из вывода nested
    NT=$(extract_value "$NESTED_OUTPUT" "Tag nonce \(nt\)")
    AR=$(extract_value "$NESTED_OUTPUT" "Reader response \(ar\)")
    AT=$(extract_value "$NESTED_OUTPUT" "Tag response \(at\)")
    DATA=$(extract_value "$NESTED_OUTPUT" "Encrypted data")

    # Проверка, удалось ли извлечь данные
    if [[ -z "$NT" || -z "$AR" || -z "$AT" || -z "$DATA" ]]; then
        echo "Ошибка: не удалось извлечь данные - проверьте вывод команды" | tee -a "$LOG_FILE"
    else
        echo "Извлеченные данные:" | tee -a "$LOG_FILE"
        echo "NT: $NT" | tee -a "$LOG_FILE"
        echo "AR: $AR" | tee -a "$LOG_FILE"
        echo "AT: $AT" | tee -a "$LOG_FILE"
        echo "DATA: $DATA" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
    fi
}

mf_hardnested() {
    echo "7. Попытка выполнение атаки hardnested..." | tee -a "$LOG_FILE"
    run_command "hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta"
}

mf_staticnested() {
    echo "8. Попытка выполнение атаки staticnested..." | tee -a "$LOG_FILE"
    run_command "hf mf staticnested --1k --blk 0 -a -k FFFFFFFFFFFF"
}

mf_brute() {
    echo "9. Попытка выполнение атаки brute..." | tee -a "$LOG_FILE"
    run_command "hf mf brute"
}

mf_autopwn() {
    echo "10. Попытка восстановление ключей через autopwn..." | tee -a "$LOG_FILE"
    run_command "hf mf autopwn"
}

mf_nack() {
    echo "11. Проверка уязвимости nack..." | tee -a "$LOG_FILE"
    run_command "hf mf nack"
}

mf_crypto1() {
    echo "12. Попытка восстановление данных Crypto1..." | tee -a "$LOG_FILE"
    if [[ -n "$NT" && -n "$AR" && -n "$AT" && -n "$DATA" ]]; then
        echo "Расшифровка данных Crypto1..." | tee -a "$LOG_FILE"
        run_command "hf mf decrypt --nt $NT --ar $AR --at $AT -d $DATA"
    else
        echo "Пропуск расшифровки данных Crypto1: недостаточно данных" | tee -a "$LOG_FILE"
    fi
}

mf_rdsc() {
    # Если ключ известен
    echo "13. Попытка чтения данных из сектора 0..." | tee -a "$LOG_FILE"
    run_command "hf mf rdsc 0 A FFFFFFFFFFFF"
}

mf_wrsc() {
    # Если ключ известен
    echo "14. Попытка записи данных в сектор 0..." | tee -a "$LOG_FILE"
    run_command "hf mf wrsc 0 A FFFFFFFFFFFF 000102030405060708090A0B0C0D0E0F"
}

mf_sim() {
    echo "15. Попытка эмуляции карты с UID: ${UID}..." | tee -a "$LOG_FILE"
    run_command "hf mf sim --1k --uid ${UID} --atqa ${ATQA} --sak ${SAK}"
}

mifare_ops() {
    # Добавить обработку из инфо, чтобы пропускать неконтекстные проверки
    echo "16. Проведение операций с MIFARE Classic..." | tee -a "$LOG_FILE"
    run_command "hf mf dump"  # Дамп карты в файл
    #run_command "hf mf restore"  # Восстановление карты из файла
    #run_command "hf mf wipe"  # Очистка карты
}

magic_gen1_ops() {
    echo "17. Проведение операций с Magic Gen1..." | tee -a "$LOG_FILE"
    run_command "hf mf csetuid $UID"  # Установка UID на карте
    #run_command "hf mf cwipe"  # Очистка карты до стандартных значений
}

magic_gen3_ops() {
    echo "18. Проведение операций с Magic Gen3..." | tee -a "$LOG_FILE"
    run_command "hf mf gen3uid $UID"  # Установка UID без изменения блока производителя
    #run_command "hf mf gen3freeze -y"  # Блокировка изменений UID
}

magic_gen4_ops() {
    echo "19. Проведение операций с Magic Gen4 GTU..." | tee -a "$LOG_FILE"
    run_command "hf mf ginfo"  # Инфо о конфигурации карты
    #run_command "hf mf gsetblk 0 000102030405060708090A0B0C0D0E0F"  # Запись блока на карту
}

save_result() {
    echo "Сохранение результатов..." | tee -a "$LOG_FILE"
    
    # Перемещение файлов hf-mf-* в LOG_DIR
    for fl in $(find ${USER_DIR} -type f -name "hf-mf-*" ! -name "*.tar.gz"); do
        mv ${fl} ${LOG_DIR}
    done
    
    tar -czvf ${ARCHIVE_NAME} -C $(dirname ${LOG_DIR}) $(basename ${LOG_DIR})

    #echo "Очистка временной директории..." | tee -a "$LOG_FILE"
    #rm -rf ${LOG_DIR} 2>&1 | tee -a "$LOG_FILE"
}

# Вызов функций
mf_chk
mf_fchk
mf_info
mf_isen
mf_darkside
mf_nested
mf_hardnested
mf_staticnested
mf_brute
mf_autopwn
mf_nack
mf_crypto1
mf_rdsc
mf_wrsc
mf_sim
mifare_ops
magic_gen1_ops
magic_gen3_ops
magic_gen4_ops

save_result

echo "Все проверки завершены. Логи и результаты сохранены в $ARCHIVE_NAME" | tee -a "$LOG_FILE"
