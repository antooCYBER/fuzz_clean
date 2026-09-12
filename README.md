# Fuzz-Clean 🎯
Modulo automatizzato in Bash per il content discovery e directory fuzzing ad alte prestazioni tramite `ffuf`.

## 📌 Features
- Pre-flight check automatico dei requisiti (`ffuf`, `curl`).
- Rilevamento e verifica automatica degli host live.
- Generazione dei report strutturati in formato JSON.
- Supporto a wordlist personalizzate e filtri di stato HTTP.

## ⚙️ Requisiti
Asciugati che `ffuf` sia installato nel sistema:
```bash
sudo apt update && sudo apt install ffuf -y
🚀 Guida all'uso
Clona la repository:

Bash
git clone [https://github.com/antooCYBER/fuzz-clean.git](https://github.com/antooCYBER/fuzz-clean.git)
cd fuzz-clean
Assegna i permessi di esecuzione:

Bash
chmod +x fuzz_clean.sh
Scarica una wordlist standard (se non presente):

Bash
mkdir -p ~/wordlists
curl -o ~/wordlists/common.txt [https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt](https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt)
Avvia lo script passando la wordlist:

Bash
./fuzz_clean.sh -w ~/wordlists/common.txt

Una volta incollato, scorri in basso e clicca su **Commit changes...** per salvare.

Fatto questo, avrai anche tutto l'ambiente di fuzzing documentato e a portata di mano p
