"""Consistent hot backup: python backup.py  [outputs to backups/backup_YYYYmmdd_HHMMSS.db]."""
from datetime import datetime
from pathlib import Path
from db import connect, DB_PATH


def main():
    folder=Path(__file__).resolve().parent/'backups'
    folder.mkdir(parents=True,exist_ok=True)
    target=folder/('almox_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'.db')
    with connect() as source:
        with __import__('sqlite3').connect(str(target)) as destination:
            source.backup(destination)
    print('Backup criado:',target)
    print('Guarde em local seguro. Ele contém informações da empresa e usuários.')

if __name__=='__main__':main()
