from pathlib import Path
from zipfile import ZipFile

archive = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
with ZipFile(archive) as zf:
    candidates = [
        '412483', '412482', '411483',
        '4285F4', '4285f4', '66,133,244',
        'BlueRedYellowGreenPurpleCyanBlueRed',
        'blueredyellowgreenpurplecyanbluered',
        'BLUE-RED-YELLOW-GREEN-PURPLE-CYAN-BLUE-RED',
        'AbstractArtGallery',
    ]
    for password in candidates:
        try:
            data = zf.read('secret.txt', pwd=password.encode())
            print('PASSWORD FOUND:', password)
            print('SECRET.TXT:', data.decode(errors='replace'))
            break
        except Exception as exc:
            print('rejected:', password, type(exc).__name__)
    else:
        print('No candidate matched.')
