from pathlib import Path

alphabet = 'wesyvbniazxchjko1973652048@$+-&*<>'
comment_ciphertext = 'v7b3boika$h4h5j0jhkh161h79393i5x010j0y8n$i'
source_literal = 'flag{0af4edfd-3b6c-4f6f-853c-5b83acb20708}'
source_output = ''.join(
    alphabet[(ord(ch)//17 + i) % 34] + alphabet[-(ord(ch)%17 + i + 1) % 34]
    for i, ch in enumerate(source_literal)
)
print(f'source flag literal length: {len(source_literal)}')
print(f'comment ciphertext length: {len(comment_ciphertext)}')
print(f'ciphertext length expected from source literal: {len(source_output)}')
print(f'source literal re-encoded: {source_output}')
print(f're-encoded source literal equals comment: {source_output == comment_ciphertext}')