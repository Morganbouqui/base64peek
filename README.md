# base64peek

Dependency-free Python CLI for Base64/Base64URL encoding, decoding, inspection, JWT structure viewing, nested Base64, hex/strings inspection, other Python base encodings, and XOR analysis for CTF/lab work.

## Quick start

\`\`\`bash
chmod +x base64peek
./base64peek
./base64peek --encode 'hello world'
./base64peek --decode aGVsbG8gd29ybGQ=
./base64peek --jwt 'HEADER.PAYLOAD.SIGNATURE'
./base64peek --xor-pattern 'BASE64_CIPHERTEXT' --key-pattern 'KEY?' --charset printable --top 10
\`\`\`

\`?\` is a wildcard in repeating-XOR key searches. Search space is capped by default; use \`--max-search-space\` deliberately if needed. Multiple ciphertexts can be scored under the same candidate key with repeated \`--xor-extra\` arguments.

Run \`./base64peek --help\` for all options.

Base64 is encoding, not encryption. Analysis results are candidates, not proof of a cipher or plaintext.

## Tests

\`\`\`bash
python3 -m unittest discover -s tests -v
\`\`\`
