import os
import re

# Directory containing the markdown files
directory = '.'

# Regex pattern to find code blocks that are not wrapped with {% code overflow="wrap" %}
# It looks for unwrapped code blocks, capturing the language specifier (if present) and the content
code_block_pattern = re.compile(r'```(\w*)\n([\s\S]*?)\n```')

# Function to process a single markdown file


def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()

    # Check if the file already contains `{% code overflow="wrap" %}`
    if '{% code overflow="wrap" %}' in content:
        print(f'Skipping: Already wrapped - {filepath}')
        return

    # Find all unwrapped code blocks in the file
    matches = code_block_pattern.findall(content)
    if not matches:
        print(f'Skipping: No code blocks found - {filepath}')
        return

    # Replace unwrapped code blocks with wrapped code blocks
    new_content = re.sub(
        code_block_pattern, r'{% code overflow="wrap" %}\n```\1\n\2\n```\n{% endcode %}', content)

    # Write the new content back to the file
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(new_content)

    print(f'Processed and updated: {filepath}')


# Walk through all files and subdirectories recursively
for root, dirs, files in os.walk(directory):
    for filename in files:
        if filename.endswith('.md'):
            filepath = os.path.join(root, filename)
            process_file(filepath)
