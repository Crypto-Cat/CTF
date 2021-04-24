from pwn import *
import re


def get_mappings(p):
    # Get a little help
    p.sendlineafter('>', '1')
    p.recvlines(2)
    # Regex to extract unicode char mappings
    char_mappings = re.findall(r'(. -> \d+)', p.recvuntil('\n').decode(), re.UNICODE)
    # Now put them into dictionary
    mapping_dictionary = {}
    for mapping in char_mappings:
        split_mapping = mapping.split(' -> ')
        mapping_dictionary[split_mapping[0]] = split_mapping[1]
    return mapping_dictionary


def take_test(p, mapping_dictionary):
    p.recvuntil(':\n\n')

    # Extract question
    question = p.recvline().decode().strip()
    info('Unmapped question: %s', question)

    # Replace mappings with correct values
    mapped_question = ''.join(mapping_dictionary.get(char, char) for char in question)
    info('Mapped question: %s', mapped_question)

    # Perform equations
    answer = eval(mapped_question.split('=')[0])
    info('Answer: %s', answer)

    p.sendlineafter(':', str(answer))
    confirmation = p.recvlinesS(3)
    info('%s, Result: %s', confirmation[1], confirmation[2])


# Connect to AlienSpeak server
p = remote('138.68.185.219', '31990')
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# Get the char mappings
mapping_dictionary = get_mappings(p)

# Take a test
p.sendlineafter('>', '2')

# Take test 500 times
for i in range(500):
    take_test(p, mapping_dictionary)

# Flag?
success('Flag: %s', re.search(r'CHTB{.*}', p.recv().decode()).group(0))
