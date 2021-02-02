from pwn import *

# The hardcoded value for this challenge
hardcoded_value = 0xb0bababa
# The value we want to write
target_string = 'flag.txt'
# The mask we can control (pext)
full_mask = []

# For each letter in "flag.txt"
for c in target_string:
    # Print out the ascii/hex/bit representation of hardcoded key
    print("key: " + str(hex(hardcoded_value)) + " (" + ''.join(num for num in bits_str(hardcoded_value)) + ")")

    # Calculate the mask
    mask = ""
    hardcoded_count = 0  # Keep index of our position in the hardcoded bit_value
    char_count = 0  # And our char bit
    # Convert to little endian (easier to work in reverse in loop)
    rvs_hardcoded_bits = bits(hardcoded_value, endian='little')
    rvs_char_bits = bits(u8(c), endian='little')

    # Loop through each bit in our char (flag.txt)
    while char_count < len(rvs_char_bits) - 1:
        # If the hardcoded value bit matches our char bit, we write 1
        if rvs_hardcoded_bits[hardcoded_count] == rvs_char_bits[char_count]:
            mask += "1"
            char_count += 1  # Only increase char bit index if we match a value
        else:  # If no match, we write 0
            mask += "0"
        # Increment hardcoded_count regardless
        hardcoded_count += 1

    # Pad with zeroes
    mask += ("0" * (16 - len(mask)))
    # Reverse our mask (remember we converted little endian to make looping easy)
    mask = ''.join(reversed(mask))
    # Add it to our list
    full_mask.append(mask)

    # Print out the mask we need to get the required char
    print("mask: " + str(hex(u16(unbits((mask))))) + ((35 - len(mask)) * " ") + " (" + mask + ")")
    # Print out the current char
    print("char (" + c + ")" + ": " + str(hex(u8(c))) + (25 * " ") + " (" + ''.join(num for num in bits_str(u8(c))) + ")\n")

# Finally, give our full mask
print("full mask: ", '[%s]' % ', '.join(map(str, full_mask)))
hex_mask = [hex(u16(unbits((i)), endian='big')) for i in full_mask]
print("in hex: ", '[%s]' % ', '.join(map(str, hex_mask)))
